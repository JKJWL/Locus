import CoreLocation
import CryptoKit
import Foundation
import wgproxy

/// Keeps the public IP near the spoofed location: runs a userspace WireGuard
/// tunnel to the server closest to the current (spoofed) coordinate and
/// exposes it as an HTTP proxy on 127.0.0.1:`proxyPort`. Point Settings ›
/// Wi‑Fi › Configure Proxy at it.
///
/// Providers:
/// - Mullvad: account login; nearest city from Mullvad's public relay list.
/// - Proton VPN / WireGuard file: imported `.conf` files; nearest import wins.
@MainActor
final class IPMask: ObservableObject {
    static let shared = IPMask()
    static let proxyPort = 9080

    enum State: Equatable {
        case off
        case connecting
        case connected
        case failed(String)
    }

    /// A concrete server to connect to, whichever provider it came from.
    struct Target: Equatable {
        /// Same key = no reconnect needed (Mullvad: city; imports: profile id).
        let groupKey: String
        let serverName: String
        let place: String
        let distanceKm: Double?
        let privateKey: String
        let address: String
        let dns: String
        let publicKey: String
        let presharedKey: String?
        let endpoint: String
    }

    @Published private(set) var state: State = .off
    @Published private(set) var enabled: Bool
    @Published private(set) var provider: VPNProvider
    @Published private(set) var target: Target?
    @Published private(set) var profiles: [WireGuardProfile]
    @Published private(set) var deviceName: String?
    @Published private(set) var isBusy = false
    @Published private(set) var lastCheck: String?

    private enum Keys {
        static let account = "mullvad.account"
        static let privateKey = "mullvad.privateKey"
        static let deviceID = "mullvad.deviceID"
        static let deviceName = "mullvad.deviceName"
        static let address = "mullvad.address"
        static let enabled = "ipmask.enabled"
        static let provider = "ipmask.provider"
        static let lastLatitude = "ipmask.lastLatitude"
        static let lastLongitude = "ipmask.lastLongitude"
    }

    private let defaults = UserDefaults.standard
    private var relays: MullvadAPI.RelayList?
    private var relaysFetchedAt: Date?
    private var followTask: Task<Void, Never>?
    private var tunnelRunning = false

    private init() {
        enabled = defaults.bool(forKey: Keys.enabled)
        provider = defaults.string(forKey: Keys.provider).flatMap(VPNProvider.init(rawValue:)) ?? .mullvad
        deviceName = defaults.string(forKey: Keys.deviceName)
        profiles = WireGuardProfileStore.load()
    }

    var isLoggedIn: Bool {
        Keychain.string(Keys.account) != nil
            && Keychain.string(Keys.privateKey) != nil
            && defaults.string(forKey: Keys.address) != nil
    }

    /// Whether the selected provider has what it needs to connect.
    var isReady: Bool {
        provider == .mullvad ? isLoggedIn : !profiles(for: provider).isEmpty
    }

    /// Last four digits, for display.
    var maskedAccount: String? {
        Keychain.string(Keys.account).map { "•••• " + String($0.suffix(4)) }
    }

    func profiles(for provider: VPNProvider) -> [WireGuardProfile] {
        profiles.filter { $0.provider == provider }
    }

    private var lastCoordinate: CLLocationCoordinate2D? {
        guard defaults.object(forKey: Keys.lastLatitude) != nil else { return nil }
        return CLLocationCoordinate2D(
            latitude: defaults.double(forKey: Keys.lastLatitude),
            longitude: defaults.double(forKey: Keys.lastLongitude)
        )
    }

    // MARK: Provider

    func setProvider(_ newValue: VPNProvider) {
        guard newValue != provider else { return }
        provider = newValue
        defaults.set(newValue.rawValue, forKey: Keys.provider)
        lastCheck = nil
        guard enabled else { return }
        if isReady, let coordinate = lastCoordinate {
            connectNearest(to: coordinate, force: true)
        } else {
            stopTunnel()
            state = .failed(provider == .mullvad ? "Log in to Mullvad first." : "Import a \(provider.title) config first.")
        }
    }

    // MARK: Mullvad account

    func logIn(accountNumber: String) async throws {
        let digits = accountNumber.filter(\.isNumber)
        guard digits.count >= 16 else {
            throw MullvadAPI.APIError.server("Mullvad account numbers are 16 digits.")
        }
        isBusy = true
        defer { isBusy = false }

        let key = Curve25519.KeyAgreement.PrivateKey()
        let publicKey = key.publicKey.rawRepresentation.base64EncodedString()
        let token = try await MullvadAPI.accessToken(accountNumber: digits)
        let device = try await MullvadAPI.registerDevice(publicKey: publicKey, token: token)

        Keychain.set(digits, for: Keys.account)
        Keychain.set(key.rawRepresentation.base64EncodedString(), for: Keys.privateKey)
        defaults.set(device.id, forKey: Keys.deviceID)
        defaults.set(device.name, forKey: Keys.deviceName)
        defaults.set(device.ipv4_address, forKey: Keys.address)
        deviceName = device.name
        objectWillChange.send()
    }

    /// Removes this device from the Mullvad account (frees one of the 5 slots).
    func logOut() async {
        if provider == .mullvad {
            setEnabled(false, near: nil)
        }
        isBusy = true
        defer { isBusy = false }
        if let account = Keychain.string(Keys.account), let id = defaults.string(forKey: Keys.deviceID),
           let token = try? await MullvadAPI.accessToken(accountNumber: account) {
            try? await MullvadAPI.removeDevice(id: id, token: token)
        }
        Keychain.set(nil, for: Keys.account)
        Keychain.set(nil, for: Keys.privateKey)
        for key in [Keys.deviceID, Keys.deviceName, Keys.address] {
            defaults.removeObject(forKey: key)
        }
        deviceName = nil
        lastCheck = nil
        objectWillChange.send()
    }

    // MARK: Imported configs (Proton / WireGuard file)

    /// Parses a `.conf`, guesses + geocodes its location, and stores it.
    @discardableResult
    func importConfig(_ text: String, fileName: String, provider: VPNProvider) async throws -> WireGuardProfile {
        let stem = (fileName as NSString).deletingPathExtension
        var profile = try WireGuardConfigParser.parse(text, fallbackName: stem.isEmpty ? "WireGuard" : stem, provider: provider)
        if !profile.locationLabel.isEmpty, let coordinate = await Self.geocode(profile.locationLabel) {
            profile.latitude = coordinate.latitude
            profile.longitude = coordinate.longitude
        }
        profiles.append(profile)
        WireGuardProfileStore.save(profiles)
        return profile
    }

    /// Sets where a config exits (e.g. "Pittsburgh, PA"). Returns false if it
    /// couldn't be found on the map.
    func setLocation(_ label: String, for id: WireGuardProfile.ID) async -> Bool {
        let trimmed = label.trimmingCharacters(in: .whitespacesAndNewlines)
        let coordinate = trimmed.isEmpty ? nil : await Self.geocode(trimmed)
        // Re-find after the await: the list may have changed meanwhile.
        guard let index = profiles.firstIndex(where: { $0.id == id }) else { return false }
        profiles[index].locationLabel = trimmed
        profiles[index].latitude = coordinate?.latitude
        profiles[index].longitude = coordinate?.longitude
        WireGuardProfileStore.save(profiles)
        return coordinate != nil
    }

    func deleteProfile(_ id: WireGuardProfile.ID) {
        profiles.removeAll { $0.id == id }
        WireGuardProfileStore.save(profiles)
        if target?.groupKey == "profile:\(id)", enabled {
            if isReady, let coordinate = lastCoordinate {
                connectNearest(to: coordinate, force: true)
            } else {
                stopTunnel()
                state = .failed("Import a \(provider.title) config first.")
            }
        }
    }

    private static func geocode(_ place: String) async -> CLLocationCoordinate2D? {
        let placemarks = try? await CLGeocoder().geocodeAddressString(place)
        return placemarks?.first?.location?.coordinate
    }

    // MARK: Tunnel

    func setEnabled(_ on: Bool, near coordinate: CLLocationCoordinate2D?) {
        enabled = on
        defaults.set(on, forKey: Keys.enabled)
        if on {
            if let coordinate { remember(coordinate) }
            guard let target = coordinate ?? lastCoordinate else {
                state = .failed("Teleport somewhere (or allow Location) so Locus can pick the nearest server.")
                return
            }
            connectNearest(to: target, force: true)
        } else {
            followTask?.cancel()
            followTask = nil
            stopTunnel()
            state = .off
        }
    }

    /// Reconnect at launch so the Wi‑Fi proxy isn't left pointing at nothing.
    func resumeAtLaunch() {
        guard enabled, isReady, let target = lastCoordinate else { return }
        connectNearest(to: target, force: true)
    }

    /// Called on every successful spoof update. Cheap when the nearest server is unchanged.
    func follow(_ coordinate: CLLocationCoordinate2D) {
        remember(coordinate)
        guard enabled, isReady else { return }
        connectNearest(to: coordinate, force: false)
    }

    private func remember(_ coordinate: CLLocationCoordinate2D) {
        defaults.set(coordinate.latitude, forKey: Keys.lastLatitude)
        defaults.set(coordinate.longitude, forKey: Keys.lastLongitude)
    }

    private func stopTunnel() {
        Self.stopTunnelFFI()
        tunnelRunning = false
        target = nil
    }

    private func connectNearest(to coordinate: CLLocationCoordinate2D, force: Bool) {
        // Joystick/route updates arrive several times a second; one lookup at a
        // time. A forced connect (toggle, provider change) replaces a running one.
        if force {
            followTask?.cancel()
        } else if followTask != nil {
            return
        }
        followTask = Task { [weak self] in
            await self?.runConnect(to: coordinate, force: force)
            if !Task.isCancelled { self?.followTask = nil }
        }
    }

    private func runConnect(to coordinate: CLLocationCoordinate2D, force: Bool) async {
        let next: Target
        do {
            next = try await nearestTarget(to: coordinate)
        } catch {
            state = .failed(error.localizedDescription)
            return
        }
        if Task.isCancelled { return }
        if !force, tunnelRunning, next.groupKey == target?.groupKey {
            return
        }

        let endpoint: String
        if let resolved = await Task.detached(operation: { Self.resolveEndpoint(next.endpoint) }).value {
            endpoint = resolved
        } else {
            state = .failed("Couldn't resolve server address \(next.endpoint).")
            return
        }

        state = .connecting
        let previous = target
        target = next
        var peer: [String: Any] = ["public_key": next.publicKey, "endpoint": endpoint]
        if let psk = next.presharedKey { peer["preshared_key"] = psk }
        let config: [String: Any] = [
            "private_key": next.privateKey,
            "address": next.address,
            "dns": next.dns,
            "mtu": 1280,
            "listen": "127.0.0.1:\(Self.proxyPort)",
            "peer": peer,
        ]
        // Same identity (e.g. Mullvad city change) → just swap the peer.
        let swapPeer = tunnelRunning && previous.map {
            $0.privateKey == next.privateKey && $0.address == next.address && $0.dns == next.dns
        } == true
        let error = await Task.detached {
            swapPeer ? Self.setPeerFFI(peer) : Self.startTunnelFFI(config)
        }.value
        if let error {
            tunnelRunning = false
            state = .failed(error)
            return
        }
        tunnelRunning = true
        NSLog("[Locus] IP mask (%@) → %@ (%@)", provider.title, next.serverName, next.place)

        // A fresh handshake proves the server accepted our key.
        let startedAt = Int(Date().timeIntervalSince1970) - 1
        for _ in 0..<20 {
            try? await Task.sleep(nanoseconds: 500_000_000)
            if Task.isCancelled { return }
            if Self.lastHandshake() >= startedAt {
                state = .connected
                return
            }
        }
        state = .failed("No reply from \(next.serverName). Check the account is active and the config is current.")
    }

    private func nearestTarget(to coordinate: CLLocationCoordinate2D) async throws -> Target {
        switch provider {
        case .mullvad:
            guard let privateKey = Keychain.string(Keys.privateKey),
                  let address = defaults.string(forKey: Keys.address) else {
                throw MullvadAPI.APIError.server("Log in to Mullvad first.")
            }
            let list: MullvadAPI.RelayList
            do {
                list = try await relayList()
            } catch {
                throw MullvadAPI.APIError.server("Couldn't load Mullvad servers: \(error.localizedDescription)")
            }
            guard let pick = MullvadAPI.nearest(to: coordinate, in: list) else {
                throw MullvadAPI.APIError.server("No active Mullvad WireGuard servers found.")
            }
            return Target(
                groupKey: "mullvad:\(pick.country)/\(pick.city)",
                serverName: pick.hostname,
                place: pick.city,
                distanceKm: pick.distanceKm,
                privateKey: privateKey,
                address: address,
                dns: list.wireguard.ipv4_gateway,
                publicKey: pick.publicKey,
                presharedKey: nil,
                endpoint: pick.endpoint
            )

        case .proton, .custom:
            let candidates = profiles(for: provider)
            guard !candidates.isEmpty else {
                throw MullvadAPI.APIError.server("Import a \(provider.title) config first.")
            }
            let here = CLLocation(latitude: coordinate.latitude, longitude: coordinate.longitude)
            let located = candidates.compactMap { profile -> (WireGuardProfile, Double)? in
                guard let c = profile.coordinate else { return nil }
                return (profile, here.distance(from: CLLocation(latitude: c.latitude, longitude: c.longitude)))
            }
            // Configs without a known location are only used if none have one.
            let (profile, meters) = located.min { $0.1 < $1.1 } ?? (candidates[0], -1)
            return Target(
                groupKey: "profile:\(profile.id)",
                serverName: profile.name,
                place: profile.locationLabel.isEmpty ? "Unknown location" : profile.locationLabel,
                distanceKm: meters >= 0 ? meters / 1000 : nil,
                privateKey: profile.privateKey,
                address: profile.address,
                dns: profile.dns,
                publicKey: profile.peerPublicKey,
                presharedKey: profile.presharedKey,
                endpoint: profile.endpoint
            )
        }
    }

    private func relayList() async throws -> MullvadAPI.RelayList {
        if let relays, let fetched = relaysFetchedAt, Date().timeIntervalSince(fetched) < 6 * 3600 {
            return relays
        }
        let cacheURL = FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("mullvad-relays.json")
        do {
            let data = try await MullvadAPI.fetchRelays()
            let list = try MullvadAPI.decodeRelays(data)
            try? data.write(to: cacheURL)
            relays = list
            relaysFetchedAt = Date()
            return list
        } catch {
            // Offline / API blocked: fall back to the last list we saw.
            if let data = try? Data(contentsOf: cacheURL), let list = try? MullvadAPI.decodeRelays(data) {
                relays = list
                return list
            }
            throw error
        }
    }

    // MARK: Leak check

    /// Asks am.i.mullvad.net (works for any exit IP), through our own proxy,
    /// which IP and place the world sees.
    func checkIP() async {
        let config = URLSessionConfiguration.ephemeral
        config.connectionProxyDictionary = [
            "HTTPEnable": true, "HTTPProxy": "127.0.0.1", "HTTPPort": Self.proxyPort,
            "HTTPSEnable": true, "HTTPSProxy": "127.0.0.1", "HTTPSPort": Self.proxyPort,
        ]
        config.timeoutIntervalForRequest = 15
        struct Answer: Decodable {
            let ip: String
            let city: String?
            let country: String?
            let mullvad_exit_ip: Bool
        }
        do {
            let (data, _) = try await URLSession(configuration: config)
                .data(from: URL(string: "https://am.i.mullvad.net/json")!)
            let answer = try JSONDecoder().decode(Answer.self, from: data)
            let place = [answer.city, answer.country].compactMap { $0 }.joined(separator: ", ")
            if provider == .mullvad {
                lastCheck = answer.mullvad_exit_ip
                    ? "Mullvad exit \(answer.ip) · \(place)"
                    : "Not through Mullvad: \(answer.ip) · \(place)"
            } else {
                lastCheck = "Exit IP \(answer.ip) · \(place)"
            }
        } catch {
            lastCheck = "Proxy check failed: \(error.localizedDescription)"
        }
    }

    // MARK: wgproxy FFI

    /// wireguard-go needs an IP endpoint; resolve hostnames from custom configs.
    nonisolated private static func resolveEndpoint(_ endpoint: String) -> String? {
        let host: String
        let port: String
        if endpoint.hasPrefix("["), let close = endpoint.firstIndex(of: "]") {
            host = String(endpoint[endpoint.index(after: endpoint.startIndex)..<close])
            port = String(endpoint[endpoint.index(after: close)...].dropFirst())
        } else if let colon = endpoint.lastIndex(of: ":") {
            host = String(endpoint[..<colon])
            port = String(endpoint[endpoint.index(after: colon)...])
        } else {
            return nil
        }
        guard !host.isEmpty, UInt16(port) != nil else { return nil }
        if TunnelConfig.isValidIPv4(host) { return "\(host):\(port)" }
        if host.contains(":") { return "[\(host)]:\(port)" }

        var hints = addrinfo()
        hints.ai_family = AF_INET
        hints.ai_socktype = SOCK_DGRAM
        var result: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(host, nil, &hints, &result) == 0, let first = result else { return nil }
        defer { freeaddrinfo(result) }
        var buffer = [CChar](repeating: 0, count: Int(NI_MAXHOST))
        guard getnameinfo(first.pointee.ai_addr, first.pointee.ai_addrlen, &buffer, socklen_t(buffer.count), nil, 0, NI_NUMERICHOST) == 0 else {
            return nil
        }
        return "\(String(cString: buffer)):\(port)"
    }

    nonisolated private static func json(_ object: [String: Any]) -> String {
        let data = (try? JSONSerialization.data(withJSONObject: object)) ?? Data()
        return String(data: data, encoding: .utf8) ?? "{}"
    }

    nonisolated private static func consume(_ result: UnsafeMutablePointer<CChar>?) -> String? {
        guard let result else { return nil }
        defer { LocusWGFree(result) }
        return String(cString: result)
    }

    nonisolated private static func startTunnelFFI(_ config: [String: Any]) -> String? {
        consume(LocusWGStart(json(config)))
    }

    nonisolated private static func setPeerFFI(_ peer: [String: Any]) -> String? {
        consume(LocusWGSetPeer(json(peer)))
    }

    nonisolated private static func stopTunnelFFI() {
        LocusWGStop()
    }

    nonisolated private static func lastHandshake() -> Int {
        guard let text = consume(LocusWGStatus()),
              let object = try? JSONSerialization.jsonObject(with: Data(text.utf8)) as? [String: Any] else { return 0 }
        return (object["last_handshake"] as? Int) ?? 0
    }
}
