import CoreLocation
import CryptoKit
import Foundation
import wgproxy

/// Keeps the public IP near the spoofed location: runs a userspace WireGuard
/// tunnel to the Mullvad relay closest to the current (spoofed) coordinate and
/// exposes it as an HTTP proxy on 127.0.0.1:`proxyPort`. Point Settings ›
/// Wi‑Fi › Configure Proxy at it. Teleports that land nearer a different
/// Mullvad city switch the server automatically.
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

    @Published private(set) var state: State = .off
    @Published private(set) var enabled: Bool
    @Published private(set) var choice: MullvadAPI.Choice?
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
        deviceName = defaults.string(forKey: Keys.deviceName)
    }

    var isLoggedIn: Bool {
        Keychain.string(Keys.account) != nil
            && Keychain.string(Keys.privateKey) != nil
            && defaults.string(forKey: Keys.address) != nil
    }

    /// Last four digits, for display.
    var maskedAccount: String? {
        Keychain.string(Keys.account).map { "•••• " + String($0.suffix(4)) }
    }

    private var lastCoordinate: CLLocationCoordinate2D? {
        guard defaults.object(forKey: Keys.lastLatitude) != nil else { return nil }
        return CLLocationCoordinate2D(
            latitude: defaults.double(forKey: Keys.lastLatitude),
            longitude: defaults.double(forKey: Keys.lastLongitude)
        )
    }

    // MARK: Account

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
        setEnabled(false, near: nil)
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
            Self.stopTunnel()
            tunnelRunning = false
            choice = nil
            state = .off
        }
    }

    /// Reconnect at launch so the Wi‑Fi proxy isn't left pointing at nothing.
    func resumeAtLaunch() {
        guard enabled, isLoggedIn, let target = lastCoordinate else { return }
        connectNearest(to: target, force: true)
    }

    /// Called on every successful spoof update. Cheap when the nearest city is unchanged.
    func follow(_ coordinate: CLLocationCoordinate2D) {
        remember(coordinate)
        guard enabled, isLoggedIn else { return }
        connectNearest(to: coordinate, force: false)
    }

    private func remember(_ coordinate: CLLocationCoordinate2D) {
        defaults.set(coordinate.latitude, forKey: Keys.lastLatitude)
        defaults.set(coordinate.longitude, forKey: Keys.lastLongitude)
    }

    private func connectNearest(to coordinate: CLLocationCoordinate2D, force: Bool) {
        // Joystick/route updates arrive several times a second; one lookup at a time.
        guard followTask == nil else { return }
        followTask = Task { [weak self] in
            await self?.runConnect(to: coordinate, force: force)
            self?.followTask = nil
        }
    }

    private func runConnect(to coordinate: CLLocationCoordinate2D, force: Bool) async {
        guard let privateKey = Keychain.string(Keys.privateKey),
              let address = defaults.string(forKey: Keys.address) else {
            state = .failed("Log in to Mullvad first.")
            return
        }
        let list: MullvadAPI.RelayList
        do {
            list = try await relayList()
        } catch {
            state = .failed("Couldn't load Mullvad servers: \(error.localizedDescription)")
            return
        }
        guard let pick = MullvadAPI.nearest(to: coordinate, in: list) else {
            state = .failed("No active Mullvad WireGuard servers found.")
            return
        }
        if !force, tunnelRunning, pick.city == choice?.city, pick.country == choice?.country {
            return
        }

        state = .connecting
        choice = pick
        let peer: [String: Any] = ["public_key": pick.publicKey, "endpoint": pick.endpoint]
        let config: [String: Any] = [
            "private_key": privateKey,
            "address": address,
            "dns": list.wireguard.ipv4_gateway,
            "mtu": 1280,
            "listen": "127.0.0.1:\(Self.proxyPort)",
            "peer": peer,
        ]
        let reuse = tunnelRunning
        let error = await Task.detached {
            reuse ? Self.setPeer(peer) : Self.startTunnel(config)
        }.value
        if let error {
            tunnelRunning = false
            state = .failed(error)
            return
        }
        tunnelRunning = true
        NSLog("[Locus] IP mask → %@ (%@, %.0f km)", pick.hostname, pick.city, pick.distanceKm)

        // A fresh handshake proves the server accepted our key.
        for _ in 0..<20 {
            try? await Task.sleep(nanoseconds: 500_000_000)
            if Task.isCancelled { return }
            if Self.lastHandshake() > 0 {
                state = .connected
                return
            }
        }
        state = .failed("No reply from \(pick.hostname). Check the Mullvad account has time left.")
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

    /// Asks Mullvad's checker, through our own proxy, which IP the world sees.
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
            lastCheck = answer.mullvad_exit_ip
                ? "Mullvad exit \(answer.ip) · \(place)"
                : "Not through Mullvad: \(answer.ip) · \(place)"
        } catch {
            lastCheck = "Proxy check failed: \(error.localizedDescription)"
        }
    }

    // MARK: wgproxy FFI

    nonisolated private static func json(_ object: [String: Any]) -> String {
        let data = (try? JSONSerialization.data(withJSONObject: object)) ?? Data()
        return String(data: data, encoding: .utf8) ?? "{}"
    }

    nonisolated private static func consume(_ result: UnsafeMutablePointer<CChar>?) -> String? {
        guard let result else { return nil }
        defer { LocusWGFree(result) }
        return String(cString: result)
    }

    nonisolated private static func startTunnel(_ config: [String: Any]) -> String? {
        consume(LocusWGStart(json(config)))
    }

    nonisolated private static func setPeer(_ peer: [String: Any]) -> String? {
        consume(LocusWGSetPeer(json(peer)))
    }

    nonisolated private static func stopTunnel() {
        LocusWGStop()
    }

    nonisolated private static func lastHandshake() -> Int {
        guard let text = consume(LocusWGStatus()),
              let object = try? JSONSerialization.jsonObject(with: Data(text.utf8)) as? [String: Any] else { return 0 }
        return (object["last_handshake"] as? Int) ?? 0
    }
}
