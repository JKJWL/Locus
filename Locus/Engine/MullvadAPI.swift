import CoreLocation
import Foundation

/// Mullvad's public relay list + the account/device endpoints the official
/// apps use to register a WireGuard key.
enum MullvadAPI {
    private static let base = URL(string: "https://api.mullvad.net")!

    /// Bypasses the system (Wi-Fi) proxy: if that proxy is Locus itself and the
    /// tunnel is down, API calls must still reach Mullvad to bring it up.
    private static let session: URLSession = {
        let config = URLSessionConfiguration.ephemeral
        config.connectionProxyDictionary = [:]
        return URLSession(configuration: config)
    }()

    struct Location: Decodable {
        let country: String
        let city: String
        let latitude: Double
        let longitude: Double
    }

    struct Relay: Decodable {
        let hostname: String
        let location: String
        let active: Bool
        let ipv4_addr_in: String
        let public_key: String
        let weight: Int?
    }

    struct RelayList: Decodable {
        struct WireGuard: Decodable {
            let relays: [Relay]
            let ipv4_gateway: String
        }

        let locations: [String: Location]
        let wireguard: WireGuard
    }

    struct Device: Decodable {
        let id: String
        let name: String
        let ipv4_address: String
    }

    enum APIError: LocalizedError {
        case server(String)

        var errorDescription: String? {
            switch self {
            case .server(let message): return message
            }
        }
    }

    /// A chosen server and where it is.
    struct Choice: Equatable {
        let hostname: String
        let city: String
        let country: String
        let endpoint: String
        let publicKey: String
        let distanceKm: Double
    }

    // MARK: Relay list

    static func fetchRelays() async throws -> Data {
        let (data, response) = try await session.data(from: base.appendingPathComponent("app/v1/relays"))
        try check(response, data)
        return data
    }

    static func decodeRelays(_ data: Data) throws -> RelayList {
        try JSONDecoder().decode(RelayList.self, from: data)
    }

    /// Nearest city with an active WireGuard relay; a relay in that city is
    /// picked at random (weighted) so reconnects spread across servers.
    static func nearest(to coordinate: CLLocationCoordinate2D, in list: RelayList) -> Choice? {
        let target = CLLocation(latitude: coordinate.latitude, longitude: coordinate.longitude)
        let active = list.wireguard.relays.filter(\.active)
        let byCity = Dictionary(grouping: active, by: \.location)

        var best: (key: String, location: Location, meters: Double)?
        for key in byCity.keys {
            guard let location = list.locations[key] else { continue }
            let meters = target.distance(from: CLLocation(latitude: location.latitude, longitude: location.longitude))
            if best == nil || meters < best!.meters {
                best = (key, location, meters)
            }
        }
        guard let best, let relays = byCity[best.key], let relay = weightedPick(relays) else { return nil }
        return Choice(
            hostname: relay.hostname,
            city: best.location.city,
            country: best.location.country,
            endpoint: "\(relay.ipv4_addr_in):51820",
            publicKey: relay.public_key,
            distanceKm: best.meters / 1000
        )
    }

    private static func weightedPick(_ relays: [Relay]) -> Relay? {
        let total = relays.reduce(0) { $0 + max(1, $1.weight ?? 1) }
        guard total > 0 else { return relays.first }
        var roll = Int.random(in: 0..<total)
        for relay in relays {
            roll -= max(1, relay.weight ?? 1)
            if roll < 0 { return relay }
        }
        return relays.last
    }

    // MARK: Account / device

    static func accessToken(accountNumber: String) async throws -> String {
        struct Response: Decodable { let access_token: String }
        let data = try await post("auth/v1/token", body: ["account_number": accountNumber], token: nil)
        return try JSONDecoder().decode(Response.self, from: data).access_token
    }

    /// Registers a WireGuard public key as a new device on the account
    /// (Mullvad allows 5 devices per account).
    static func registerDevice(publicKey: String, token: String) async throws -> Device {
        let body: [String: Any] = ["pubkey": publicKey, "hijack_dns": false]
        let data = try await post("accounts/v1/devices", body: body, token: token)
        return try JSONDecoder().decode(Device.self, from: data)
    }

    static func removeDevice(id: String, token: String) async throws {
        var request = URLRequest(url: base.appendingPathComponent("accounts/v1/devices/\(id)"))
        request.httpMethod = "DELETE"
        request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        let (data, response) = try await session.data(for: request)
        try check(response, data)
    }

    private static func post(_ path: String, body: [String: Any], token: String?) async throws -> Data {
        var request = URLRequest(url: base.appendingPathComponent(path))
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        if let token {
            request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        }
        request.httpBody = try JSONSerialization.data(withJSONObject: body)
        let (data, response) = try await session.data(for: request)
        try check(response, data)
        return data
    }

    private static func check(_ response: URLResponse, _ data: Data) throws {
        guard let http = response as? HTTPURLResponse, !(200..<300).contains(http.statusCode) else { return }
        struct ErrorBody: Decodable { let code: String?; let error: String? }
        let body = try? JSONDecoder().decode(ErrorBody.self, from: data)
        switch body?.code {
        case "INVALID_ACCOUNT":
            throw APIError.server("That Mullvad account number wasn't accepted.")
        case "MAX_DEVICES_REACHED":
            throw APIError.server("This Mullvad account already has 5 devices. Remove one in the Mullvad app or website, then log in again.")
        default:
            throw APIError.server(body?.error ?? "Mullvad API error (HTTP \(http.statusCode)).")
        }
    }
}
