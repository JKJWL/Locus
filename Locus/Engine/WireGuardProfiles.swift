import CoreLocation
import Foundation

enum VPNProvider: String, CaseIterable, Identifiable, Codable {
    case mullvad
    case proton
    case custom

    var id: String { rawValue }

    var title: String {
        switch self {
        case .mullvad: return "Mullvad"
        case .proton: return "Proton VPN"
        case .custom: return "WireGuard file"
        }
    }
}

/// One imported WireGuard config (Proton download or any `.conf`), with the
/// place it exits so the nearest one to the spoofed location can be picked.
struct WireGuardProfile: Codable, Identifiable, Equatable {
    var id = UUID()
    var provider: VPNProvider
    var name: String
    var locationLabel: String
    var latitude: Double?
    var longitude: Double?
    var privateKey: String
    var address: String
    var dns: String
    var peerPublicKey: String
    var presharedKey: String?
    var endpoint: String

    var coordinate: CLLocationCoordinate2D? {
        guard let latitude, let longitude else { return nil }
        return CLLocationCoordinate2D(latitude: latitude, longitude: longitude)
    }
}

enum WireGuardConfigParser {
    enum ParseError: LocalizedError {
        case missing(String)
        case invalid(String)

        var errorDescription: String? {
            switch self {
            case .missing(let field): return "This WireGuard config has no \(field)."
            case .invalid(let field): return "This WireGuard config has an invalid \(field)."
            }
        }
    }

    /// Parses a standard wg-quick `.conf`. Only the first [Peer] is used.
    static func parse(_ text: String, fallbackName: String, provider: VPNProvider) throws -> WireGuardProfile {
        var section = ""
        var interface: [String: String] = [:]
        var peer: [String: String] = [:]
        var peerComment: String?
        var peerCount = 0

        for rawLine in text.components(separatedBy: .newlines) {
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            if line.isEmpty { continue }
            if line.hasPrefix("[") {
                section = line.lowercased()
                if section == "[peer]" { peerCount += 1 }
                continue
            }
            if line.hasPrefix("#") {
                // Proton labels the server in a comment, e.g. "# US-PA#25".
                if section == "[peer]", peerCount == 1, peerComment == nil {
                    peerComment = line.dropFirst().trimmingCharacters(in: .whitespaces)
                }
                continue
            }
            guard let eq = line.firstIndex(of: "=") else { continue }
            let key = line[..<eq].trimmingCharacters(in: .whitespaces).lowercased()
            let value = line[line.index(after: eq)...].trimmingCharacters(in: .whitespaces)
            if section == "[interface]" {
                interface[key] = value
            } else if section == "[peer]", peerCount == 1 {
                peer[key] = value
            }
        }

        guard let privateKey = interface["privatekey"] else { throw ParseError.missing("PrivateKey") }
        guard isKey(privateKey) else { throw ParseError.invalid("PrivateKey") }
        guard let addressList = interface["address"],
              let address = firstIPv4(addressList) else { throw ParseError.missing("IPv4 Address") }
        guard let publicKey = peer["publickey"] else { throw ParseError.missing("peer PublicKey") }
        guard isKey(publicKey) else { throw ParseError.invalid("peer PublicKey") }
        guard let endpoint = peer["endpoint"], !endpoint.isEmpty else { throw ParseError.missing("peer Endpoint") }
        let presharedKey = peer["presharedkey"]
        if let presharedKey, !isKey(presharedKey) { throw ParseError.invalid("PresharedKey") }

        let name: String
        if let peerComment, peerComment.range(of: #"^[A-Z]{2}(-[A-Z]{2})?#\d+"#, options: .regularExpression) != nil {
            name = peerComment
        } else {
            name = fallbackName
        }

        return WireGuardProfile(
            provider: provider,
            name: name,
            locationLabel: guessLocation(serverName: name) ?? "",
            privateKey: privateKey,
            address: address,
            // Fallback resolver is still reached through the tunnel.
            dns: interface["dns"].flatMap(firstIPv4) ?? "1.1.1.1",
            peerPublicKey: publicKey,
            presharedKey: presharedKey,
            endpoint: endpoint
        )
    }

    /// Proton server names → a geocodable place: "US-PA#25" → "PA, United States",
    /// "DE#12" → "Germany", Secure Core "CH-US#1" → "United States" (exit country).
    static func guessLocation(serverName: String) -> String? {
        guard serverName.range(of: #"^[A-Z]{2}(-[A-Z]{2})?#\d+"#, options: .regularExpression) != nil else { return nil }
        let codes = serverName.split(separator: "#")[0].split(separator: "-").map(String.init)
        let english = Locale(identifier: "en_US")
        func country(_ code: String) -> String { english.localizedString(forRegionCode: code) ?? code }
        if codes.count == 2 {
            let secureCoreEntries: Set<String> = ["CH", "IS", "SE"]
            if secureCoreEntries.contains(codes[0]), codes[0] != codes[1] {
                return country(codes[1])
            }
            return "\(codes[1]), \(country(codes[0]))"
        }
        return country(codes[0])
    }

    private static func firstIPv4(_ list: String) -> String? {
        list.split(separator: ",")
            .map { String($0.trimmingCharacters(in: .whitespaces).split(separator: "/").first ?? "") }
            .first { TunnelConfig.isValidIPv4($0) }
    }

    private static func isKey(_ value: String) -> Bool {
        Data(base64Encoded: value)?.count == 32
    }
}

/// Imported profiles live in the Keychain because they contain private keys.
enum WireGuardProfileStore {
    private static let key = "wireguard.profiles"

    static func load() -> [WireGuardProfile] {
        guard let json = Keychain.string(key), let data = json.data(using: .utf8) else { return [] }
        return (try? JSONDecoder().decode([WireGuardProfile].self, from: data)) ?? []
    }

    static func save(_ profiles: [WireGuardProfile]) {
        let data = (try? JSONEncoder().encode(profiles)) ?? Data()
        Keychain.set(profiles.isEmpty ? nil : String(data: data, encoding: .utf8), for: key)
    }
}
