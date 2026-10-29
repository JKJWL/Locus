import Foundation

/// Addresses of the user's LocalDevVPN instance (Settings → LocalDevVPN).
///
/// - Device IP: where Locus connects to reach remoted (LocalDevVPN reflects it
///   back into the phone). Default 10.7.0.1.
/// - Tunnel IP: the phone's own utun address. Only used to detect that
///   LocalDevVPN is up; connecting *to* it gets a TCP reset.
///
/// The RPPairing file holds no addresses, so changing these never needs a re-pair.
enum TunnelConfig {
    static let defaultIP = "10.7.0.1"
    static let defaultsKey = "locus.targetDeviceIP"
    static let tunnelDefaultsKey = "locus.localTunnelIP"

    /// Device IP (connection target).
    static var targetIP: String {
        stored(defaultsKey) ?? defaultIP
    }

    static func setTargetIP(_ value: String) {
        UserDefaults.standard.set(value.trimmingCharacters(in: .whitespacesAndNewlines), forKey: defaultsKey)
    }

    /// Tunnel IP (phone's utun address). Empty = auto-detect.
    static var tunnelIP: String? {
        stored(tunnelDefaultsKey)
    }

    static func setTunnelIP(_ value: String) {
        UserDefaults.standard.set(value.trimmingCharacters(in: .whitespacesAndNewlines), forKey: tunnelDefaultsKey)
    }

    /// Accepts "10.7.1.1" or "10.7.1.1/32" as LocalDevVPN displays them.
    static func normalized(_ value: String) -> String {
        String(value.trimmingCharacters(in: .whitespacesAndNewlines).split(separator: "/").first ?? "")
    }

    static func isValidIPv4(_ value: String) -> Bool {
        var addr = in_addr()
        return normalized(value).withCString { inet_pton(AF_INET, $0, &addr) } == 1
    }

    private static func stored(_ key: String) -> String? {
        guard let value = UserDefaults.standard.string(forKey: key) else { return nil }
        let trimmed = normalized(value)
        return trimmed.isEmpty ? nil : trimmed
    }
}
