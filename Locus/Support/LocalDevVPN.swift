import Darwin
import Foundation
import UIKit

enum LocalDevVPN {
    static let appStoreURL = URL(string: "https://apps.apple.com/us/app/localdevvpn/id6755608044")!
    static let detectURL = URL(string: "localdevvpn://")!

    /// Starts the tunnel, then returns to Locus via `locus://`.
    static let enableURL = URL(string: "localdevvpn://enable?scheme=locus")!

    static var isInstalled: Bool {
        UIApplication.shared.canOpenURL(detectURL)
    }

    /// LocalDevVPN gives a utun interface the *tunnel* IP (e.g. 10.7.1.1) while
    /// Locus targets the *device* IP (e.g. 10.7.0.1), which is never a local address.
    /// With a Tunnel IP set, require that exact utun address; otherwise accept any
    /// utun address sharing the device IP's /16.
    static var isConnected: Bool {
        let utun = ipv4InterfaceAddresses().filter { $0.name.hasPrefix("utun") }
        if let tunnelIP = TunnelConfig.tunnelIP {
            return utun.contains { $0.address == tunnelIP }
        }
        let parts = TunnelConfig.targetIP.split(separator: ".")
        guard parts.count == 4 else { return false }
        let prefix = parts.prefix(2).joined(separator: ".") + "."
        return utun.contains { $0.address.hasPrefix(prefix) }
    }

    /// Problem with the configured addresses, or nil when they look right.
    static var configurationIssue: String? {
        let device = TunnelConfig.targetIP
        guard TunnelConfig.isValidIPv4(device) else {
            return "Device IP \(device) is not a valid IPv4 address."
        }
        if let tunnel = TunnelConfig.tunnelIP {
            guard TunnelConfig.isValidIPv4(tunnel) else {
                return "Tunnel IP \(tunnel) is not a valid IPv4 address."
            }
            if tunnel == device {
                return "Device IP and Tunnel IP are the same. Use LocalDevVPN's Device IP for Device IP."
            }
        }
        if ipv4InterfaceAddresses().contains(where: { $0.address == device }) {
            return "\(device) is this iPhone's own tunnel address. Enter LocalDevVPN's Device IP instead (e.g. 10.7.0.1)."
        }
        return nil
    }

    static func openInstalled() {
        UIApplication.shared.open(enableURL)
    }

    static func openAppStore() {
        UIApplication.shared.open(appStoreURL)
    }

    /// Open LocalDevVPN to connect if installed; otherwise App Store.
    static func openOrInstall() {
        if isInstalled {
            openInstalled()
        } else {
            openAppStore()
        }
    }

    private static func ipv4InterfaceAddresses() -> [(name: String, address: String)] {
        var ifaddr: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&ifaddr) == 0, let first = ifaddr else { return [] }
        defer { freeifaddrs(ifaddr) }

        var results: [(name: String, address: String)] = []
        var ptr: UnsafeMutablePointer<ifaddrs>? = first
        while let current = ptr {
            let interface = current.pointee
            if interface.ifa_addr.pointee.sa_family == UInt8(AF_INET) {
                var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
                let nameLen = socklen_t(MemoryLayout<sockaddr_in>.size)
                if getnameinfo(
                    interface.ifa_addr,
                    nameLen,
                    &host,
                    socklen_t(host.count),
                    nil,
                    0,
                    NI_NUMERICHOST
                ) == 0 {
                    results.append((String(cString: interface.ifa_name), String(cString: host)))
                }
            }
            ptr = interface.ifa_next
        }
        return results
    }
}
