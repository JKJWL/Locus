import SwiftUI
import UIKit
import UniformTypeIdentifiers

/// Settings › IP masking: provider dropdown (Mullvad / Proton VPN / WireGuard
/// file), account login or config imports, and tunnel status.
struct IPMaskSection: View {
    @EnvironmentObject private var session: SpoofSession
    @ObservedObject private var ipMask = IPMask.shared

    @State private var mullvadAccount = ""
    @State private var message: String?
    @State private var showConfImporter = false
    @State private var editing: WireGuardProfile?
    @State private var editLocation = ""

    private static let confTypes: [UTType] = [UTType(filenameExtension: "conf"), .plainText, .data].compactMap { $0 }

    var body: some View {
        Section {
            Picker("Provider", selection: Binding(
                get: { ipMask.provider },
                set: { ipMask.setProvider($0); message = nil }
            )) {
                ForEach(VPNProvider.allCases) { provider in
                    Text(provider.title).tag(provider)
                }
            }
            .pickerStyle(.menu)

            switch ipMask.provider {
            case .mullvad:
                mullvadRows
            case .proton, .custom:
                profileRows
            }

            if ipMask.isReady {
                Toggle("Match IP to spoofed location", isOn: Binding(
                    get: { ipMask.enabled },
                    set: { ipMask.setEnabled($0, near: session.simulated ?? session.realCoordinate) }
                ))
                LabeledContent("Status") {
                    Text(statusText)
                        .foregroundStyle(statusColor)
                        .multilineTextAlignment(.trailing)
                }
                if let target = ipMask.target {
                    LabeledContent("Server") {
                        VStack(alignment: .trailing) {
                            Text("\(target.place) · \(target.serverName)")
                            if let km = target.distanceKm {
                                Text("\(Int(km.rounded())) km from spoof")
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                        }
                    }
                }
                LabeledContent("Proxy", value: "127.0.0.1:\(IPMask.proxyPort)")
                Button("Check my IP") {
                    Task { await ipMask.checkIP() }
                }
                if let check = ipMask.lastCheck {
                    Text(check)
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
            }

            if let message {
                Text(message)
                    .font(.footnote)
                    .foregroundStyle(LocusTheme.statusBad)
            }
        } header: {
            Text("IP masking")
        } footer: {
            Text(footer)
        }
        .sheet(isPresented: $showConfImporter) {
            PairingDocumentPicker(
                types: Self.confTypes,
                allowsMultiple: true,
                onPick: { url in
                    showConfImporter = false
                    importFile(url)
                },
                onCancel: { showConfImporter = false }
            )
            .ignoresSafeArea()
        }
        .alert("Server location", isPresented: Binding(
            get: { editing != nil },
            set: { if !$0 { editing = nil } }
        )) {
            TextField("City, region or country", text: $editLocation)
            Button("Save") {
                if let profile = editing {
                    let label = editLocation
                    Task {
                        let found = await ipMask.setLocation(label, for: profile.id)
                        message = found || label.isEmpty ? nil : "Couldn't find \"\(label)\" on the map. Try a city and country."
                    }
                }
                editing = nil
            }
            Button("Cancel", role: .cancel) { editing = nil }
        } message: {
            Text("Where this server's IP is, e.g. \"Pittsburgh, PA\". Locus uses it to pick the config nearest your spoofed location.")
        }
    }

    // MARK: Mullvad

    @ViewBuilder
    private var mullvadRows: some View {
        if ipMask.isLoggedIn {
            LabeledContent("Account", value: ipMask.maskedAccount ?? "")
            if let name = ipMask.deviceName {
                LabeledContent("Device", value: name)
            }
            Button("Log out of Mullvad", role: .destructive) {
                Task { await ipMask.logOut() }
            }
            .disabled(ipMask.isBusy)
        } else {
            SecureField("Mullvad account number", text: $mullvadAccount)
                .keyboardType(.numberPad)
            Button(ipMask.isBusy ? "Logging in…" : "Log in") {
                Task {
                    do {
                        try await ipMask.logIn(accountNumber: mullvadAccount)
                        mullvadAccount = ""
                        message = nil
                    } catch {
                        message = error.localizedDescription
                    }
                }
            }
            .disabled(ipMask.isBusy || mullvadAccount.isEmpty)
        }
    }

    // MARK: Imported configs

    @ViewBuilder
    private var profileRows: some View {
        ForEach(ipMask.profiles(for: ipMask.provider)) { profile in
            Button {
                editLocation = profile.locationLabel
                editing = profile
            } label: {
                VStack(alignment: .leading, spacing: 2) {
                    Text(profile.name)
                        .foregroundStyle(.primary)
                    Text(locationLine(profile))
                        .font(.caption)
                        .foregroundStyle(profile.coordinate == nil ? LocusTheme.statusWarn : .secondary)
                }
            }
            .swipeActions {
                Button("Delete", role: .destructive) {
                    ipMask.deleteProfile(profile.id)
                }
            }
        }
        Button("Import .conf file…") { showConfImporter = true }
        Button("Paste config from clipboard") { pasteConfig() }
    }

    private func locationLine(_ profile: WireGuardProfile) -> String {
        if profile.locationLabel.isEmpty { return "Location not set — tap to set" }
        return profile.coordinate == nil ? "\(profile.locationLabel) (not found — tap to fix)" : profile.locationLabel
    }

    private func importFile(_ url: URL) {
        let scoped = url.startAccessingSecurityScopedResource()
        defer { if scoped { url.stopAccessingSecurityScopedResource() } }
        guard let text = try? String(contentsOf: url, encoding: .utf8) else {
            message = "Couldn't read \(url.lastPathComponent)."
            return
        }
        importText(text, fileName: url.lastPathComponent)
    }

    private func pasteConfig() {
        guard let text = UIPasteboard.general.string, !text.isEmpty else {
            message = "The clipboard is empty. Copy the contents of a WireGuard .conf first."
            return
        }
        importText(text, fileName: "Pasted config")
    }

    private func importText(_ text: String, fileName: String) {
        let provider = ipMask.provider
        Task {
            do {
                let profile = try await ipMask.importConfig(text, fileName: fileName, provider: provider)
                message = profile.coordinate == nil
                    ? "Imported \(profile.name). Tap it to set where the server is."
                    : nil
            } catch {
                message = error.localizedDescription
            }
        }
    }

    // MARK: Status

    private var statusText: String {
        switch ipMask.state {
        case .off: return "Off"
        case .connecting: return "Connecting…"
        case .connected: return "Connected"
        case .failed(let message): return message
        }
    }

    private var statusColor: Color {
        switch ipMask.state {
        case .off: return .secondary
        case .connecting: return LocusTheme.statusWarn
        case .connected: return LocusTheme.statusGood
        case .failed: return LocusTheme.statusBad
        }
    }

    private var footer: String {
        let source: String
        switch ipMask.provider {
        case .mullvad:
            source = "Uses the Mullvad server nearest your spoofed location, switching when you teleport near a different city."
        case .proton:
            source = "On account.protonvpn.com › Downloads › WireGuard configuration, create one config per city you want (standard or Secure Core) and import them all. Locus uses whichever is nearest your spoofed location."
        case .custom:
            source = "Import any WireGuard .conf, one per server. Tap a config to set where it exits; Locus uses whichever is nearest your spoofed location."
        }
        return source + " Then set Settings › Wi‑Fi › (i) › Configure Proxy › Manual: Server 127.0.0.1, Port \(IPMask.proxyPort). Covers normal app and web traffic on Wi‑Fi only — calls, some games and cellular use your real IP. Keep Locus running: if it's closed, Wi‑Fi browsing stops until you reopen it or turn the proxy off."
    }
}
