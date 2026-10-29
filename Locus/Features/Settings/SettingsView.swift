import SwiftUI
import UniformTypeIdentifiers

struct SettingsView: View {
    @EnvironmentObject private var pairing: PairingStore
    @EnvironmentObject private var session: SpoofSession
    @Environment(\.dismiss) private var dismiss

    @State private var showImporter = false
    @State private var showPairOnDevice = false
    @State private var showNameEasterEgg = false
    @State private var tunnelIP = TunnelConfig.targetIP
    @State private var localTunnelIP = TunnelConfig.tunnelIP ?? ""
    @ObservedObject private var ipMask = IPMask.shared
    @State private var mullvadAccount = ""
    @State private var mullvadError: String?
    @State private var localDevVPNInstalled = LocalDevVPN.isInstalled
    @Environment(\.scenePhase) private var scenePhase

    private var supportsOnDevicePairing: Bool {
        if #available(iOS 27.0, *) { return true }
        return false
    }

    private var appVersion: String {
        let short = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "—"
        let build = Bundle.main.infoDictionary?["CFBundleVersion"] as? String ?? ""
        return build.isEmpty ? short : "\(short) (\(build))"
    }

    var body: some View {
        NavigationStack {
            List {
                Section {
                    Label {
                        Text(pairing.hasPairingFile ? "RPPairing file installed" : "No pairing file")
                    } icon: {
                        Image(systemName: pairing.hasPairingFile ? "checkmark.seal.fill" : "exclamationmark.triangle.fill")
                            .foregroundStyle(pairing.hasPairingFile ? LocusTheme.statusGood : LocusTheme.statusWarn)
                    }

                    if supportsOnDevicePairing {
                        Button {
                            showPairOnDevice = true
                        } label: {
                            Label("Pair on this iPhone", systemImage: "iphone.gen3.radiowaves.left.and.right")
                        }
                    }

                    Button("Import RPPairing file…") { showImporter = true }
                    Button("Paste RPPairing from clipboard") {
                        do {
                            try pairing.importPairingFromClipboard()
                        } catch {
                            session.lastError = error.localizedDescription
                        }
                    }
                    if pairing.hasPairingFile {
                        Button("Remove pairing file", role: .destructive) {
                            try? pairing.removePairing()
                        }
                    }
                } header: {
                    Text("Developer pairing")
                } footer: {
                    Text(supportsOnDevicePairing
                         ? "On iOS 27, use Pair on this iPhone — no computer. Locus advertises a pairable host; confirm the 6-digit code under Settings › Privacy & Security › Developer Mode › Pair with Host. On older iOS, import an RPPairing file from idevice_pair (not a SideStore lockdown .mobiledevicepairing). LiveContainer: enable Fix File Picker on Locus, or use Paste / Share → LiveContainer → Locus."
                         : "Import an RPPairing file from idevice_pair (not a SideStore lockdown .mobiledevicepairing). If the file picker fails (common in LiveContainer), enable Fix File Picker on the app, share the file into LiveContainer → Locus, or copy the plist and use Paste.")
                }

                Section {
                    LabeledContent("Device IP") {
                        TextField("10.7.0.1", text: $tunnelIP)
                            .multilineTextAlignment(.trailing)
                            .keyboardType(.numbersAndPunctuation)
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled()
                            .onSubmit(saveTunnelAddresses)
                    }
                    LabeledContent("Tunnel IP") {
                        TextField("Auto", text: $localTunnelIP)
                            .multilineTextAlignment(.trailing)
                            .keyboardType(.numbersAndPunctuation)
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled()
                            .onSubmit(saveTunnelAddresses)
                    }
                    LabeledContent("Status") {
                        Text(LocalDevVPN.isConnected ? "Connected" : "Not connected")
                            .foregroundStyle(LocalDevVPN.isConnected ? LocusTheme.statusGood : LocusTheme.statusWarn)
                    }
                    if let issue = LocalDevVPN.configurationIssue {
                        Text(issue)
                            .font(.footnote)
                            .foregroundStyle(LocusTheme.statusWarn)
                    }
                    Button("Save addresses", action: saveTunnelAddresses)
                    Button {
                        if localDevVPNInstalled {
                            LocalDevVPN.openInstalled()
                        } else {
                            LocalDevVPN.openAppStore()
                        }
                    } label: {
                        Label(
                            localDevVPNInstalled ? "Open LocalDevVPN" : "Get LocalDevVPN (App Store)",
                            systemImage: localDevVPNInstalled ? "lock.shield.fill" : "arrow.down.app.fill"
                        )
                    }
                } header: {
                    Text("Tunnel")
                } footer: {
                    Text("Copy both from LocalDevVPN (the /32 suffix is fine). Device IP is where Locus connects (default 10.7.0.1); Tunnel IP is only used to check LocalDevVPN is up — leave it empty to auto-detect. The pairing file has no addresses, so changing these never needs a re-pair. Start a spoof on Wi‑Fi first; it can keep working on cellular afterward.")
                }

                Section {
                    if ipMask.isLoggedIn {
                        LabeledContent("Account", value: ipMask.maskedAccount ?? "")
                        if let name = ipMask.deviceName {
                            LabeledContent("Device", value: name)
                        }
                        Toggle("Match IP to spoofed location", isOn: Binding(
                            get: { ipMask.enabled },
                            set: { ipMask.setEnabled($0, near: session.simulated ?? session.realCoordinate) }
                        ))
                        LabeledContent("Status") {
                            Text(ipMaskStatus)
                                .foregroundStyle(ipMaskColor)
                                .multilineTextAlignment(.trailing)
                        }
                        if let choice = ipMask.choice {
                            LabeledContent("Server", value: "\(choice.city) · \(choice.hostname)")
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
                                    mullvadError = nil
                                } catch {
                                    mullvadError = error.localizedDescription
                                }
                            }
                        }
                        .disabled(ipMask.isBusy || mullvadAccount.isEmpty)
                    }
                    if let mullvadError {
                        Text(mullvadError)
                            .font(.footnote)
                            .foregroundStyle(LocusTheme.statusBad)
                    }
                } header: {
                    Text("IP masking (Mullvad)")
                } footer: {
                    Text("Routes traffic through the Mullvad server nearest your spoofed location, switching when you teleport near a different city. Then set Settings › Wi‑Fi › (i) › Configure Proxy › Manual: Server 127.0.0.1, Port \(IPMask.proxyPort). Covers normal app and web traffic on Wi‑Fi only — calls, some games and cellular use your real IP. Keep Locus running: if it's closed, Wi‑Fi browsing stops until you reopen it or turn the proxy off.")
                }

                Section("Privacy") {
                    Text("Fully on-device. Favorites and recents stay in UserDefaults. No analytics. Locus only contacts Mullvad (login, server list) if you turn on IP masking.")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }

                Section("About") {
                    LabeledContent("Version", value: appVersion)
                    LabeledContent("Engine", value: "idevice DVT location simulation")
                    Text("Locus is free and open source (MIT). Location injection uses the MIT-licensed idevice FFI.")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }

                Section {
                    Button {
                        showNameEasterEgg = true
                    } label: {
                        Text("locus, n. — a place. From the Latin for where you are.")
                            .font(.footnote.italic())
                            .foregroundStyle(.secondary)
                            .multilineTextAlignment(.center)
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 4)
                    }
                    .buttonStyle(.plain)
                    .listRowBackground(Color.clear)
                    .listRowSeparator(.hidden)
                }
            }
            .navigationTitle("Settings")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Done") {
                        saveTunnelAddresses()
                        dismiss()
                    }
                }
            }
            .sheet(isPresented: $showImporter) {
            PairingDocumentPicker(
                onPick: { url in
                    showImporter = false
                    do {
                        try pairing.importPairing(from: url)
                    } catch {
                        session.lastError = error.localizedDescription
                    }
                },
                onCancel: { showImporter = false }
            )
            .ignoresSafeArea()
        }
            .sheet(isPresented: $showPairOnDevice) {
                PairOnDeviceView()
                    .environmentObject(pairing)
            }
            .fullScreenCover(isPresented: $showNameEasterEgg) {
                LocusEasterEggView()
            }
            .onAppear {
                localDevVPNInstalled = LocalDevVPN.isInstalled
            }
            .onChange(of: scenePhase) { _, phase in
                if phase == .active {
                    localDevVPNInstalled = LocalDevVPN.isInstalled
                }
            }
        }
    }

    private var ipMaskStatus: String {
        switch ipMask.state {
        case .off: return "Off"
        case .connecting: return "Connecting…"
        case .connected: return "Connected"
        case .failed(let message): return message
        }
    }

    private var ipMaskColor: Color {
        switch ipMask.state {
        case .off: return .secondary
        case .connecting: return LocusTheme.statusWarn
        case .connected: return LocusTheme.statusGood
        case .failed: return LocusTheme.statusBad
        }
    }

    private func saveTunnelAddresses() {
        tunnelIP = TunnelConfig.normalized(tunnelIP)
        localTunnelIP = TunnelConfig.normalized(localTunnelIP)
        TunnelConfig.setTargetIP(tunnelIP)
        TunnelConfig.setTunnelIP(localTunnelIP)
    }
}

struct PlacesView: View {
    @EnvironmentObject private var session: SpoofSession
    @EnvironmentObject private var pairing: PairingStore
    @Environment(\.dismiss) private var dismiss

    @State private var placeToRename: SavedPlace?
    @State private var renameText = ""

    var body: some View {
        NavigationStack {
            List {
                Section("Favorites") {
                    if session.favorites.isEmpty {
                        Text("Star a pin from the map to save it.")
                            .foregroundStyle(.secondary)
                    }
                    ForEach(session.favorites) { place in
                        placeButton(place)
                            .swipeActions(edge: .trailing, allowsFullSwipe: true) {
                                Button(role: .destructive) {
                                    session.removeFavorite(place)
                                } label: {
                                    Label("Delete", systemImage: "trash.fill")
                                }
                                Button {
                                    placeToRename = place
                                    renameText = place.name
                                } label: {
                                    Label("Rename", systemImage: "pencil")
                                }
                                .tint(.gray)
                            }
                    }
                }

                Section("Recents") {
                    if session.recents.isEmpty {
                        Text("Teleports show up here.")
                            .foregroundStyle(.secondary)
                    }
                    ForEach(session.recents) { place in
                        placeButton(place)
                            .swipeActions(edge: .trailing, allowsFullSwipe: true) {
                                Button(role: .destructive) {
                                    session.removeRecent(place)
                                } label: {
                                    Label("Delete", systemImage: "trash.fill")
                                }
                            }
                    }
                }
            }
            .navigationTitle("Places")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Done") { dismiss() }
                }
            }
            .alert("Rename Favorite", isPresented: Binding(
                get: { placeToRename != nil },
                set: { if !$0 { placeToRename = nil } }
            )) {
                TextField("Name", text: $renameText)
                Button("Cancel", role: .cancel) {
                    placeToRename = nil
                }
                Button("Save") {
                    if let place = placeToRename {
                        session.renameFavorite(place, to: renameText)
                    }
                    placeToRename = nil
                }
            } message: {
                Text("Choose a name you’ll recognize later.")
            }
        }
    }

    private func placeButton(_ place: SavedPlace) -> some View {
        Button {
            session.teleport(to: place.coordinate, pairing: pairing)
            dismiss()
        } label: {
            VStack(alignment: .leading, spacing: 2) {
                Text(place.name).foregroundStyle(.primary)
                Text(String(format: "%.5f, %.5f", place.latitude, place.longitude))
                    .font(.caption.monospaced())
                    .foregroundStyle(.secondary)
            }
        }
    }
}
