import Foundation
import idevice
import UIKit
import UserNotifications
import CoreLocation

/// Runs idevice's iOS 27+ pairable-host flow on-device.
///
/// `pairable_host_prepare` generates the host identity + TXT records; advertising
/// uses Network.framework NWListener (Bonjour). Inbound TCP is relayed to a
/// loopback socket whose accepted fd goes to `pairable_host_accept_fd`. The
/// 6-digit PIN is created only after that connection + pair-setup handshake.
@MainActor
final class PairOnDeviceService: ObservableObject {
    enum Phase: Equatable {
        case idle
        case advertising
        case deviceConnected
        case awaitingPIN(String)
        case succeeded
        case failed(String)
    }

    @Published private(set) var phase: Phase = .idle
    @Published private(set) var pin: String?
    @Published private(set) var debugPort: UInt16?

    private var worker: Thread?
    private var callbackBox = PairCallbackBox()
    private var backgroundTask = UIBackgroundTaskIdentifier.invalid
    private let keepAlive = PairingKeepAlive()
    private let audioKeepAlive = SilentAudioKeepAlive()
    private let advertiser = PairableHostAdvertiser()

    var isBusy: Bool {
        switch phase {
        case .advertising, .deviceConnected, .awaitingPIN: return true
        default: return false
        }
    }

    func start(pairingStore: PairingStore) {
        guard !isBusy else { return }
        phase = .advertising
        pin = nil
        debugPort = nil
        // Fresh box per attempt so a cancelled worker can't call into a new run.
        callbackBox.cancel()
        callbackBox = PairCallbackBox()
        callbackBox.owner = self

        requestNotificationPermission()
        beginKeepAlive()

        _ = pairingStore.pairingURL
        try? FileManager.default.createDirectory(
            at: pairingStore.pairingURL.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )

        let outputPath = pairingStore.pairingURL.path
        let box = callbackBox

        worker = Thread {
            autoreleasepool {
                Self.runBlockingAccept(outputPath: outputPath, box: box)
            }
        }
        worker?.name = "locus.pairable-host"
        worker?.qualityOfService = .userInitiated
        worker?.start()
    }

    func acknowledgeFailure() {
        if case .failed = phase {
            teardown()
            phase = .idle
            pin = nil
        }
    }

    func resetToIdle() {
        teardown()
        phase = .idle
        pin = nil
        debugPort = nil
    }

    fileprivate func handleListening(port: UInt16, serviceIdentifier: String, txtRecords: [String: String]) {
        debugPort = port
        advertiser.publish(port: port, serviceIdentifier: serviceIdentifier, txtRecords: txtRecords)
        phase = .advertising
        NSLog("[Locus] listening on %u, Bonjour id=%@", port, serviceIdentifier)
    }

    fileprivate func handleConnected() {
        phase = .deviceConnected
        Self.postPlainNotification(
            title: "Locus connected",
            body: "Generating pairing code…"
        )
    }

    fileprivate func handlePIN(_ value: String) {
        pin = value
        phase = .awaitingPIN(value)
        Self.postPINNotification(value)
        UINotificationFeedbackGenerator().notificationOccurred(.success)
    }

    fileprivate func handleSuccess() {
        pin = nil
        phase = .succeeded
        // Don't cancel the relay: the device may still be receiving M6.
        callbackBox.cancel()
        advertiser.stopListening()
        endKeepAlive()
        Self.postPlainNotification(
            title: "Locus paired",
            body: "RPPairing is ready. Connect LocalDevVPN, then teleport."
        )
    }

    fileprivate func handleFailure(_ message: String) {
        pin = nil
        phase = .failed(message)
        teardown()
    }

    private func teardown() {
        callbackBox.cancel()
        advertiser.stop()
        endKeepAlive()
    }

    private func beginKeepAlive() {
        UIApplication.shared.isIdleTimerDisabled = true
        keepAlive.start()
        audioKeepAlive.start()
        guard backgroundTask == .invalid else { return }
        backgroundTask = UIApplication.shared.beginBackgroundTask(withName: "locus.pairable-host") { [weak self] in
            self?.endKeepAlive()
        }
    }

    private func endKeepAlive() {
        UIApplication.shared.isIdleTimerDisabled = false
        keepAlive.stop()
        audioKeepAlive.stop()
        guard backgroundTask != .invalid else { return }
        UIApplication.shared.endBackgroundTask(backgroundTask)
        backgroundTask = .invalid
    }

    private func requestNotificationPermission() {
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound]) { _, _ in }
    }

    private static func postPINNotification(_ pin: String) {
        let content = UNMutableNotificationContent()
        content.title = "Locus pairing code"
        content.body = pin
        content.sound = .default
        if #available(iOS 15.0, *) {
            content.interruptionLevel = .timeSensitive
        }
        let request = UNNotificationRequest(identifier: "locus.pairing.pin", content: content, trigger: nil)
        UNUserNotificationCenter.current().add(request)
    }

    private static func postPlainNotification(title: String, body: String) {
        let content = UNMutableNotificationContent()
        content.title = title
        content.body = body
        content.sound = .default
        let request = UNNotificationRequest(identifier: "locus.pairing.status.\(UUID().uuidString)", content: content, trigger: nil)
        UNUserNotificationCenter.current().add(request)
    }

    nonisolated private static func runBlockingAccept(outputPath: String, box: PairCallbackBox) {
        let name = "Locus"
        let model = "Mac17,7"

        // 1. Generate host identity + the TXT records Developer Mode expects.
        var handle: OpaquePointer?
        var serviceIDPtr: UnsafeMutablePointer<CChar>?
        var txtData: UnsafeMutablePointer<UInt8>?
        var txtLen: UInt = 0
        var altIRK = [UInt8](repeating: 0, count: 16)

        let prepareError: UnsafeMutablePointer<IdeviceFfiError>? = name.withCString { namePtr in
            model.withCString { modelPtr in
                pairable_host_prepare(
                    namePtr,
                    modelPtr,
                    false,
                    &handle,
                    &serviceIDPtr,
                    &txtData,
                    &txtLen,
                    &altIRK
                )
            }
        }
        if let prepareError {
            fail(box, errorMessage(prepareError, fallback: "Could not prepare pairing host"))
            return
        }
        guard let handle, let serviceIDPtr, let txtData else {
            fail(box, "Could not prepare pairing host.")
            return
        }
        defer { pairable_host_free(handle) }

        let serviceIdentifier = String(cString: serviceIDPtr)
        idevice_string_free(serviceIDPtr)
        let txtRecords = parseTXTRecords(Data(bytes: txtData, count: Int(txtLen)))
        idevice_data_free(txtData, txtLen)
        NSLog("[Locus] pairable host prepared id=%@ txt=%@", serviceIdentifier, txtRecords.description)

        // 2. Loopback socket that the Bonjour listener relays the device into.
        guard let loopback = LoopbackPairingSocket() else {
            fail(box, "Could not open a local socket for pairing.")
            return
        }
        defer { loopback.close() }

        DispatchQueue.main.async {
            box.owner?.handleListening(
                port: loopback.port,
                serviceIdentifier: serviceIdentifier,
                txtRecords: txtRecords
            )
        }

        guard let fd = loopback.acceptConnection(isCancelled: { box.isCancelled }) else {
            fail(box, "Pairing connection failed.")
            return
        }
        defer { Darwin.close(fd) }
        DispatchQueue.main.async { box.owner?.handleConnected() }

        // 3. Run pair-setup on the connected socket (PIN arrives via callback).
        var outFile: OpaquePointer?
        let err = pairable_host_accept_fd(
            handle,
            fd,
            pinDisplayTrampoline,
            Unmanaged.passUnretained(box).toOpaque(),
            nil,
            &outFile
        )

        if let err {
            fail(box, errorMessage(err, fallback: "Unknown pairing error"))
            return
        }

        guard let outFile else {
            DispatchQueue.main.async {
                box.owner?.handleFailure("Pairing finished but no pairing file was returned.")
            }
            return
        }

        defer { rp_pairing_file_free(outFile) }

        let parent = (outputPath as NSString).deletingLastPathComponent
        try? FileManager.default.createDirectory(atPath: parent, withIntermediateDirectories: true)

        let writeError = outputPath.withCString { path in
            rp_pairing_file_write(outFile, path)
        }
        if let writeError {
            let message: String
            if let cMessage = writeError.pointee.message {
                message = String(cString: cMessage)
            } else {
                message = "Failed to write pairing file"
            }
            idevice_error_free(writeError)
            DispatchQueue.main.async {
                box.owner?.handleFailure("Paired, but failed to save file: \(message)")
            }
            return
        }

        try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: outputPath)
        DispatchQueue.main.async { box.owner?.handleSuccess() }
    }

    /// Reports a failure unless the attempt was cancelled (reset / new attempt).
    nonisolated private static func fail(_ box: PairCallbackBox, _ message: String) {
        guard !box.isCancelled else { return }
        DispatchQueue.main.async { box.owner?.handleFailure(message) }
    }

    /// Reads and frees an idevice error.
    nonisolated private static func errorMessage(_ err: UnsafeMutablePointer<IdeviceFfiError>, fallback: String) -> String {
        defer { idevice_error_free(err) }
        if let cMessage = err.pointee.message {
            return String(cString: cMessage)
        }
        return "\(fallback) (\(err.pointee.code))"
    }

    /// `pairable_host_prepare` returns TXT records as an XML plist dictionary.
    nonisolated private static func parseTXTRecords(_ data: Data) -> [String: String] {
        let plist = try? PropertyListSerialization.propertyList(from: data, format: nil)
        return (plist as? [String: String]) ?? [:]
    }
}

/// Blocking 127.0.0.1 listener whose accepted fd is passed to idevice.
private final class LoopbackPairingSocket {
    let port: UInt16
    private var listenFD: Int32

    init?() {
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { return nil }

        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = 0
        addr.sin_addr.s_addr = inet_addr("127.0.0.1")
        var len = socklen_t(MemoryLayout<sockaddr_in>.size)

        let bound = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, len) }
        }
        guard bound == 0, listen(fd, 1) == 0 else {
            Darwin.close(fd)
            return nil
        }
        let named = withUnsafeMutablePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &len) }
        }
        guard named == 0 else {
            Darwin.close(fd)
            return nil
        }

        listenFD = fd
        port = UInt16(bigEndian: addr.sin_port)
    }

    /// Polls so a cancelled attempt doesn't block this thread forever.
    func acceptConnection(isCancelled: () -> Bool) -> Int32? {
        var pfd = pollfd(fd: listenFD, events: Int16(POLLIN), revents: 0)
        while !isCancelled() {
            let ready = poll(&pfd, 1, 500)
            if ready < 0 {
                if errno == EINTR { continue }
                return nil
            }
            if ready == 0 { continue }
            let fd = Darwin.accept(listenFD, nil, nil)
            return fd >= 0 ? fd : nil
        }
        return nil
    }

    func close() {
        guard listenFD >= 0 else { return }
        Darwin.close(listenFD)
        listenFD = -1
    }
}

private final class PairingKeepAlive: NSObject, CLLocationManagerDelegate {
    private let manager = CLLocationManager()

    override init() {
        super.init()
        manager.delegate = self
        manager.desiredAccuracy = kCLLocationAccuracyThreeKilometers
        manager.pausesLocationUpdatesAutomatically = false
        manager.allowsBackgroundLocationUpdates = true
        manager.showsBackgroundLocationIndicator = true
    }

    func start() {
        manager.requestAlwaysAuthorization()
        manager.startUpdatingLocation()
    }

    func stop() {
        manager.stopUpdatingLocation()
    }
}

final class PairCallbackBox: @unchecked Sendable {
    weak var owner: PairOnDeviceService?
    private let lock = NSLock()
    private var cancelled = false

    var isCancelled: Bool {
        lock.lock()
        defer { lock.unlock() }
        return cancelled
    }

    func cancel() {
        lock.lock()
        cancelled = true
        lock.unlock()
    }
}

private func pinDisplayTrampoline(pin: UnsafePointer<CChar>?, context: UnsafeMutableRawPointer?) {
    guard let pin, let context else { return }
    let value = String(cString: pin)
    let box = Unmanaged<PairCallbackBox>.fromOpaque(context).takeUnretainedValue()
    DispatchQueue.main.async { box.owner?.handlePIN(value) }
}
