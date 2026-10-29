import Foundation
import idevice

/// Routes idevice's Rust tracing output to Documents/idevice-debug.log.
///
/// Documents is exposed in the Files app (UIFileSharingEnabled), so the log can
/// be shared from the phone when debugging pairing / tunnel failures without Xcode.
enum IdeviceLog {
    static var fileURL: URL {
        FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("idevice-debug.log")
    }

    static func start() {
        let path = strdup(fileURL.path)
        defer { free(path) }
        // 0 = Disabled (console), 4 = Debug (file). Raw values from IdeviceLogLevel.
        let result = idevice_init_logger(IdeviceLogLevel(rawValue: 0), IdeviceLogLevel(rawValue: 4), path)
        NSLog("[Locus] idevice logger init: %d → %@", result.rawValue, fileURL.path)
    }
}
