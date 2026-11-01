import SwiftUI
import UniformTypeIdentifiers
import UIKit

/// Reliable pairing-file picker. SwiftUI `fileImporter` often shows `.plist` files
/// that can’t be selected (especially inside sheets / on iOS 18–26).
/// Also used for WireGuard `.conf` imports (`types` + `allowsMultiple`).
struct PairingDocumentPicker: UIViewControllerRepresentable {
    var types: [UTType] = PairingStore.supportedTypes
    var allowsMultiple = false
    var onPick: (URL) -> Void
    var onCancel: (() -> Void)?

    func makeCoordinator() -> Coordinator {
        Coordinator(onPick: onPick, onCancel: onCancel)
    }

    func makeUIViewController(context: Context) -> UIDocumentPickerViewController {
        let picker = UIDocumentPickerViewController(
            forOpeningContentTypes: types,
            asCopy: true
        )
        picker.delegate = context.coordinator
        picker.allowsMultipleSelection = allowsMultiple
        picker.shouldShowFileExtensions = true
        return picker
    }

    func updateUIViewController(_ uiViewController: UIDocumentPickerViewController, context: Context) {}

    final class Coordinator: NSObject, UIDocumentPickerDelegate {
        let onPick: (URL) -> Void
        let onCancel: (() -> Void)?

        init(onPick: @escaping (URL) -> Void, onCancel: (() -> Void)?) {
            self.onPick = onPick
            self.onCancel = onCancel
        }

        func documentPicker(_ controller: UIDocumentPickerViewController, didPickDocumentsAt urls: [URL]) {
            guard !urls.isEmpty else {
                onCancel?()
                return
            }
            urls.forEach(onPick)
        }

        func documentPickerWasCancelled(_ controller: UIDocumentPickerViewController) {
            onCancel?()
        }
    }
}
