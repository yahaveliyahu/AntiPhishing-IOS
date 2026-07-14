//
//  QRScannerView.swift
//  AntiPhishing
//
//  Port of QrScannerActivity. Uses AVFoundation (the iOS equivalent of
//  CameraX + ML Kit barcode scanning) to detect QR codes containing URLs,
//  then runs the same check pipeline and shows the ResultView.
//

import SwiftUI
import AVFoundation

struct QRScannerView: View {
    let onClose: () -> Void

    @EnvironmentObject var settings: AppSettings
    @StateObject private var history = HistoryStore.shared

    @State private var scanHandled = false
    @State private var detectedUrl: String?
    @State private var result: CheckResult?
    @State private var safeBanner: String?

    var body: some View {
        ZStack {
            if let url = detectedUrl {
                if let result {
                    ResultView(
                        url: url,
                        result: result,
                        isQr: true,
                        onProceed: { open(url); onClose() },
                        onGoBack: onClose
                    )
                    .background(Color(.systemBackground))
                } else {
                    CheckingView(url: url, isQr: true)
                        .background(Color(.systemBackground))
                }
            } else {
                cameraLayer
            }

            if let safeBanner {
                VStack {
                    Spacer()
                    Text(safeBanner)
                        .padding()
                        .background(.ultraThinMaterial)
                        .clipShape(Capsule())
                        .padding(.bottom, 40)
                }
            }
        }
    }

    private var cameraLayer: some View {
        ZStack {
            CameraPreview { code in
                guard !scanHandled, let url = CheckPipeline.extractUrlFromText(code) else { return }
                scanHandled = true
                Task { await handle(url) }
            }
            .ignoresSafeArea()

            VStack {
                HStack {
                    Text(L10n.string("scan_qr_title", settings.language))
                        .foregroundStyle(.white).font(.title3).bold()
                    Spacer()
                    Button(action: onClose) {
                        Image(systemName: "xmark").foregroundStyle(.white).font(.title3)
                    }
                }
                .padding()
                Spacer()
                Text(L10n.string("point_camera", settings.language))
                    .foregroundStyle(.white).font(.subheadline)
                    .padding(.bottom, 48)
            }
        }
    }

    private func handle(_ url: String) async {
        detectedUrl = url
        let r = await CheckPipeline.check(url, useQrEndpoint: true)
        history.insertAndTrim(CheckPipeline.makeHistoryEntry(url: url, result: r))
        if case .whitelisted = r {
            safeBanner = L10n.string("qr_safe_message", settings.language)
        }
        result = r
    }

    private func open(_ url: String) {
        URLOpener.open(url)
    }
}

// MARK: - AVFoundation camera preview + QR detection

struct CameraPreview: UIViewControllerRepresentable {
    let onDetect: (String) -> Void

    func makeUIViewController(context: Context) -> ScannerViewController {
        let vc = ScannerViewController()
        vc.onDetect = onDetect
        return vc
    }

    func updateUIViewController(_ uiViewController: ScannerViewController, context: Context) {}
}

final class ScannerViewController: UIViewController, AVCaptureMetadataOutputObjectsDelegate {
    var onDetect: ((String) -> Void)?
    private let session = AVCaptureSession()
    private var previewLayer: AVCaptureVideoPreviewLayer?

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .black
        configureSession()
    }

    private func configureSession() {
        guard let device = AVCaptureDevice.default(for: .video),
              let input = try? AVCaptureDeviceInput(device: device),
              session.canAddInput(input) else { return }
        session.addInput(input)

        let output = AVCaptureMetadataOutput()
        if session.canAddOutput(output) {
            session.addOutput(output)
            output.setMetadataObjectsDelegate(self, queue: .main)
            output.metadataObjectTypes = [.qr]
        }

        let layer = AVCaptureVideoPreviewLayer(session: session)
        layer.videoGravity = .resizeAspectFill
        layer.frame = view.layer.bounds
        view.layer.addSublayer(layer)
        previewLayer = layer

        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            self?.session.startRunning()
        }
    }

    override func viewDidLayoutSubviews() {
        super.viewDidLayoutSubviews()
        previewLayer?.frame = view.layer.bounds
    }

    func metadataOutput(_ output: AVCaptureMetadataOutput,
                        didOutput metadataObjects: [AVMetadataObject],
                        from connection: AVCaptureConnection) {
        guard let obj = metadataObjects.first as? AVMetadataMachineReadableCodeObject,
              let value = obj.stringValue else { return }
        onDetect?(value)
    }

    override func viewWillDisappear(_ animated: Bool) {
        super.viewWillDisappear(animated)
        if session.isRunning {
            DispatchQueue.global(qos: .userInitiated).async { [weak self] in
                self?.session.stopRunning()
            }
        }
    }
}
