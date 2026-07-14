//
//  LinkCheckView.swift
//  AntiPhishing
//
//  Runs the full check pipeline for a single URL (from the manual field or a
//  shared link) and shows the CheckingView → ResultView flow. This is the
//  iOS-friendly equivalent of LinkInterceptorActivity's checking screen.
//

import SwiftUI

struct LinkCheckView: View {
    let url: String
    let onDismiss: () -> Void
    /// Optional custom "open" handler. The Share Extension injects this to open
    /// the URL via its extensionContext (UIApplication.shared.open is unavailable
    /// inside extensions). When nil, the app opens the URL itself.
    var onOpen: ((String) -> Void)? = nil

    @EnvironmentObject var settings: AppSettings
    @StateObject private var history = HistoryStore.shared

    @State private var result: CheckResult?
    @State private var safeBanner: String?

    var body: some View {
        ZStack {
            if let result {
                ResultView(
                    url: url,
                    result: result,
                    onProceed: { proceed() },
                    onGoBack: onDismiss
                )
            } else {
                CheckingView(url: url)
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
        .task {
            let r = await CheckPipeline.check(url)
            history.insertAndTrim(CheckPipeline.makeHistoryEntry(url: url, result: r))
            if case .whitelisted = r {
                safeBanner = L10n.string("safe_message", settings.language)
            }
            result = r
        }
    }

    private func proceed() {
        // Opening is always delegated to the caller (URLOpener in the app,
        // extensionContext in the Share Extension) so this view contains no
        // reference to UIApplication.shared and compiles in both targets.
        onOpen?(url)
        if onOpen == nil { onDismiss() }
    }
}
