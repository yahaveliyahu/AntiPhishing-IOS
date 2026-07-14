//
//  ShareViewController.swift
//  AntiPhishingShare (Share Extension target)
//
//  This is the iOS equivalent of Android's link interception. Instead of
//  silently capturing every link (which iOS does not permit for third-party
//  apps), the user taps "Share → AntiPhishing" on a link from any app
//  (Safari, Messages, WhatsApp, Mail, …). This extension extracts the URL,
//  runs the SAME check pipeline, shows the SAME warning screens, and records
//  the result into the SAME shared history (via the App Group).
//
//  ── Setup in Xcode ──────────────────────────────────────────────────────────
//  1. File ▸ New ▸ Target… ▸ Share Extension. Name it "AntiPhishingShare".
//  2. Delete the auto-generated MainInterface.storyboard and the boilerplate
//     ShareViewController; replace with this file.
//  3. Add these files to the extension target (check the target box):
//        LexicalAnalyzer.swift, CheckResult.swift, LocalUrlLists.swift,
//        CheckPipeline.swift, ApiClient.swift, HistoryStore.swift,
//        AppSettings.swift, Localization.swift, Theme.swift,
//        Components.swift, ResultView.swift, LinkCheckView.swift
//     (Select each file ▸ File Inspector ▸ Target Membership ▸ tick the
//      extension target. The UI files only need SwiftUI, no camera.)
//  4. Add the App Group "group.ronyahav.antiphishing" capability to BOTH
//     the app target and this extension target.
//  5. In the extension's Info.plist, set the activation rule to accept URLs
//     and text (NSExtensionActivationSupportsWebURLWithMaxCount = 1 and
//     NSExtensionActivationSupportsText = YES) — see ShareExtension-Info.plist.
//

import SwiftUI
import UniformTypeIdentifiers

class ShareViewController: UIHostingController<ShareRootView> {

    required init?(coder aDecoder: NSCoder) {
        super.init(coder: aDecoder, rootView: ShareRootView(extracted: nil, onDone: { _ in }))
        self.rootView = ShareRootView(extracted: nil, onDone: { [weak self] open in
            self?.finish(openURL: open)
        })
        loadSharedItem()
    }

    private func loadSharedItem() {
        guard let item = extensionContext?.inputItems.first as? NSExtensionItem,
              let providers = item.attachments else {
            finish(openURL: nil); return
        }

        let urlType = UTType.url.identifier
        let textType = UTType.plainText.identifier

        for provider in providers {
            if provider.hasItemConformingToTypeIdentifier(urlType) {
                provider.loadItem(forTypeIdentifier: urlType, options: nil) { [weak self] data, _ in
                    let urlString = (data as? URL)?.absoluteString
                        ?? (data as? String) ?? ""
                    DispatchQueue.main.async { self?.present(urlString) }
                }
                return
            }
        }
        for provider in providers {
            if provider.hasItemConformingToTypeIdentifier(textType) {
                provider.loadItem(forTypeIdentifier: textType, options: nil) { [weak self] data, _ in
                    let text = (data as? String) ?? ""
                    DispatchQueue.main.async { self?.present(text) }
                }
                return
            }
        }
        finish(openURL: nil)
    }

    private func present(_ rawText: String) {
        guard let url = CheckPipeline.extractUrlFromText(rawText) else {
            finish(openURL: nil); return
        }
        rootView = ShareRootView(extracted: url, onDone: { [weak self] open in
            self?.finish(openURL: open)
        })
    }

    private func finish(openURL: String?) {
        if let openURL, let u = URL(string: openURL) {
            // Hand the URL back to the system so it opens after dismissal.
            _ = openURL
            extensionContext?.open(u) { _ in
                self.extensionContext?.completeRequest(returningItems: [], completionHandler: nil)
            }
        } else {
            extensionContext?.completeRequest(returningItems: [], completionHandler: nil)
        }
    }
}

// MARK: - Root SwiftUI view for the share sheet

struct ShareRootView: View {
    let extracted: String?
    let onDone: (String?) -> Void

    @StateObject private var settings = AppSettings.shared

    var body: some View {
        Group {
            if let url = extracted {
                LinkCheckView(
                    url: url,
                    onDismiss: { onDone(nil) },
                    onOpen: { open in onDone(open) }
                )
                .environmentObject(settings)
            } else {
                VStack(spacing: 16) {
                    ProgressView()
                    Text(L10n.string("no_link_found", settings.language))
                        .font(.callout)
                        .foregroundStyle(.secondary)
                    Button(L10n.string("close", settings.language)) { onDone(nil) }
                        .buttonStyle(.borderedProminent)
                }
                .padding()
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Color(.systemBackground))
    }
}
