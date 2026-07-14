//
//  ContentView.swift
//  AntiPhishing
//
//  Main dashboard — port of MainActivity.kt.
//  Shows the animated shield, protection toggle, stats, QR scanner button,
//  a manual link-check field (iOS-friendly equivalent of link interception),
//  recent activity, the "open safe links in" selector, and language toggle.
//

import SwiftUI
import UIKit

struct ContentView: View {
    @StateObject private var settings = AppSettings.shared
    @StateObject private var history = HistoryStore.shared
    @ObservedObject private var protectionCenter = ProtectionCenter.shared

    @Environment(\.scenePhase) private var scenePhase

    @State private var showScanner = false
    @State private var manualLink = ""
    @State private var checkUrl: String?      // drives the result sheet

    // Activation flow (iOS-honest equivalent of Android's "turn on protection"
    // browser-role step): toggling on opens a setup sheet, and returning to the
    // app verifies the checking pipeline actually works.
    @State private var showActivation = false
    @State private var activationConfirmed = false
    @State private var pendingSettingsReturn = false
    @State private var statusBanner: String?

    private var lang: AppLanguage { settings.language }

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 0) {
                    Spacer().frame(height: 16)
                    SecurityShield()
                    Spacer().frame(height: 16)

                    Text(settings.isProtectionActive
                         ? L10n.string("system_protected", lang)
                         : L10n.string("protection_disabled", lang))
                        .font(.title3).bold()
                        .foregroundStyle(settings.isProtectionActive ? AppColors.primary : .red)

                    Spacer().frame(height: 24)

                    // Stats
                    HStack(spacing: 16) {
                        StatCard(label: L10n.string("stats_scanned_today", lang),
                                 value: "\(history.todayScannedCount)",
                                 color: AppColors.primary)
                        StatCard(label: L10n.string("stats_threats_blocked", lang),
                                 value: "\(history.blockedThreatsCount)",
                                 color: .red)
                    }

                    Spacer().frame(height: 24)

                    // Master protection switch
                    HStack {
                        Text(L10n.string("active_protection", lang))
                            .font(.headline)
                        Spacer()
                        Toggle("", isOn: Binding(
                            get: { settings.isProtectionActive },
                            set: { on in setProtection(on) }
                        )).labelsHidden()
                    }
                    .padding(16)
                    .background(Color(.secondarySystemBackground).opacity(0.5))
                    .clipShape(RoundedRectangle(cornerRadius: 12))

                    Spacer().frame(height: 16)

                    // Safari Web Extension protection — status card + entry
                    // to the database / allowlist / extension-setup screen.
                    NavigationLink {
                        SafariProtectionView().environmentObject(settings)
                    } label: {
                        safariProtectionCard
                    }
                    .buttonStyle(.plain)

                    Spacer().frame(height: 16)

                    // Manual link check (iOS-friendly interception equivalent)
                    VStack(alignment: .leading, spacing: 8) {
                        Text(L10n.string("check_link", lang)).font(.subheadline).bold()
                        HStack {
                            TextField(L10n.string("paste_link", lang), text: $manualLink)
                                .textInputAutocapitalization(.never)
                                .autocorrectionDisabled()
                                .textFieldStyle(.roundedBorder)
                            Button(L10n.string("check_button", lang)) {
                                if let u = CheckPipeline.extractUrlFromText(manualLink) {
                                    checkUrl = u
                                }
                            }
                            .buttonStyle(.borderedProminent)
                            .disabled(manualLink.trimmingCharacters(in: .whitespaces).isEmpty)
                        }
                    }
                    .padding(16)
                    .background(Color(.secondarySystemBackground).opacity(0.5))
                    .clipShape(RoundedRectangle(cornerRadius: 12))

                    Spacer().frame(height: 16)

                    // QR scanner button — disabled when protection is off
                    Button {
                        if settings.isProtectionActive {
                            showScanner = true
                        }
                    } label: {
                        Text("📷  " + L10n.string("scan_qr", lang))
                            .bold()
                            .frame(maxWidth: .infinity).frame(height: 52)
                    }
                    .background(settings.isProtectionActive ? AppColors.primary : Color.gray)
                    .foregroundStyle(.white)
                    .clipShape(RoundedRectangle(cornerRadius: 12))

                    Spacer().frame(height: 32)

                    // Recent activity
                    Text(L10n.string("recent_activity", lang))
                        .font(.title3).bold()
                        .frame(maxWidth: .infinity, alignment: .leading)
                    Spacer().frame(height: 8)

                    ForEach(history.recentLinks) { link in
                        RecentLinkItem(link: link) { history.deleteLink(id: link.id) }
                    }

                    Spacer().frame(height: 32)
                    Divider()
                    Spacer().frame(height: 16)

                    // "Open safe links in" selector
                    VStack(alignment: .leading, spacing: 8) {
                        Text(L10n.string("target_browser_label", lang))
                            .font(.subheadline).bold()
                        Picker("", selection: $settings.openInSafari) {
                            Text(L10n.string("open_in_safari", lang)).tag(true)
                            Text(L10n.string("open_in_app", lang)).tag(false)
                        }
                        .pickerStyle(.segmented)
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)

                    Spacer().frame(height: 16)

                    Button(role: .destructive) {
                        history.clearHistory()
                    } label: {
                        Label(L10n.string("clear_history", lang), systemImage: "trash")
                            .foregroundStyle(.gray)
                    }

                    Spacer().frame(height: 32)
                }
                .padding(.horizontal, 24)
            }
            .refreshable {
                // Pull-to-refresh: pick up a fresh extension heartbeat,
                // allowlist edits and server freshness without relaunching.
                await protectionCenter.refreshStatus()
            }
            .navigationTitle(L10n.string("app_name", lang))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button {
                        settings.toggleLanguage()
                    } label: {
                        Image(systemName: "globe")
                    }
                }
            }
        }
        .environment(\.layoutDirection, lang == .hebrew ? .rightToLeft : .leftToRight)
        .environmentObject(settings)
        .fullScreenCover(isPresented: $showScanner) {
            QRScannerView(onClose: { showScanner = false })
                .environmentObject(settings)
        }
        .sheet(item: Binding(
            get: { checkUrl.map { IdentifiableURL(value: $0) } },
            set: { checkUrl = $0?.value }
        )) { item in
            LinkCheckView(
                url: item.value,
                onDismiss: { checkUrl = nil; manualLink = "" },
                onOpen: { URLOpener.open($0); checkUrl = nil; manualLink = "" }
            )
            .environmentObject(settings)
        }
        .sheet(isPresented: $showActivation, onDismiss: {
            // Backed out without finishing setup → leave protection off, the way
            // Android reverts the switch when the browser role isn't granted.
            if !activationConfirmed { settings.isProtectionActive = false }
        }) {
            ActivationSetupView(
                onOpenSettings: { openDefaultBrowserSettings() },
                onDone: { finishActivation() }
            )
            .environmentObject(settings)
        }
        .onChange(of: scenePhase) { _, phase in
            // "After he comes back" — returning from Settings confirms + verifies.
            if phase == .active && pendingSettingsReturn {
                pendingSettingsReturn = false
                finishActivation()
            }
            // Pick up extension heartbeats / allowlist changes made while
            // the app was in the background.
            if phase == .active {
                protectionCenter.refreshLocalState()
            }
        }
        .task {
            // Lightweight freshness check only (local state + /api/stats).
            // Database downloads run solely from the user-pressed button on
            // the Safari Protection screen.
            await protectionCenter.runLaunchCheckIfNeeded()
        }
        .overlay(alignment: .bottom) {
            if let statusBanner {
                Text(statusBanner)
                    .font(.subheadline).bold()
                    .multilineTextAlignment(.center)
                    .padding(.horizontal, 18).padding(.vertical, 12)
                    .background(.ultraThinMaterial)
                    .clipShape(Capsule())
                    .shadow(radius: 4, y: 2)
                    .padding(.horizontal, 24)
                    .padding(.bottom, 24)
                    .transition(.move(edge: .bottom).combined(with: .opacity))
            }
        }
        .animation(.easeInOut, value: statusBanner)
    }

    // MARK: - Safari protection card

    /// Compact dashboard summary of the Safari Web Extension protection.
    private var safariProtectionCard: some View {
        let visual = protectionCenter.summary.visual
        return HStack(spacing: 12) {
            Image(systemName: "safari.fill")
                .font(.system(size: 26))
                .foregroundStyle(AppColors.primary)
            VStack(alignment: .leading, spacing: 2) {
                Text(L10n.string("safari_protection_title", lang))
                    .font(.headline)
                HStack(spacing: 5) {
                    Image(systemName: visual.icon)
                        .font(.caption)
                        .foregroundStyle(visual.color)
                    Text(L10n.string(visual.titleKey, lang))
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                }
            }
            Spacer()
            if protectionCenter.updateActivity.isBusy {
                ProgressView()
            }
            Image(systemName: "chevron.forward")
                .font(.footnote)
                .foregroundStyle(.secondary)
        }
        .padding(16)
        .background(Color(.secondarySystemBackground).opacity(0.5))
        .clipShape(RoundedRectangle(cornerRadius: 12))
    }

    // MARK: - Activation flow

    /// Called whenever the protection toggle changes.
    private func setProtection(_ on: Bool) {
        if on {
            // Turn on optimistically and present the setup sheet; if the user
            // backs out, the sheet's onDismiss reverts it.
            settings.isProtectionActive = true
            activationConfirmed = false
            showActivation = true
        } else {
            settings.isProtectionActive = false
            showBanner(L10n.string("protection_off_banner", lang))
        }
    }

    /// Opens iOS Settings → Apps → Default Apps (the default-browser picker)
    /// directly, using the official iOS 18.3+ deep link
    /// `app-settings:default-applications`. If that screen isn't available
    /// (e.g. on some simulators), it falls back to the app's own Settings page.
    private func openDefaultBrowserSettings() {
        pendingSettingsReturn = true
        let defaultApps = URL(string: UIApplication.openDefaultApplicationsSettingsURLString)
        let appSettings = URL(string: UIApplication.openSettingsURLString)
        if let defaultApps {
            UIApplication.shared.open(defaultApps) { success in
                if !success, let appSettings {
                    UIApplication.shared.open(appSettings)
                }
            }
        } else if let appSettings {
            UIApplication.shared.open(appSettings)
        }
    }

    /// Confirms protection is on and runs a real check that the pipeline works.
    private func finishActivation() {
        activationConfirmed = true
        settings.isProtectionActive = true
        showActivation = false
        verifyProtection()
    }

    /// Honest "does it work?" check — runs a live link check through the same
    /// pipeline real links use, so the confirmation reflects reality.
    private func verifyProtection() {
        statusBanner = L10n.string("verifying_protection", lang)
        Task {
            let result = await CheckPipeline.check("https://www.google.com")
            if case .error = result {
                showBanner(L10n.string("protection_active_offline", lang))
            } else {
                showBanner(L10n.string("protection_active_banner", lang))
            }
        }
    }

    /// Shows a transient banner that auto-dismisses.
    private func showBanner(_ text: String) {
        statusBanner = text
        Task {
            try? await Task.sleep(nanoseconds: 4_000_000_000)
            if statusBanner == text { statusBanner = nil }
        }
    }
}

struct IdentifiableURL: Identifiable {
    let value: String
    var id: String { value }
}

#Preview {
    ContentView()
}
