//
//  SafariProtectionView.swift
//  AntiPhishing
//
//  Safari-protection dashboard: protection/database status, the
//  "Update Protection Database" action, the enable-the-extension guide, and
//  entry to the approved-domains (allowlist) screen.
//
//  Honesty rules baked into this screen:
//   • iOS provides no API to enable a Safari extension or query its state —
//     the user must enable it in Settings, so we only *guide* them there and
//     detect activity through the extension's heartbeat.
//   • The extension protects Safari only; if another browser is the default,
//     links open unprotected. We say so instead of overpromising.
//

import SwiftUI
import UIKit

/// Icon/color/copy for each protection state — shared by the dashboard card
/// in ContentView and the full status screen below.
extension ProtectionCenter.Summary {
    var visual: (icon: String, color: Color, titleKey: String, detailKey: String) {
        switch self {
        case .storageError:
            return ("exclamationmark.octagon.fill", .red, "sp_status_storage_error", "sp_status_storage_error_detail")
        case .masterOff:
            return ("shield.slash.fill", .red, "protection_disabled", "sp_master_off_detail")
        case .updating:
            return ("arrow.triangle.2.circlepath", AppColors.primary, "sp_status_updating", "sp_status_updating_detail")
        case .notReady:
            return ("shield.slash.fill", .orange, "sp_status_no_db", "sp_status_no_db_detail")
        case .notReadyOffline:
            return ("wifi.slash", .red, "sp_status_no_db_offline", "sp_status_no_db_offline_detail")
        case .active:
            return ("checkmark.shield.fill", .green, "sp_status_active", "sp_status_active_detail")
        case .activeUpdateAvailable:
            return ("shield.lefthalf.filled", AppColors.primary, "sp_status_update_available", "sp_status_update_available_detail")
        case .activeStale:
            return ("clock.badge.exclamationmark", .orange, "sp_status_active_stale", "sp_status_active_stale_detail")
        case .activeOffline:
            return ("wifi.slash", .orange, "sp_status_offline", "sp_status_offline_detail")
        case .updateFailedDatabaseActive:
            return ("exclamationmark.shield.fill", .orange, "sp_status_update_failed", "sp_status_update_failed_detail")
        }
    }
}

struct SafariProtectionView: View {
    @ObservedObject private var center = ProtectionCenter.shared
    @EnvironmentObject var settings: AppSettings

    @State private var showExtensionGuide = false
    /// Mirrors SharedStore.isCheckToastEnabled (shared defaults have no
    /// SwiftUI binding of their own).
    @State private var showCheckToast = SharedStore.isCheckToastEnabled
    /// Mirrors SharedStore.recentVisits — written by the extension process,
    /// so this view re-reads it explicitly rather than observing it.
    @State private var recentVisits: [SharedStore.RecentVisit] = []
    @Environment(\.scenePhase) private var scenePhase

    private var lang: AppLanguage { settings.language }

    var body: some View {
        ScrollView {
            VStack(spacing: 16) {
                statusCard
                extensionCard
                recentVisitsCard
                databaseCard
                allowlistCard
                safariOnlyNote
            }
            .padding(20)
        }
        .refreshable {
            // Pull-to-refresh: re-read the extension heartbeat (did the user
            // just enable it in Settings?) and the server freshness state.
            await center.refreshStatus()
            reloadRecentVisits()
        }
        .navigationTitle(L10n.string("safari_protection_title", lang))
        .navigationBarTitleDisplayMode(.inline)
        .sheet(isPresented: $showExtensionGuide) {
            SafariExtensionGuideView()
                .environmentObject(settings)
        }
        .onAppear {
            center.refreshLocalState()
            showCheckToast = SharedStore.isCheckToastEnabled
            reloadRecentVisits()
        }
        .onChange(of: showCheckToast) { _, on in
            SharedStore.isCheckToastEnabled = on
        }
        .onChange(of: scenePhase) { _, phase in
            // Returning from Settings/Safari — the heartbeat may be fresh now.
            if phase == .active {
                center.refreshLocalState()
                reloadRecentVisits()
            }
        }
        .environment(\.layoutDirection, lang == .hebrew ? .rightToLeft : .leftToRight)
    }

    // MARK: Status card

    private var statusCard: some View {
        let visual = center.summary.visual
        return VStack(spacing: 10) {
            Image(systemName: visual.icon)
                .font(.system(size: 44))
                .foregroundStyle(visual.color)
            Text(L10n.string(visual.titleKey, lang))
                .font(.headline)
                .multilineTextAlignment(.center)
            if case .updating(let phaseKey, let detail, let fraction) = center.updateActivity {
                updateProgress(phaseKey: phaseKey, detail: detail, fraction: fraction)
            } else {
                Text(L10n.string(visual.detailKey, lang))
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
            }
            if let outcomeKey = center.lastUpdateOutcomeKey {
                Text(L10n.string(outcomeKey, lang))
                    .font(.footnote).bold()
                    .foregroundStyle(outcomeKey.hasPrefix("err_") ? .red : AppColors.primary)
                    .multilineTextAlignment(.center)
                    .padding(.top, 2)
            }
        }
        .frame(maxWidth: .infinity)
        .padding(20)
        .background(visual.color.opacity(0.08))
        .clipShape(RoundedRectangle(cornerRadius: 16))
    }

    /// Live update progress: percent bar, phase + detail, and an
    /// elapsed / estimated-remaining line that ticks every second.
    private func updateProgress(phaseKey: String, detail: String?, fraction: Double?) -> some View {
        VStack(spacing: 6) {
            if let fraction {
                ProgressView(value: fraction)
                    .progressViewStyle(.linear)
                    .tint(AppColors.primary)
                HStack {
                    Text("\(Int(fraction * 100))%")
                        .font(.footnote).bold()
                        .foregroundStyle(AppColors.primary)
                    Spacer()
                    if let started = center.updateStartedAt {
                        TimelineView(.periodic(from: .now, by: 1)) { context in
                            Text(timingLine(started: started, fraction: fraction, now: context.date))
                                .font(.footnote)
                                .foregroundStyle(.secondary)
                                .monospacedDigit()
                        }
                    }
                }
            } else {
                ProgressView().padding(.top, 2)
            }
            Text(L10n.string(phaseKey, lang) + (detail.map { " · \($0)" } ?? ""))
                .font(.footnote)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
        }
        .padding(.top, 4)
    }

    /// "0:42 · ~1:10 left" — the remaining estimate appears once there is
    /// enough progress for the extrapolation to mean anything.
    private func timingLine(started: Date, fraction: Double, now: Date) -> String {
        let elapsed = max(now.timeIntervalSince(started), 0)
        var line = Self.mmss(elapsed)
        if fraction > 0.05, fraction < 1 {
            let remaining = elapsed / fraction * (1 - fraction)
            line += " · ~" + Self.mmss(remaining) + " " + L10n.string("sp_progress_left", lang)
        }
        return line
    }

    static func mmss(_ interval: TimeInterval) -> String {
        let seconds = Int(interval.rounded())
        return String(format: "%d:%02d", seconds / 60, seconds % 60)
    }

    // MARK: Extension card

    private var extensionCard: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 10) {
                Image(systemName: center.extensionDetected ? "puzzlepiece.extension.fill" : "puzzlepiece.extension")
                    .foregroundStyle(center.extensionDetected ? .green : .orange)
                VStack(alignment: .leading, spacing: 2) {
                    Text(L10n.string(center.extensionDetected ? "sp_ext_enabled" : "sp_ext_not_detected", lang))
                        .font(.subheadline).bold()
                    if let seen = center.extensionLastSeen, center.extensionDetected {
                        Text(L10n.string("sp_ext_last_seen", lang) + " " + seen.formatted(.relative(presentation: .named)))
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    } else {
                        Text(L10n.string("sp_ext_not_detected_detail", lang))
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
                Spacer()
            }
            Button {
                showExtensionGuide = true
            } label: {
                Text(L10n.string("sp_ext_guide_button", lang))
                    .font(.subheadline).bold()
                    .frame(maxWidth: .infinity)
                    .frame(height: 40)
            }
            .background(AppColors.primary.opacity(0.12))
            .foregroundStyle(AppColors.primary)
            .clipShape(RoundedRectangle(cornerRadius: 10))

            Divider()

            // Visible proof the protection runs: a small toast in Safari on
            // the first check of every domain (see SharedStore/content.js).
            Toggle(isOn: $showCheckToast) {
                VStack(alignment: .leading, spacing: 2) {
                    Text(L10n.string("sp_toast_toggle", lang))
                        .font(.subheadline).bold()
                    Text(L10n.string("sp_toast_toggle_detail", lang))
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            .tint(AppColors.primary)
        }
        .padding(16)
        .background(Color(.secondarySystemBackground).opacity(0.5))
        .clipShape(RoundedRectangle(cornerRadius: 12))
    }

    // MARK: Recent visits card

    private func reloadRecentVisits() {
        recentVisits = Array(SharedStore.recentVisits.prefix(5))
    }

    /// Icon/color/label for a recorded verdict — mirrors the verdict strings
    /// the native handler writes in SharedStore.recordRecentVisit.
    private func visitVisual(_ verdict: String) -> (icon: String, color: Color, labelKey: String) {
        switch verdict {
        case "safe": return ("checkmark.shield.fill", .green, "sp_visit_verdict_safe")
        case "malicious": return ("exclamationmark.shield.fill", .red, "sp_visit_verdict_malicious")
        case "allowlisted": return ("checkmark.circle.fill", AppColors.primary, "sp_visit_verdict_allowlisted")
        case "off": return ("shield.slash", .secondary, "sp_visit_verdict_off")
        default: return ("shield.slash.fill", .orange, "sp_visit_verdict_unprotected")
        }
    }

    private var recentVisitsCard: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text(L10n.string("sp_recent_visits_title", lang))
                .font(.subheadline).bold()

            if recentVisits.isEmpty {
                Text(L10n.string("sp_recent_visits_empty", lang))
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            } else {
                ForEach(recentVisits, id: \.host) { visit in
                    let visual = visitVisual(visit.verdict)
                    HStack(spacing: 10) {
                        Image(systemName: visual.icon)
                            .foregroundStyle(visual.color)
                            .frame(width: 20)
                        Text(visit.host)
                            .font(.footnote)
                            .lineLimit(1)
                            .truncationMode(.middle)
                        Spacer()
                        Text(L10n.string(visual.labelKey, lang))
                            .font(.caption2).bold()
                            .foregroundStyle(visual.color)
                        Text(Date(timeIntervalSince1970: visit.timestamp).formatted(.relative(presentation: .named)))
                            .font(.caption2)
                            .foregroundStyle(.secondary)
                    }
                    if visit.host != recentVisits.last?.host {
                        Divider()
                    }
                }
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(16)
        .background(Color(.secondarySystemBackground).opacity(0.5))
        .clipShape(RoundedRectangle(cornerRadius: 12))
    }

    // MARK: Database card

    private var databaseCard: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(L10n.string("sp_db_section", lang))
                .font(.subheadline).bold()

            if let metadata = center.metadata {
                infoRow("number", L10n.string("sp_db_version", lang), "\(metadata.version)")
                infoRow("calendar", L10n.string("sp_db_updated", lang),
                        metadata.updatedAt.formatted(date: .abbreviated, time: .shortened))
                infoRow("shield.checkered", L10n.string("sp_db_domains", lang),
                        (center.localDomainCount ?? metadata.domainCount).formatted())
                if let serverCount = center.serverStats?.maliciousDomains ?? metadata.serverMaliciousDomains {
                    infoRow("server.rack", L10n.string("sp_db_server_domains", lang), serverCount.formatted())
                }
                if let checked = metadata.lastCheckedAt {
                    infoRow("clock", L10n.string("sp_db_checked", lang),
                            checked.formatted(.relative(presentation: .named)))
                }
                if center.isCheckingFreshness {
                    HStack(spacing: 6) {
                        ProgressView().controlSize(.mini)
                        Text(L10n.string("sp_checking_freshness", lang))
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    .padding(.top, 2)
                }
                if let duration = metadata.lastUpdateDuration {
                    infoRow("stopwatch", L10n.string("sp_db_duration", lang),
                            Self.mmss(duration))
                }
                if let issues = metadata.lastFeedIssues, !issues.isEmpty {
                    feedIssuesBox(issues)
                }
            } else {
                Text(L10n.string("sp_db_none", lang))
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }

            Button {
                Task { await center.startUpdate(force: center.metadata != nil) }
            } label: {
                HStack {
                    if center.updateActivity.isBusy {
                        ProgressView().tint(.white)
                    } else {
                        Image(systemName: "arrow.down.circle.fill")
                    }
                    Text(L10n.string(center.metadata == nil ? "sp_download_button" : "sp_update_button", lang))
                        .bold()
                }
                .frame(maxWidth: .infinity)
                .frame(height: 48)
            }
            .background(center.updateActivity.isBusy ? Color.gray : AppColors.primary)
            .foregroundStyle(.white)
            .clipShape(RoundedRectangle(cornerRadius: 12))
            .disabled(center.updateActivity.isBusy)
            .padding(.top, 6)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(16)
        .background(Color(.secondarySystemBackground).opacity(0.5))
        .clipShape(RoundedRectangle(cornerRadius: 12))
    }

    /// Per-feed problems from the last update (non-fatal — the database
    /// still built). Raw technical reasons on purpose: this is the
    /// diagnostics the user asked "are there any errors?" about.
    private func feedIssuesBox(_ issues: [String: String]) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Label(L10n.string("sp_feed_issues", lang), systemImage: "exclamationmark.triangle.fill")
                .font(.caption).bold()
                .foregroundStyle(.orange)
            ForEach(issues.sorted(by: { $0.key < $1.key }), id: \.key) { name, reason in
                Text("\(name.replacingOccurrences(of: "_", with: " ")): \(reason)")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(10)
        .background(Color.orange.opacity(0.08))
        .clipShape(RoundedRectangle(cornerRadius: 8))
        .padding(.top, 4)
    }

    private func infoRow(_ icon: String, _ label: String, _ value: String) -> some View {
        HStack(spacing: 8) {
            Image(systemName: icon)
                .font(.system(size: 13))
                .foregroundStyle(AppColors.primary)
                .frame(width: 20)
            Text(label)
                .font(.footnote)
                .foregroundStyle(.secondary)
            Spacer()
            Text(value)
                .font(.footnote).bold()
        }
    }

    // MARK: Allowlist + note

    private var allowlistCard: some View {
        NavigationLink {
            AllowlistView().environmentObject(settings)
        } label: {
            HStack {
                Image(systemName: "checkmark.circle.badge.questionmark")
                    .foregroundStyle(AppColors.primary)
                Text(L10n.string("allowlist_title", lang))
                    .font(.subheadline).bold()
                Spacer()
                Image(systemName: "chevron.forward")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }
            .padding(16)
            .background(Color(.secondarySystemBackground).opacity(0.5))
            .clipShape(RoundedRectangle(cornerRadius: 12))
        }
        .buttonStyle(.plain)
    }

    private var safariOnlyNote: some View {
        Text(L10n.string("sp_note_safari_only", lang))
            .font(.footnote)
            .foregroundStyle(.secondary)
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.horizontal, 4)
    }
}

// MARK: - Enable-extension guide

/// Step-by-step sheet guiding the user to Settings ▸ Apps ▸ Safari ▸
/// Extensions. iOS deliberately keeps this a manual user action, so the most
/// an app may do is open the Settings app.
struct SafariExtensionGuideView: View {
    @EnvironmentObject var settings: AppSettings
    @Environment(\.dismiss) private var dismiss

    private var lang: AppLanguage { settings.language }

    var body: some View {
        ScrollView {
            VStack(spacing: 20) {
                Image(systemName: "safari.fill")
                    .font(.system(size: 52))
                    .foregroundStyle(AppColors.primary)
                    .padding(.top, 24)

                Text(L10n.string("ext_guide_title", lang))
                    .font(.title2).bold()
                    .multilineTextAlignment(.center)

                Text(L10n.string("ext_guide_intro", lang))
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)

                VStack(alignment: .leading, spacing: 14) {
                    guideStep(1, L10n.string("ext_guide_step1", lang))
                    guideStep(2, L10n.string("ext_guide_step2", lang))
                    guideStep(3, L10n.string("ext_guide_step3", lang))
                    guideStep(4, L10n.string("ext_guide_step4", lang))
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(16)
                .background(Color(.secondarySystemBackground).opacity(0.5))
                .clipShape(RoundedRectangle(cornerRadius: 12))

                Text(L10n.string("ext_guide_note", lang))
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)

                Button {
                    // Best deep link iOS offers: the app's own Settings page
                    // (Settings ▸ Apps ▸ AntiPhishing), one tap from Safari's
                    // extension list. There is no public URL directly into
                    // Safari's extension settings.
                    if let url = URL(string: UIApplication.openSettingsURLString) {
                        UIApplication.shared.open(url)
                    }
                } label: {
                    Text(L10n.string("ext_guide_open_settings", lang)).bold()
                        .frame(maxWidth: .infinity).frame(height: 52)
                }
                .background(AppColors.primary)
                .foregroundStyle(.white)
                .clipShape(RoundedRectangle(cornerRadius: 12))

                Button(L10n.string("close", lang)) { dismiss() }
                    .foregroundStyle(AppColors.primary)
            }
            .padding(24)
        }
        .environment(\.layoutDirection, lang == .hebrew ? .rightToLeft : .leftToRight)
    }

    private func guideStep(_ number: Int, _ text: String) -> some View {
        HStack(alignment: .top, spacing: 12) {
            Text("\(number)")
                .font(.subheadline).bold()
                .frame(width: 26, height: 26)
                .background(AppColors.primary.opacity(0.15))
                .clipShape(Circle())
                .foregroundStyle(AppColors.primary)
            Text(text)
                .font(.subheadline)
            Spacer(minLength: 0)
        }
    }
}
