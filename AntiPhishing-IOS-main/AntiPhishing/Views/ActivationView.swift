//
//  ActivationView.swift
//  AntiPhishing
//
//  Shown when the user turns on the protection toggle. It is the iOS-honest
//  equivalent of Android's "grant the browser role" step: iOS does not let a
//  non-browser app become the system link handler, so instead of promising
//  silent interception, this screen explains how protection actually works on
//  iOS (Share → AntiPhishing, QR, manual paste) and lets the user open Settings
//  and come back. ContentView then verifies the checking pipeline works.
//

import SwiftUI

struct ActivationSetupView: View {
    let onOpenSettings: () -> Void
    let onDone: () -> Void

    @EnvironmentObject var settings: AppSettings
    private var lang: AppLanguage { settings.language }

    var body: some View {
        ScrollView {
            VStack(spacing: 20) {
                SecurityShield()
                    .padding(.top, 24)

                Text(L10n.string("activate_title", lang))
                    .font(.title2).bold()
                    .multilineTextAlignment(.center)

                Text(L10n.string("activate_intro", lang))
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)

                VStack(alignment: .leading, spacing: 14) {
                    stepRow("square.and.arrow.up", L10n.string("activate_step_share", lang))
                    stepRow("qrcode.viewfinder", L10n.string("activate_step_qr", lang))
                    stepRow("checkmark.shield.fill", L10n.string("activate_step_safe", lang))
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(16)
                .background(Color(.secondarySystemBackground).opacity(0.5))
                .clipShape(RoundedRectangle(cornerRadius: 12))

                Text(L10n.string("activate_note", lang))
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)

                Button(action: onDone) {
                    Text(L10n.string("activate_done", lang)).bold()
                        .frame(maxWidth: .infinity).frame(height: 52)
                }
                .background(AppColors.primary)
                .foregroundStyle(.white)
                .clipShape(RoundedRectangle(cornerRadius: 12))

                Button(action: onOpenSettings) {
                    Text(L10n.string("open_settings", lang))
                        .frame(maxWidth: .infinity).frame(height: 48)
                }
                .foregroundStyle(AppColors.primary)
            }
            .padding(24)
        }
        .environment(\.layoutDirection, lang == .hebrew ? .rightToLeft : .leftToRight)
    }

    private func stepRow(_ icon: String, _ text: String) -> some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: icon)
                .foregroundStyle(AppColors.primary)
                .font(.system(size: 18))
                .frame(width: 26)
            Text(text)
                .font(.subheadline)
            Spacer(minLength: 0)
        }
    }
}
