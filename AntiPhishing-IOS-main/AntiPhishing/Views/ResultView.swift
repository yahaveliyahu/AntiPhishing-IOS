//
//  ResultView.swift
//  AntiPhishing
//
//  Port of ResultScreen + CheckingScreen from LinkInterceptorActivity.kt.
//   ✅ Whitelisted → auto-proceeds, brief safe message
//   🚨 Malicious   → blocks, shows warning + explanation + source
//   🔍 Unknown     → "needs review", user can proceed
//   ⚠️ Error       → shows error, user can proceed or go back
//

import SwiftUI

struct CheckingView: View {
    let url: String
    var isQr: Bool = false
    @EnvironmentObject var settings: AppSettings

    var body: some View {
        VStack(spacing: 24) {
            ProgressView()
                .scaleEffect(1.8)
                .padding(.bottom, 8)
            Text("🔍 " + L10n.string(isQr ? "checking_qr" : "checking_link", settings.language))
                .font(.title3).bold()
                .multilineTextAlignment(.center)
            Text(truncate(url, 60))
                .font(.caption)
                .foregroundStyle(.gray)
                .multilineTextAlignment(.center)
                .monospaced()
        }
        .padding(32)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

struct ResultView: View {
    let url: String
    let result: CheckResult
    var isQr: Bool = false
    let onProceed: () -> Void
    let onGoBack: () -> Void

    @EnvironmentObject var settings: AppSettings
    private var lang: AppLanguage { settings.language }

    var body: some View {
        Group {
            switch result {
            case .whitelisted:
                CheckingView(url: url, isQr: isQr)
                    .onAppear { onProceed() }
            case .malicious(let explanation, let source, _, _):
                maliciousView(explanation: explanation, source: source)
            case .unknown(let explanation):
                unknownView(explanation: explanation)
            case .error(let message):
                errorView(message: message)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    // MARK: Malicious

    private func maliciousView(explanation: String, source: String?) -> some View {
        ScrollView {
            VStack(spacing: 0) {
                ZStack {
                    Circle().fill(AppColors.maliciousCircle).frame(width: 92, height: 92)
                    Text("!").font(.system(size: 46, weight: .bold)).foregroundStyle(AppColors.maliciousRed)
                }
                .padding(.bottom, 18)

                Text(L10n.string("dangerous_blocked", lang))
                    .font(.system(size: 26, weight: .bold))
                    .foregroundStyle(AppColors.maliciousTitle)
                    .multilineTextAlignment(.center)
                    .padding(.bottom, 8)

                Text(L10n.string("dangerous_subtitle", lang))
                    .font(.system(size: 15))
                    .foregroundStyle(AppColors.maliciousSubtitle)
                    .multilineTextAlignment(.center)
                    .padding(.bottom, 22)

                detailCard(
                    badgeLabel: L10n.string("risk_level", lang),
                    badgeValue: L10n.string("high_risk", lang),
                    badgeBg: AppColors.maliciousCircle,
                    badgeFg: AppColors.maliciousRed,
                    explanation: explanation,
                    source: source
                )
                .padding(.bottom, 24)

                Button(action: onGoBack) {
                    Text(L10n.string("go_back", lang)).bold()
                        .frame(maxWidth: .infinity).frame(height: 54)
                }
                .background(AppColors.blueButton).foregroundStyle(.white)
                .clipShape(RoundedRectangle(cornerRadius: 12))
                .padding(.bottom, 10)

                Button(action: onProceed) {
                    Text(L10n.string("open_anyway", lang)).bold()
                        .frame(maxWidth: .infinity).frame(height: 50)
                }
                .foregroundStyle(AppColors.maliciousRed)
                .overlay(RoundedRectangle(cornerRadius: 12).stroke(AppColors.maliciousRed))
            }
            .padding(24)
        }
        .background(AppColors.maliciousBg)
    }

    // MARK: Unknown

    private func unknownView(explanation: String) -> some View {
        ScrollView {
            VStack(spacing: 0) {
                ZStack {
                    Circle().fill(AppColors.unknownCircle).frame(width: 92, height: 92)
                    Text("?").font(.system(size: 46, weight: .bold)).foregroundStyle(AppColors.unknownOrange)
                }
                .padding(.bottom, 18)

                Text(L10n.string("link_needs_review", lang))
                    .font(.system(size: 26, weight: .bold))
                    .foregroundStyle(AppColors.unknownTitle)
                    .multilineTextAlignment(.center)
                    .padding(.bottom, 8)

                Text(L10n.string("review_subtitle", lang))
                    .font(.system(size: 15))
                    .foregroundStyle(AppColors.unknownSubtitle)
                    .multilineTextAlignment(.center)
                    .padding(.bottom, 22)

                detailCard(
                    badgeLabel: L10n.string("status", lang),
                    badgeValue: L10n.string("unknown", lang),
                    badgeBg: AppColors.unknownCircle,
                    badgeFg: AppColors.unknownOrange,
                    explanation: explanation,
                    source: nil
                )
                .padding(.bottom, 24)

                Button(action: onGoBack) {
                    Text(L10n.string("go_back", lang)).bold()
                        .frame(maxWidth: .infinity).frame(height: 54)
                }
                .background(AppColors.blueButton).foregroundStyle(.white)
                .clipShape(RoundedRectangle(cornerRadius: 12))
                .padding(.bottom, 10)

                Button(action: onProceed) {
                    Text(L10n.string("open_link", lang)).bold()
                        .frame(maxWidth: .infinity).frame(height: 50)
                }
                .foregroundStyle(AppColors.unknownOrange)
                .overlay(RoundedRectangle(cornerRadius: 12).stroke(AppColors.unknownOrange))
            }
            .padding(24)
        }
        .background(AppColors.unknownBg)
    }

    // MARK: Error

    private func errorView(message: String) -> some View {
        VStack(spacing: 16) {
            Text("⚠️").font(.system(size: 64))
            Text(L10n.string("could_not_check", lang))
                .font(.system(size: 22, weight: .bold))
                .foregroundStyle(AppColors.unknownOrange)
                .multilineTextAlignment(.center)

            VStack(alignment: .leading, spacing: 8) {
                Text(L10n.string("server_unreachable", lang)).font(.system(size: 15))
                Text(message).font(.caption).foregroundStyle(.gray)
            }
            .padding(16)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Color(.secondarySystemBackground))
            .clipShape(RoundedRectangle(cornerRadius: 12))

            Button(action: onProceed) {
                Text(L10n.string("open_anyway", lang))
                    .frame(maxWidth: .infinity).frame(height: 52)
            }
            .buttonStyle(.borderedProminent)

            Button(action: onGoBack) {
                Text(L10n.string("go_back", lang)).foregroundStyle(.gray)
                    .frame(maxWidth: .infinity)
            }
        }
        .padding(24)
    }

    // MARK: Shared detail card

    private func detailCard(badgeLabel: String, badgeValue: String, badgeBg: Color, badgeFg: Color, explanation: String, source: String?) -> some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                Text(badgeLabel).font(.system(size: 13)).foregroundStyle(.gray).fontWeight(.medium)
                Spacer()
                Text(badgeValue)
                    .font(.system(size: 12, weight: .bold))
                    .foregroundStyle(badgeFg)
                    .padding(.horizontal, 10).padding(.vertical, 5)
                    .background(badgeBg)
                    .clipShape(RoundedRectangle(cornerRadius: 6))
            }
            .padding(.bottom, 14)

            Text(truncate(url, 90))
                .font(.system(size: 12)).monospaced()
                .foregroundStyle(AppColors.monoText)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(12)
                .background(AppColors.cardGrayBg)
                .clipShape(RoundedRectangle(cornerRadius: 6))
                .padding(.bottom, 14)

            Text(explanation)
                .font(.system(size: 15))
                .foregroundStyle(Color(red: 0.2, green: 0.2, blue: 0.2))
                .frame(maxWidth: .infinity, alignment: .leading)

            if let source {
                Text("\(L10n.string("source", lang)): \(source)")
                    .font(.system(size: 12)).foregroundStyle(.gray)
                    .padding(.horizontal, 10).padding(.vertical, 6)
                    .background(Color(.secondarySystemBackground))
                    .clipShape(RoundedRectangle(cornerRadius: 6))
                    .padding(.top, 10)
            }
        }
        .padding(18)
        .background(Color(.systemBackground))
        .clipShape(RoundedRectangle(cornerRadius: 12))
        .shadow(radius: 3, y: 1)
    }
}

func truncate(_ s: String, _ n: Int) -> String {
    s.count > n ? String(s.prefix(n)) + "..." : s
}
