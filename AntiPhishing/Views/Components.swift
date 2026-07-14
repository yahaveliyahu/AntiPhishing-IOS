//
//  Components.swift
//  AntiPhishing
//
//  Reusable UI components ported from SecurityShield.kt and
//  DashboardComponents.kt (StatCard, RecentLinkItem).
//

import SwiftUI

// MARK: - SecurityShield (animated "breathing" shield)

struct SecurityShield: View {
    @State private var scale: CGFloat = 1.0

    var body: some View {
        Image(systemName: "shield.lefthalf.filled")
            .resizable()
            .scaledToFit()
            .frame(width: 120, height: 120)
            .foregroundStyle(AppColors.primary)
            .scaleEffect(scale)
            .opacity(0.8 + (scale - 1.0))
            .onAppear {
                withAnimation(.easeInOut(duration: 1.5).repeatForever(autoreverses: true)) {
                    scale = 1.15
                }
            }
    }
}

// MARK: - StatCard

struct StatCard: View {
    let label: String
    let value: String
    let color: Color

    var body: some View {
        VStack(spacing: 4) {
            Text(value)
                .font(.title2).bold()
                .foregroundStyle(color)
            Text(label)
                .font(.caption)
                .foregroundStyle(color.opacity(0.8))
        }
        .frame(maxWidth: .infinity)
        .padding(16)
        .background(color.opacity(0.1))
        .clipShape(RoundedRectangle(cornerRadius: 12))
    }
}

// MARK: - RecentLinkItem

struct RecentLinkItem: View {
    let link: ScannedLink
    let onDelete: () -> Void

    private var shouldShowRed: Bool { link.isSuspicious || link.riskScore >= 80 }
    private var indicatorColor: Color { shouldShowRed ? .red : .green }
    private var indicatorIcon: String { shouldShowRed ? "exclamationmark.triangle.fill" : "checkmark.circle.fill" }

    private var timeString: String {
        let date = Date(timeIntervalSince1970: link.timestamp / 1000)
        let f = DateFormatter()
        f.dateFormat = "HH:mm"
        return f.string(from: date)
    }

    var body: some View {
        HStack(spacing: 16) {
            ZStack {
                Circle()
                    .fill(indicatorColor.opacity(0.12))
                    .frame(width: 40, height: 40)
                Image(systemName: indicatorIcon)
                    .foregroundStyle(indicatorColor)
                    .font(.system(size: 20))
            }

            VStack(alignment: .leading, spacing: 2) {
                Text(link.url)
                    .font(.body).fontWeight(.medium)
                    .lineLimit(1)
                    .truncationMode(.tail)
                Text(timeString)
                    .font(.caption2)
                    .foregroundStyle(.gray)
            }
            .frame(maxWidth: .infinity, alignment: .leading)

            if shouldShowRed {
                Text("\(link.riskScore)%")
                    .font(.callout).bold()
                    .foregroundStyle(.red)
            }

            Button(action: onDelete) {
                Image(systemName: "trash")
                    .foregroundStyle(AppColors.maliciousRed)
                    .font(.system(size: 20))
            }
            .frame(width: 40, height: 40)
        }
        .padding(.vertical, 8)
    }
}
