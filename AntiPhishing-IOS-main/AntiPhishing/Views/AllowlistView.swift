//
//  AllowlistView.swift
//  AntiPhishing
//
//  Management screen for domains the user approved via "Continue Anyway" on
//  the Safari warning page. Data lives in the shared allowlist file (see
//  AllowlistStore) so removals here take effect in the extension immediately.
//

import SwiftUI

struct AllowlistView: View {
    @EnvironmentObject var settings: AppSettings

    @State private var entries: [AllowlistEntry] = []
    @State private var confirmClearAll = false

    private var lang: AppLanguage { settings.language }

    var body: some View {
        Group {
            if entries.isEmpty {
                VStack(spacing: 12) {
                    Image(systemName: "checkmark.circle.badge.questionmark")
                        .font(.system(size: 44))
                        .foregroundStyle(.secondary)
                    Text(L10n.string("allowlist_empty", lang))
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
                        .padding(.horizontal, 32)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                List {
                    Section {
                        ForEach(entries) { entry in
                            entryRow(entry)
                        }
                        .onDelete { indexSet in
                            for index in indexSet {
                                AllowlistStore.remove(domain: entries[index].domain)
                            }
                            reload()
                        }
                    } footer: {
                        Text(L10n.string("allowlist_footer", lang))
                    }
                }
            }
        }
        .navigationTitle(L10n.string("allowlist_title", lang))
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                Menu {
                    Button {
                        AllowlistStore.clearExpired()
                        reload()
                    } label: {
                        Label(L10n.string("allowlist_clear_expired", lang), systemImage: "clock.arrow.circlepath")
                    }
                    Button(role: .destructive) {
                        confirmClearAll = true
                    } label: {
                        Label(L10n.string("allowlist_clear_all", lang), systemImage: "trash")
                    }
                } label: {
                    Image(systemName: "ellipsis.circle")
                }
                .disabled(entries.isEmpty)
            }
        }
        .confirmationDialog(L10n.string("allowlist_clear_all_confirm", lang),
                            isPresented: $confirmClearAll,
                            titleVisibility: .visible) {
            Button(L10n.string("allowlist_clear_all", lang), role: .destructive) {
                AllowlistStore.clearAll()
                reload()
            }
        }
        .onAppear(perform: reload)
        .environment(\.layoutDirection, lang == .hebrew ? .rightToLeft : .leftToRight)
    }

    private func entryRow(_ entry: AllowlistEntry) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                Text(entry.domain)
                    .font(.subheadline).bold()
                    .lineLimit(1)
                Spacer()
                if entry.isExpired {
                    Text(L10n.string("allowlist_expired", lang))
                        .font(.caption2).bold()
                        .padding(.horizontal, 8).padding(.vertical, 3)
                        .background(Color.gray.opacity(0.2))
                        .clipShape(Capsule())
                        .foregroundStyle(.secondary)
                }
            }
            Text(L10n.string("allowlist_approved", lang) + " " +
                 entry.approvedAt.formatted(date: .abbreviated, time: .shortened))
                .font(.caption)
                .foregroundStyle(.secondary)
            Text((entry.isExpired
                  ? L10n.string("allowlist_expired_at", lang)
                  : L10n.string("allowlist_expires", lang)) + " " +
                 entry.expiresAt.formatted(.relative(presentation: .named)))
                .font(.caption)
                .foregroundStyle(entry.isExpired ? Color.secondary : Color.orange)
        }
        .padding(.vertical, 2)
    }

    private func reload() {
        entries = AllowlistStore.allEntries()
    }
}
