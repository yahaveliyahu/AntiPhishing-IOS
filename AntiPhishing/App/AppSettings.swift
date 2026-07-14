//
//  AppSettings.swift
//  AntiPhishing
//
//  Port of the SharedPreferences ("AntiPhishingPrefs") + language toggle.
//  Stored in the shared App Group so the Share Extension sees the same state.
//

import Foundation
import Combine

enum AppLanguage: String, CaseIterable {
    case english = "en"
    case hebrew = "he"
}

final class AppSettings: ObservableObject {

    static let shared = AppSettings()

    private var defaults: UserDefaults {
        UserDefaults(suiteName: HistoryStore.appGroup) ?? .standard
    }

    @Published var isProtectionActive: Bool {
        didSet { defaults.set(isProtectionActive, forKey: "is_active") }
    }

    /// "Open in" preference. On iOS, third-party apps cannot be set as the
    /// system default browser handler, so a safe link opens in Safari (or the
    /// in-app browser). This mirrors the Android "target_browser" selector.
    @Published var openInSafari: Bool {
        didSet { defaults.set(openInSafari, forKey: "open_in_safari") }
    }

    @Published var language: AppLanguage {
        didSet {
            defaults.set(language.rawValue, forKey: "app_language")
            applyLanguage()
        }
    }

    private init() {
        let d = UserDefaults(suiteName: HistoryStore.appGroup) ?? .standard
        self.isProtectionActive = d.bool(forKey: "is_active")
        self.openInSafari = d.object(forKey: "open_in_safari") as? Bool ?? true
        let langRaw = d.string(forKey: "app_language")
            ?? (Locale.preferredLanguages.first?.hasPrefix("he") == true ? "he" : "en")
        self.language = AppLanguage(rawValue: langRaw) ?? .english
    }

    func toggleLanguage() {
        language = (language == .hebrew) ? .english : .hebrew
    }

    private func applyLanguage() {
        // Persisted; views read `language` reactively via L10n.
    }
}
