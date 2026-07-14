//
//  URLOpener.swift
//  AntiPhishing  (main app target ONLY — do not add to the Share Extension)
//
//  Opens a verified-safe / user-confirmed link. Kept out of the extension
//  target because UIApplication.shared is unavailable inside app extensions.
//

import UIKit

enum URLOpener {
    static func open(_ url: String) {
        guard let u = URL(string: url) else { return }
        UIApplication.shared.open(u)
    }
}
