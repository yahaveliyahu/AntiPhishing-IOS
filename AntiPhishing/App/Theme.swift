//
//  Theme.swift
//  AntiPhishing
//
//  Color palette ported from the Android Material theme (Color.kt).
//

import SwiftUI

enum AppColors {
    // Material light primary (0xFF0061A4)
    static let primary = Color(red: 0x00 / 255, green: 0x61 / 255, blue: 0xA4 / 255)
    static let primaryDark = Color(red: 0x9E / 255, green: 0xCA / 255, blue: 0xFF / 255)

    static let danger = Color.red
    static let safe = Color.green

    // Warning-screen palette (from LinkInterceptorActivity)
    static let maliciousBg = Color(red: 0xFF / 255, green: 0xF7 / 255, blue: 0xF7 / 255)
    static let maliciousCircle = Color(red: 0xFF / 255, green: 0xEB / 255, blue: 0xEE / 255)
    static let maliciousRed = Color(red: 0xC6 / 255, green: 0x28 / 255, blue: 0x28 / 255)
    static let maliciousTitle = Color(red: 0x7F / 255, green: 0x1D / 255, blue: 0x1D / 255)
    static let maliciousSubtitle = Color(red: 0x6B / 255, green: 0x4B / 255, blue: 0x4B / 255)

    static let unknownBg = Color(red: 0xFF / 255, green: 0xFB / 255, blue: 0xF0 / 255)
    static let unknownCircle = Color(red: 0xFF / 255, green: 0xF3 / 255, blue: 0xD6 / 255)
    static let unknownOrange = Color(red: 0xE6 / 255, green: 0x51 / 255, blue: 0x00 / 255)
    static let unknownTitle = Color(red: 0x7A / 255, green: 0x3E / 255, blue: 0x00 / 255)
    static let unknownSubtitle = Color(red: 0x6A / 255, green: 0x54 / 255, blue: 0x36 / 255)

    static let blueButton = Color(red: 0x19 / 255, green: 0x76 / 255, blue: 0xD2 / 255)
    static let monoText = Color(red: 0x42 / 255, green: 0x42 / 255, blue: 0x42 / 255)
    static let cardGrayBg = Color(red: 0xF7 / 255, green: 0xF7 / 255, blue: 0xF7 / 255)
}
