// Theme.qml
//
// Kitsune - design tokens. Every color in the interface comes from
// here, so the dark, light and system palettes cover every screen.
//
// SPDX-License-Identifier: GPL-2.0-or-later

pragma Singleton
import QtQuick

QtObject {
    id: theme

    // 0 = system colors, 1 = light, 2 = dark
    readonly property int mode: kitsuneSettings.themeMode
    readonly property bool system: mode === 0
    readonly property bool dark: mode === 2 || (mode === 0 && kitsuneSettings.systemPrefersDark)

    property SystemPalette sys: SystemPalette { colorGroup: SystemPalette.Active }

    // Dark: deep navy with a cyan accent, after the design mockups.
    readonly property var darkPalette: ({
        window:        "#070d1a",
        surface:       "#0c1628",
        surfaceRaised: "#112038",
        surfaceHover:  "#16294a",
        border:        "#1d3557",
        borderStrong:  "#2a4a75",
        text:          "#e6f1ff",
        textMuted:     "#8aa0bf",
        textFaint:     "#5b7092",
        accent:        "#22d3ee",
        accentStrong:  "#0ea5c6",
        accentSoft:    "#0d3a4d",
        onAccent:      "#03222b",
        selection:     "#123a57",
        rowAlt:        "#0a1424",
        success:       "#34d399",
        warning:       "#fbbf24",
        danger:        "#f87171"
    })

    readonly property var lightPalette: ({
        window:        "#f3f6fb",
        surface:       "#ffffff",
        surfaceRaised: "#ffffff",
        surfaceHover:  "#eaf3fb",
        border:        "#d7e0ec",
        borderStrong:  "#b6c5d9",
        text:          "#0d1b2e",
        textMuted:     "#4a5d78",
        textFaint:     "#7d8ea6",
        accent:        "#0891b2",
        accentStrong:  "#0e7490",
        accentSoft:    "#dff4f9",
        onAccent:      "#ffffff",
        selection:     "#cdeefa",
        rowAlt:        "#f7f9fc",
        success:       "#059669",
        warning:       "#b45309",
        danger:        "#dc2626"
    })

    // System: the operating system's own colors and accent.
    readonly property var systemPalette: ({
        window:        sys.window,
        surface:       sys.base,
        surfaceRaised: sys.base,
        surfaceHover:  Qt.tint(sys.base, Qt.rgba(sys.highlight.r, sys.highlight.g, sys.highlight.b, 0.10)),
        border:        Qt.tint(sys.window, Qt.rgba(sys.windowText.r, sys.windowText.g, sys.windowText.b, 0.15)),
        borderStrong:  Qt.tint(sys.window, Qt.rgba(sys.windowText.r, sys.windowText.g, sys.windowText.b, 0.30)),
        text:          sys.windowText,
        textMuted:     Qt.tint(sys.windowText, Qt.rgba(sys.window.r, sys.window.g, sys.window.b, 0.35)),
        textFaint:     Qt.tint(sys.windowText, Qt.rgba(sys.window.r, sys.window.g, sys.window.b, 0.55)),
        accent:        sys.highlight,
        accentStrong:  sys.highlight,
        accentSoft:    Qt.tint(sys.base, Qt.rgba(sys.highlight.r, sys.highlight.g, sys.highlight.b, 0.18)),
        onAccent:      sys.highlightedText,
        selection:     Qt.tint(sys.base, Qt.rgba(sys.highlight.r, sys.highlight.g, sys.highlight.b, 0.28)),
        // Not sys.alternateBase: some platforms (Windows) make it a strong color.
        rowAlt:        Qt.tint(sys.base, Qt.rgba(sys.windowText.r, sys.windowText.g, sys.windowText.b, 0.04)),
        success:       dark ? "#34d399" : "#059669",
        warning:       dark ? "#fbbf24" : "#b45309",
        danger:        dark ? "#f87171" : "#dc2626"
    })

    readonly property var p: system ? systemPalette : (dark ? darkPalette : lightPalette)

    readonly property color window:        p.window
    readonly property color surface:       p.surface
    readonly property color surfaceRaised: p.surfaceRaised
    readonly property color surfaceHover:  p.surfaceHover
    readonly property color border:        p.border
    readonly property color borderStrong:  p.borderStrong
    readonly property color text:          p.text
    readonly property color textMuted:     p.textMuted
    readonly property color textFaint:     p.textFaint
    readonly property color accent:        p.accent
    readonly property color accentStrong:  p.accentStrong
    readonly property color accentSoft:    p.accentSoft
    readonly property color onAccent:      p.onAccent
    readonly property color selection:     p.selection
    readonly property color rowAlt:        p.rowAlt
    readonly property color success:       p.success
    readonly property color warning:       p.warning
    readonly property color danger:        p.danger

    // Glow is a dark-theme flourish; the other palettes stay flat.
    readonly property bool glow: dark && !system

    // Typography
    readonly property string fontFamily: Qt.platform.os === "windows" ? "Segoe UI Variable Text"
                                        : Qt.platform.os === "osx" ? "SF Pro Text" : "Inter"
    readonly property string monoFamily: Qt.platform.os === "windows" ? "Cascadia Mono"
                                        : Qt.platform.os === "osx" ? "SF Mono" : "JetBrains Mono"
    readonly property int fontSmall: 12
    readonly property int fontBody: 13
    readonly property int fontLarge: 15
    readonly property int fontTitle: 20

    // Shape and spacing
    readonly property int radius: 10
    readonly property int radiusSmall: 6
    readonly property int gap: 12
    readonly property int rowHeight: 28

    // One hue per protocol family, tuned per theme.
    function protocolColor(name) {
        const n = (name || "").toUpperCase()
        const darkSet = dark || (system && kitsuneSettings.systemPrefersDark)
        if (n.startsWith("TLS") || n.startsWith("SSL") || n === "QUIC")
            return darkSet ? "#22d3ee" : "#0e7490"
        if (n.startsWith("HTTP"))
            return darkSet ? "#4ade80" : "#15803d"
        if (n === "TCP")
            return darkSet ? "#60a5fa" : "#1d4ed8"
        if (n === "UDP")
            return darkSet ? "#a78bfa" : "#6d28d9"
        if (n.startsWith("DNS") || n === "MDNS" || n === "LLMNR" || n === "NBNS")
            return darkSet ? "#2dd4bf" : "#0f766e"
        if (n.startsWith("ICMP"))
            return darkSet ? "#a3e635" : "#4d7c0f"
        if (n === "ARP")
            return darkSet ? "#fbbf24" : "#b45309"
        if (n.startsWith("DHCP") || n === "BOOTP")
            return darkSet ? "#f472b6" : "#be185d"
        if (n === "SSH")
            return darkSet ? "#fb923c" : "#c2410c"
        if (n.startsWith("SMB") || n === "NFS")
            return darkSet ? "#f87171" : "#b91c1c"
        return textMuted
    }
}
