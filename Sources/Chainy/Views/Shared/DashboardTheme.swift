// DashboardTheme.swift
//
// The color palette behind every dashboard-shell view (RootView,
// OverviewView, ChainBuilderView, LogsView, NodesView, SettingsView).
// Fixed hex values rather than dynamic system/vibrancy colors -- a Linear/
// Raycast-style shell reads as flat, high-contrast surfaces (solid white
// cards on a light gray page) rather than the semi-transparent grays macOS's
// own vibrancy materials produce, so this palette is deliberately opaque
// end to end: no `Color.primary.opacity(...)` washes, no `Material`. Views
// read colors through `@Environment(\.dashboardPalette)` rather than
// hardcoding them, so this file is still the single place to retheme the
// app.
import SwiftUI
import AppKit

/// Scales a byte count to whichever unit (B/KB/MB/GB) keeps the number
/// short -- shared by Overview's live rate/cumulative total and the
/// Connections panel's per-connection byte counts, so every byte figure in
/// the app speaks the same unit family instead of each screen rolling its
/// own rounding.
func scaledByteUnit(_ bytes: Double) -> (value: String, unit: String) {
    let gb = 1024.0 * 1024.0 * 1024.0
    let mb = 1024.0 * 1024.0
    let kb = 1024.0
    switch bytes {
    case gb...: return (String(format: "%.2f", bytes / gb), "GB")
    case mb...: return (String(format: "%.1f", bytes / mb), "MB")
    case kb...: return (String(format: "%.1f", bytes / kb), "KB")
    default: return (String(format: "%.0f", bytes), "B")
    }
}

struct DashboardPalette {
    let bg: Color
    let bgSidebar: Color
    let bgPanel: Color
    let bgElevated: Color
    let bgHover: Color
    let border: Color
    let borderSoft: Color
    let text: Color
    let textDim: Color
    let textFaint: Color
    let accent: Color
    let accentDim: Color
    let accentSecondary: Color
    let accentSecondaryDim: Color
    let green: Color
    let greenDim: Color
    let amber: Color
    let amberDim: Color
    let red: Color
    let redDim: Color
}

enum DashboardTheme {
    static let light = DashboardPalette(
        bg: Color(hex: 0xF5F6F8),
        bgSidebar: Color(hex: 0xECEEF2),
        bgPanel: Color(hex: 0xFFFFFF),
        bgElevated: Color(hex: 0xF5F6F8),
        bgHover: Color(hex: 0xEBEDF1),
        border: Color(hex: 0xE2E6EC),
        borderSoft: Color(hex: 0xECEFF3),
        text: Color(hex: 0x171A21),
        textDim: Color(hex: 0x4B5468),
        textFaint: Color(hex: 0x7C879A),
        // accent/accentSecondary sample the AppIcon's link-chain gradient
        // (indigo -> cyan) so the chrome reads as the same brand as the icon
        // instead of a generic system blue.
        accent: Color(hex: 0x4F46E5),
        accentDim: Color(hex: 0xE0E7FF),
        accentSecondary: Color(hex: 0x0891B2),
        accentSecondaryDim: Color(hex: 0xCFFAFE),
        green: Color(hex: 0x16A34A),
        greenDim: Color(hex: 0xDCFCE7),
        amber: Color(hex: 0xD97706),
        amberDim: Color(hex: 0xFEF3C7),
        red: Color(hex: 0xDC2626),
        redDim: Color(hex: 0xFEE2E2)
    )

    static let dark = DashboardPalette(
        bg: Color(hex: 0x1A1B1F),
        bgSidebar: Color(hex: 0x16171B),
        bgPanel: Color(hex: 0x212226),
        bgElevated: Color(hex: 0x26272C),
        bgHover: Color(hex: 0x2C2D33),
        border: Color(hex: 0x303136),
        borderSoft: Color(hex: 0x2A2B30),
        text: Color(hex: 0xF0F1F3),
        textDim: Color(hex: 0xAEB4C0),
        textFaint: Color(hex: 0x848C9C),
        accent: Color(hex: 0x6366F1),
        accentDim: Color(hex: 0x22234A),
        accentSecondary: Color(hex: 0x06B6D4),
        accentSecondaryDim: Color(hex: 0x0E3A42),
        green: Color(hex: 0x22C55E),
        greenDim: Color(hex: 0x14301F),
        amber: Color(hex: 0xF59E0B),
        amberDim: Color(hex: 0x3A2A0F),
        red: Color(hex: 0xEF4444),
        redDim: Color(hex: 0x3A1414)
    )

    static func current(for scheme: ColorScheme) -> DashboardPalette {
        scheme == .dark ? dark : light
    }
}

private extension Color {
    init(hex: UInt32) {
        self.init(
            .sRGB,
            red: Double((hex >> 16) & 0xFF) / 255,
            green: Double((hex >> 8) & 0xFF) / 255,
            blue: Double(hex & 0xFF) / 255,
            opacity: 1
        )
    }
}

/// Reads the current `DashboardPalette` from the environment -- every
/// dashboard-shell view uses this instead of hardcoding colors, so changes
/// to `DashboardTheme.light`/`.dark` propagate everywhere at once.
private struct DashboardPaletteKey: EnvironmentKey {
    static let defaultValue = DashboardTheme.light
}

extension EnvironmentValues {
    var dashboardPalette: DashboardPalette {
        get { self[DashboardPaletteKey.self] }
        set { self[DashboardPaletteKey.self] = newValue }
    }
}

extension View {
    /// Applies the dashboard palette matching `scheme` to this view and its
    /// descendants via the environment.
    func dashboardPalette(for scheme: ColorScheme) -> some View {
        environment(\.dashboardPalette, DashboardTheme.current(for: scheme))
    }

    /// Every custom `.buttonStyle(.plain)` control in this app (icon
    /// buttons, text-only actions) draws its own chrome, which means it
    /// gets none of AppKit's automatic hover/pressed feedback for free --
    /// without this, a button gives no visual sign it's interactive until
    /// the moment it's clicked. This centralizes the "hovering this control
    /// shows a pointing-hand cursor and flips `isHovering`" wiring so every
    /// call site pairs it with its own color/background change instead of
    /// re-deriving the push/pop cursor dance each time.
    func hoverCursor(_ isHovering: Binding<Bool>, enabled: Bool = true) -> some View {
        onHover { hovering in
            if hovering {
                // Only gates *entering* the hover state -- if `enabled`
                // flips to `false` while the mouse is already over the
                // control (e.g. the last node gets deleted while hovering
                // "Test All"), the matching exit event below still must run
                // unconditionally, or `isHovering` gets stuck `true` (the
                // hover highlight never turns off) and `NSCursor.pop()`
                // never balances the earlier `push()` (the pointing-hand
                // cursor gets stuck too).
                guard enabled else { return }
                isHovering.wrappedValue = true
                NSCursor.pointingHand.push()
            } else {
                guard isHovering.wrappedValue else { return }
                isHovering.wrappedValue = false
                NSCursor.pop()
            }
        }
        .animation(.easeOut(duration: 0.12), value: isHovering.wrappedValue)
    }
}

/// A dashboard-styled card: white surface, hairline border, 12pt corner
/// radius, a very light shadow -- the base container used throughout
/// Overview/Chain Builder/Log/Nodes/Settings.
struct DashboardCard<Content: View>: View {
    @Environment(\.dashboardPalette) private var palette
    var padding: CGFloat = 18
    @ViewBuilder var content: Content

    var body: some View {
        content
            .padding(padding)
            .background(palette.bgPanel, in: RoundedRectangle(cornerRadius: 12, style: .continuous))
            .clipShape(RoundedRectangle(cornerRadius: 12, style: .continuous))
            .overlay(
                RoundedRectangle(cornerRadius: 12, style: .continuous)
                    .strokeBorder(palette.border, lineWidth: 1)
            )
            .shadow(color: .black.opacity(0.04), radius: 6, x: 0, y: 1)
    }
}

/// A small tinted tag label -- status badges, protocol tags, ACTIVE/healthy
/// markers.
struct DashboardBadge: View {
    @Environment(\.dashboardPalette) private var palette
    let text: String
    var foreground: Color
    var background: Color
    /// Ceiling on the pill's total width -- text past it truncates with an
    /// ellipsis instead of stretching the badge (and whatever row it sits
    /// in) arbitrarily wide. Short text sizes to its own content as usual;
    /// this only ever clamps the long end. Only set this when truncation
    /// is expected; it also turns on a hover tooltip with the
    /// untruncated text, so leave it nil for badges that should never clip.
    var maxWidth: CGFloat?

    init(_ text: String, foreground: Color, background: Color, maxWidth: CGFloat? = nil) {
        self.text = text
        self.foreground = foreground
        self.background = background
        self.maxWidth = maxWidth
    }

    var body: some View {
        let pill = Text(text)
            .font(.system(size: 11, weight: .bold))
            .foregroundStyle(foreground)
            .lineLimit(1)
            .truncationMode(.tail)
            .padding(.horizontal, 7)
            .padding(.vertical, 3)
            .frame(maxWidth: maxWidth, alignment: .center)
            .background(background, in: RoundedRectangle(cornerRadius: 6, style: .continuous))

        if maxWidth != nil {
            pill.help(text)
        } else {
            pill
        }
    }
}

/// A small status dot -- healthy/degraded/dead, running/stopped, etc.
struct DashboardDot: View {
    let color: Color
    var size: CGFloat = 7

    var body: some View {
        Circle().fill(color).frame(width: size, height: size)
    }
}
