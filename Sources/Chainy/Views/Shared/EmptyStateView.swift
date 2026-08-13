import SwiftUI

/// A centered placeholder for an empty list, used instead of
/// `ContentUnavailableView` since this app targets macOS 13.
struct EmptyStateView: View {
    @Environment(\.dashboardPalette) private var palette
    let title: String
    let systemImage: String
    let message: String

    var body: some View {
        VStack(spacing: 10) {
            Image(systemName: systemImage)
                .font(.system(size: 32))
                .foregroundStyle(palette.textFaint)
            Text(title)
                .font(.system(size: 14, weight: .semibold))
                .foregroundStyle(palette.text)
            Text(message)
                .font(.system(size: 12.5))
                .foregroundStyle(palette.textFaint)
                .multilineTextAlignment(.center)
        }
        .frame(maxWidth: 340)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .padding()
    }
}
