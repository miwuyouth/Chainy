import SwiftUI

/// A small tinted capsule label, e.g. a latency/bandwidth reading or a UDP
/// capability tag. Shared so a given chain's badges look identical wherever
/// they show up.
struct MetricBadge: View {
    let text: String
    let color: Color

    var body: some View {
        Text(text)
            .font(.caption2.weight(.bold))
            .foregroundStyle(color)
            .padding(.horizontal, 6)
            .padding(.vertical, 2)
            .background(color.opacity(0.15), in: Capsule())
    }
}
