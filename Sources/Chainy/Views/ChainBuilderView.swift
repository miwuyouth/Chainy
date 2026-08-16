import SwiftUI
import AppKit
import UniformTypeIdentifiers
import ChainCore

/// Vertical alignment shared by the Chain Builder canvas row (CLIENT,
/// insert connectors, hop pills, DESTINATION) so they all line up on the
/// same connector line. Plain `.center` isn't enough: `hopCard` stacks a
/// protocol caption *below* its pill, so the pill itself sits above the
/// vertical center of `hopCard`'s full (pill + caption) height. Every other
/// item in the row falls back to ordinary center alignment (the default
/// below); only `hopCard` overrides this to point at its pill's own
/// center instead of its whole block's center.
private struct ConnectorCenter: AlignmentID {
    static func defaultValue(in context: ViewDimensions) -> CGFloat {
        context[VerticalAlignment.center]
    }
}

private extension VerticalAlignment {
    static let connectorCenter = VerticalAlignment(ConnectorCenter.self)
}

/// One entry in the in-progress "Your Chain" staging list. Tracks the
/// library node it came from (if any) so the row can show that node's
/// *current* name/config, while still keeping the snapshotted `ProxyHop`
/// around as a fallback for hops loaded from an existing saved chain that
/// no longer match anything in the library (edited/deleted since -- the
/// only way `libraryNodeID` still ends up `nil` now that every staged hop
/// is added via the node picker).
private struct StagedHop: Identifiable, Equatable {
    let id = UUID()
    var libraryNodeID: UUID?
    var hop: ProxyHop
}

/// The "Chain Builder" panel: a horizontal hop-chain canvas (Client -> hops
/// -> Destination) instead of the old two-column node-pool layout. Hops are
/// picked from the node-picker overlay only -- there is no per-protocol
/// field editing here (that used to live in an inline "Hop Settings" side
/// panel and an "Add Blank Hop" form, both removed by design: editing a
/// node's real fields belongs on the Nodes panel, not mid-chain, so a hop
/// picked here always tracks a real library node). Builder save/load/
/// staging behavior is unchanged from the previous `ChainsView`: edits
/// stage locally and only become a real saved chain on "Save Chain"/
/// "Update Chain".
struct ChainBuilderView: View {
    @EnvironmentObject var store: AppStore
    @Environment(\.dashboardPalette) private var palette

    @State private var builderChainID: UUID?
    @State private var draftName = ""
    // Tracks the last name `syncAutoName` wrote, so a hand-typed name (which
    // diverges from this) is never clobbered by a later hop edit -- only a
    // still-untouched or still-auto-generated name gets regenerated.
    @State private var lastAutoName = ""
    @State private var stagedHops: [StagedHop] = []
    @State private var draggingHopID: UUID?

    @State private var showingNodePicker = false
    @State private var nodePickerInsertIndex = 0
    @State private var nodePickerSearchText = ""

    @State private var isHoveringSaveButton = false
    @State private var isHoveringCancelEdit = false

    @State private var hoveringHopCardID: UUID?
    @State private var isHoveringNodePickerSearchClear = false
    @State private var isHoveringNodePickerClose = false
    @State private var hoveringPickerNodeID: UUID?

    private var isValid: Bool {
        !draftName.trimmingCharacters(in: .whitespaces).isEmpty && !stagedHops.isEmpty
    }

    var body: some View {
        ZStack {
            VStack(spacing: 0) {
                // `builderCard` keeps its natural height; only
                // `savedChainsCard` is flexible (`.frame(maxHeight:
                // .infinity)` below), so it -- not this whole column -- is
                // what absorbs the remaining vertical space. That makes
                // this a plain `VStack`, not a `ScrollView`: a `ScrollView`
                // proposes unbounded height to its content, which is
                // exactly what made `savedChainsTable` unable to size
                // itself (see that property's doc comment) and forced the
                // old `scrollDisabled` + hand-computed `.frame(height:)`
                // workaround. A plain `VStack` here instead hands the table
                // a real, bounded height, so it can fall back to `Table`'s
                // own native scrolling -- when there are more saved chains
                // than fit, only the table scrolls, not this whole column.
                VStack(alignment: .leading, spacing: 16) {
                    builderCard
                    if store.settings.chains.isEmpty {
                        EmptyStateView(
                            title: "No saved chains yet",
                            systemImage: "link",
                            message: "Add hops above, name your chain, then click Save Chain."
                        )
                        .frame(height: 140)
                    } else {
                        savedChainsCard
                            .frame(maxHeight: .infinity)
                    }
                }
                .padding(20)
                // Without an explicit `maxHeight: .infinity` here, this
                // column would shrink-wrap to its content's own height
                // whenever the flexible branch above doesn't apply (the
                // empty-chains state has no flexible child of its own) --
                // collapsing this whole `VStack` with it and pulling
                // `footerBar` up out of its pinned-to-bottom position.
                // `alignment: .top` keeps that shrink-wrapped content
                // sitting at the top of the now-taller frame rather than
                // centered in it.
                .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)

                Rectangle().fill(palette.border).frame(height: 1)
                footerBar
            }

            nodePickerOverlay
        }
        .onChange(of: stagedHops) { _ in syncAutoName() }
    }

    /// Fills the chain-name field from the staged hops' node names (e.g.
    /// "香港 S01 → 香港 S02") as they're picked, so a new chain rarely needs a
    /// hand-typed name at all. Only touches the field while it's still empty
    /// or still holds a previous auto-generated value -- once the user types
    /// their own name it diverges from `lastAutoName` and is left alone.
    /// Skipped entirely while editing an existing saved chain, whose name
    /// was set by `loadIntoBuilder`, not by this.
    private func syncAutoName() {
        guard builderChainID == nil else { return }
        guard draftName.isEmpty || draftName == lastAutoName else { return }
        let generated = stagedHops
            .map { nodeName(for: $0) ?? "\($0.hop.host):\($0.hop.port)" }
            .joined(separator: " → ")
        draftName = generated
        lastAutoName = generated
    }

    // MARK: - Footer

    // Two cards near the top of an otherwise-empty scroll area used to leave
    // the rest of the page floating with nothing to anchor the eye at the
    // bottom. This bar -- real counts pulled straight from `store`, not
    // decorative filler -- pins to the bottom of the screen the same way
    // `RootView`'s sidebar footer does, so there's always something grounded
    // there regardless of how few chains are saved.
    private var footerBar: some View {
        HStack(spacing: 14) {
            HStack(spacing: 7) {
                DashboardDot(color: activeChain != nil ? palette.accent : palette.textFaint, size: 7)
                Text(activeChain?.name ?? "No active chain")
                    .font(.system(size: 12, weight: .medium))
                    .foregroundStyle(palette.textDim)
            }
            Spacer()
            Text("\(store.settings.chains.count) chain\(store.settings.chains.count == 1 ? "" : "s") · \(store.library.count) node\(store.library.count == 1 ? "" : "s") in library")
                .font(.system(size: 11.5))
                .foregroundStyle(palette.textFaint)
        }
        .padding(.horizontal, 24)
        .padding(.vertical, 10)
        .background(palette.bgSidebar)
    }

    private var activeChain: NamedProxyChain? {
        store.settings.chains.first { $0.id == store.settings.activeChainID }
    }

    // MARK: - Builder card

    // The name field and Save Chain button are now well clear of the outer
    // `DashboardCard`'s own rounded corner (a title row sits above the
    // field, and Save Chain sits at the very top instead) -- a bordered,
    // rounded box only reads as a second nested card when it hugs the
    // outer corner with little inset; with real vertical distance from it,
    // a normal bordered input and a solid accent button are both safe. The
    // canvas is its own inset, bordered rounded box rather than a full-bleed
    // tinted strip, for the same reason: enough margin from the card edges
    // that its corners don't compete with the outer ones.
    private var builderCard: some View {
        DashboardCard(padding: 0) {
            VStack(alignment: .leading, spacing: 22) {
                header
                canvas
            }
            .padding(.vertical, 26)
        }
    }

    private var header: some View {
        VStack(alignment: .leading, spacing: 20) {
            HStack(alignment: .top) {
                VStack(alignment: .leading, spacing: 4) {
                    Text(builderChainID == nil ? "Create Chain" : "Edit Chain")
                        .font(.system(size: 22, weight: .bold))
                        .foregroundStyle(palette.text)
                    Text("Create a chain by adding one or more hops between your device and the target host.")
                        .font(.system(size: 13))
                        .foregroundStyle(palette.textDim)
                }

                Spacer(minLength: 20)

                VStack(alignment: .trailing, spacing: 8) {
                    Button {
                        saveChain()
                    } label: {
                        HStack(spacing: 8) {
                            Image(systemName: "square.and.arrow.down")
                                .font(.system(size: 13, weight: .semibold))
                            Text(builderChainID == nil ? "Save Chain" : "Update Chain")
                        }
                    }
                    .buttonStyle(.plain)
                    .font(.system(size: 13.5, weight: .semibold))
                    .padding(.horizontal, 18)
                    .padding(.vertical, 11)
                    .foregroundStyle(.white)
                    .background(
                        palette.accent.opacity(isValid ? (isHoveringSaveButton ? 0.85 : 1) : 0.4),
                        in: RoundedRectangle(cornerRadius: 10, style: .continuous)
                    )
                    .disabled(!isValid)
                    .contentShape(Rectangle())
                    .onHover { hovering in
                        guard isValid else { return }
                        isHoveringSaveButton = hovering
                        if hovering { NSCursor.pointingHand.push() } else { NSCursor.pop() }
                    }
                    .animation(.easeOut(duration: 0.12), value: isHoveringSaveButton)
                    .accessibilityIdentifier("chainBuilder.saveChain")

                    if builderChainID != nil {
                        Button("Cancel Edit") { resetBuilder() }
                            .buttonStyle(.plain)
                            .font(.system(size: 12))
                            .foregroundStyle(isHoveringCancelEdit ? palette.text : palette.textDim)
                            .underline(isHoveringCancelEdit)
                            .contentShape(Rectangle())
                            .onHover { hovering in
                                isHoveringCancelEdit = hovering
                                if hovering { NSCursor.pointingHand.push() } else { NSCursor.pop() }
                            }
                            .animation(.easeOut(duration: 0.12), value: isHoveringCancelEdit)
                    }
                }
            }

            TextField("Chain name (e.g. Privacy Max)", text: $draftName)
                .textFieldStyle(.plain)
                .font(.system(size: 14))
                .foregroundStyle(palette.text)
                .padding(.horizontal, 14)
                .padding(.vertical, 11)
                .background(palette.bgPanel, in: RoundedRectangle(cornerRadius: 9, style: .continuous))
                .overlay(RoundedRectangle(cornerRadius: 9, style: .continuous).strokeBorder(palette.border))
                .accessibilityIdentifier("chainBuilder.nameField")
        }
        .padding(.horizontal, 28)
    }

    // MARK: - Canvas

    // The empty state has a fixed, small number of elements (two end-caps
    // and one big "+") that never need to scroll, so it skips `ScrollView`
    // entirely -- a `ScrollView`'s scrolling axis proposes effectively
    // unbounded width to its content, which makes any `.frame(maxWidth:
    // .infinity)` child inside it collapse to its minimum instead of
    // stretching (there's no concrete width to stretch against), which is
    // why the connector dashes and centering didn't work while this row
    // was nested in one. Outside a `ScrollView`, the row gets the card's
    // real, bounded width, so the connectors stretch properly and the
    // whole row centers itself. Once hops exist, the row can genuinely
    // overflow, so that state keeps the `ScrollView`.
    private var canvas: some View {
        Group {
            if stagedHops.isEmpty {
                // Fixed-width connectors (not `.frame(maxWidth: .infinity)`)
                // so the row's intrinsic width is just "its own content" --
                // the outer `.frame(maxWidth: .infinity, alignment:
                // .center)` then centers that compact cluster within the
                // full canvas width, instead of stretching the dashes
                // themselves out to the card's full width.
                HStack(spacing: 0) {
                    endCap(title: "CLIENT", subtitle: "this device", icon: "laptopcomputer")
                    connectorSegment()
                    bigAddFirstHopButton
                    connectorSegment(withArrow: true)
                    endCap(title: "DESTINATION", subtitle: "target host", icon: "network")
                }
                .padding(.vertical, 22)
                .padding(.horizontal, 24)
                .frame(maxWidth: .infinity, alignment: .center)
            } else {
                // `.frame(maxWidth: .infinity)` doesn't reliably stretch or
                // center inside a `ScrollView` along its scroll axis (see
                // the empty-state comment above) -- but `.frame(minWidth:)`
                // does, because it sets a floor rather than asking for
                // "however much is available." Reading the real viewport
                // width via `GeometryReader` and using it as that floor
                // centers a short row (few hops) while still allowing a
                // long one (many hops) to overflow and scroll normally.
                GeometryReader { proxy in
                    ScrollView(.horizontal, showsIndicators: false) {
                        HStack(alignment: .connectorCenter, spacing: 0) {
                            endCap(title: "CLIENT", subtitle: "this device", icon: "laptopcomputer")
                            insertButton(index: 0)
                            ForEach(Array(stagedHops.enumerated()), id: \.element.id) { index, staged in
                                hopCard(staged)
                                insertButton(index: index + 1)
                            }
                            endCap(title: "DESTINATION", subtitle: "target host", icon: "network")
                        }
                        .padding(.vertical, 22)
                        .padding(.horizontal, 24)
                        .frame(minWidth: proxy.size.width, alignment: .center)
                    }
                }
                .frame(height: 120)
            }
        }
        .background(palette.bgElevated, in: RoundedRectangle(cornerRadius: 14, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: 14, style: .continuous).strokeBorder(palette.border))
        .padding(.horizontal, 28)
    }

    /// A short, fixed-width dashed connector -- used either side of
    /// `bigAddFirstHopButton` so CLIENT/+/DESTINATION read as one compact,
    /// connected cluster (the whole row is then centered by its caller),
    /// rather than dashes stretching out to the canvas's full width.
    private func connectorSegment(withArrow: Bool = false) -> some View {
        HStack(spacing: 4) {
            // `Rectangle().strokeBorder(...)` insets the stroke *inward*
            // from the shape's own bounds, so on a 1pt-tall rectangle a
            // 1.25pt stroke has no room to actually draw -- it rendered
            // invisibly instead of as a hairline. A `Path` with a single
            // horizontal line and `.stroke(style:)` draws the dash pattern
            // directly on that line instead of inset into a degenerate
            // shape, so it's visible regardless of how thin the frame is.
            Path { path in
                path.move(to: CGPoint(x: 0, y: 0))
                path.addLine(to: CGPoint(x: 64, y: 0))
            }
            .stroke(palette.accent.opacity(0.5), style: StrokeStyle(lineWidth: 1.5, dash: [5, 4]))
            .frame(width: 64, height: 1)
            if withArrow {
                Image(systemName: "arrowtriangle.right.fill")
                    .font(.system(size: 10))
                    .foregroundStyle(palette.accent)
            }
        }
    }

    private var bigAddFirstHopButton: some View {
        Button {
            nodePickerInsertIndex = 0
            nodePickerSearchText = ""
            showingNodePicker = true
        } label: {
            Image(systemName: "plus")
                .font(.system(size: 17, weight: .semibold))
                .foregroundStyle(palette.accent)
                .frame(width: 44, height: 44)
                .background(palette.accentDim, in: Circle())
                .overlay(Circle().strokeBorder(palette.accent.opacity(0.45), style: StrokeStyle(lineWidth: 1.5, dash: [5, 4])))
        }
        .buttonStyle(.plain)
        .contentShape(Circle())
        .help("Add your first hop")
        .onHover { hovering in
            if hovering { NSCursor.pointingHand.push() } else { NSCursor.pop() }
        }
        .accessibilityIdentifier("chainBuilder.addFirstHop")
    }

    // `subtitle` is a fixed conceptual label ("this device" / "target
    // host"), not real host data -- unlike every other address string in
    // this view, it never resolves to an actual value (the true
    // destination is whatever site gets browsed through the tunnel). It
    // intentionally skips the `.monospaced` design used for genuine
    // host:port text elsewhere on this canvas -- otherwise it reads as an
    // unset data field instead of a label.
    private func endCap(title: String, subtitle: String, icon: String) -> some View {
        HStack(spacing: 12) {
            Image(systemName: icon)
                .font(.system(size: 16, weight: .medium))
                .foregroundStyle(palette.accent)
                .frame(width: 40, height: 40)
                .background(palette.accentDim, in: RoundedRectangle(cornerRadius: 10, style: .continuous))
            VStack(alignment: .leading, spacing: 2) {
                Text(title).font(.system(size: 10.5, weight: .bold)).foregroundStyle(palette.textDim)
                Text(subtitle).font(.system(size: 13, weight: .medium)).foregroundStyle(palette.text)
            }
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 12)
        .background(palette.bgPanel, in: RoundedRectangle(cornerRadius: 12, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: 12, style: .continuous).strokeBorder(palette.border))
    }

    private func insertButton(index: Int) -> some View {
        InsertHopButton(palette: palette, isConnected: !stagedHops.isEmpty) {
            nodePickerInsertIndex = index
            nodePickerSearchText = ""
            showingNodePicker = true
        }
    }

    /// Four distinct states -- untested/testing/reachable/unreachable --
    /// each get their own color *and* their own label text, never relying
    /// on color alone (a flat gray "untested" used to read as barely-there
    /// filler text rather than a real state).
    private func hopStatus(_ staged: StagedHop) -> (color: Color, label: String, isTesting: Bool) {
        if let libraryNodeID = staged.libraryNodeID, store.testingNodeIDs.contains(libraryNodeID) {
            return (palette.amber, "testing…", true)
        }
        guard let libraryNodeID = staged.libraryNodeID, let latency = store.nodeLatencyMs[libraryNodeID] else {
            return (palette.textFaint, "untested", false)
        }
        if let ms = latency {
            return (ms > 150 ? palette.amber : palette.green, "\(ms)ms", false)
        }
        return (palette.red, "Failed", false)
    }

    /// The originating library node's current name, if `staged` still
    /// matches one (see the `StagedHop` doc comment above). Falls back to
    /// the raw host so a hand-typed/blank hop still shows *something*.
    private func nodeName(for staged: StagedHop) -> String? {
        guard let id = staged.libraryNodeID else { return nil }
        return store.library.first { $0.id == id }?.name
    }

    /// The library node backing this staged hop, if any -- only hops that
    /// came from (and still match) a saved library node can be tested,
    /// since `AppStore.testNode` dials a real `LibraryNode`.
    private func matchedLibraryNode(for staged: StagedHop) -> LibraryNode? {
        guard let id = staged.libraryNodeID else { return nil }
        return store.library.first { $0.id == id }
    }

    /// True when this hop's protocol config has TLS switched on -- shown as
    /// a small lock glyph next to the protocol caption rather than a full
    /// `DashboardBadge`, since the pill below only has room for one caption
    /// line.
    private func hopUsesTLS(_ staged: StagedHop) -> Bool {
        switch staged.hop.protocolConfig {
        case .trojan(_, let tls, _, _, _, _): return tls
        case .vless(_, true, _, _, _, _): return true
        case .vmess(_, _, _, true, _, _, _, _): return true
        default: return false
        }
    }

    // A compact pill (name only) with a protocol caption underneath, rather
    // than the old detail-dense card (badge/host-port/TLS-badge/status-text
    // all always visible). The dropped detail isn't gone -- host:port,
    // TLS, and status are one hover away via `.help`; the Test/Remove
    // actions reveal on hover instead of always taking up card space.
    // There's no per-field editing here at all (see the type's doc
    // comment) -- that's the Nodes panel's job -- so hovering is this
    // card's only interactive state, no tap/selected state to track.
    private func hopCard(_ staged: StagedHop) -> some View {
        let status = hopStatus(staged)
        let hostPort = "\(staged.hop.host):\(String(staged.hop.port))"
        let name = nodeName(for: staged)
        let matchedNode = matchedLibraryNode(for: staged)
        let isHoveringCard = hoveringHopCardID == staged.id
        let tooltip = "\(hostPort) · \(status.label)\(hopUsesTLS(staged) ? " · TLS" : "")"

        return VStack(spacing: 8) {
            Group {
                if isHoveringCard {
                    // Swapped in place of the name label, inside the same
                    // pill footprint, instead of floating above it -- icons
                    // positioned outside the pill's own bounds (e.g. via a
                    // negative offset) sit outside its hover/hit-testing
                    // area too, so moving the mouse toward them exits the
                    // hover first and they vanish before they can be
                    // clicked.
                    HStack(spacing: 8) {
                        if let matchedNode {
                            Button {
                                Task { await store.testNode(matchedNode) }
                            } label: {
                                Image(systemName: "bolt.fill")
                                    .font(.system(size: 9))
                                    .frame(width: 20, height: 20)
                            }
                            .buttonStyle(.plain)
                            .foregroundStyle(.white)
                            .background(palette.accent, in: Circle())
                            .disabled(status.isTesting)
                            .help("Test this node's connectivity and latency")
                        }
                        Button {
                            stagedHops.removeAll { $0.id == staged.id }
                        } label: {
                            Image(systemName: "xmark")
                                .font(.system(size: 9, weight: .bold))
                                .frame(width: 20, height: 20)
                        }
                        .buttonStyle(.plain)
                        .foregroundStyle(.white)
                        .background(palette.red, in: Circle())
                        .help("Remove hop")
                    }
                } else {
                    Text(name ?? "Unnamed hop")
                        .font(.system(size: 13, weight: .semibold))
                        .foregroundStyle(name != nil ? palette.text : palette.textFaint)
                        .italic(name == nil)
                        .lineLimit(1)
                        .truncationMode(.middle)
                }
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 11)
            .frame(width: 140)
            .background(palette.bgPanel, in: Capsule())
            .overlay(
                Capsule().strokeBorder(palette.border, lineWidth: 1)
            )
            .overlay(alignment: .topTrailing) {
                Group {
                    if status.isTesting {
                        ProgressView().controlSize(.mini)
                    } else {
                        DashboardDot(color: status.color, size: 7)
                    }
                }
                .offset(x: -8, y: 8)
            }
            // Propagates this pill's own center up through the VStack as
            // the row's `.connectorCenter` alignment point -- the same
            // mechanism `.firstTextBaseline` uses to align nested text
            // across sibling views, so the caption below doesn't pull the
            // connector line down toward the middle of "pill + caption."
            .alignmentGuide(.connectorCenter) { d in d[VerticalAlignment.center] }

            HStack(spacing: 4) {
                Text(staged.hop.protocolConfig.displayName)
                    .font(.system(size: 11.5))
                    .foregroundStyle(palette.textDim)
                if hopUsesTLS(staged) {
                    Image(systemName: "lock.fill")
                        .font(.system(size: 8))
                        .foregroundStyle(palette.accent)
                }
            }
        }
        .frame(width: 140)
        .contentShape(Rectangle())
        .help(tooltip)
        .onHover { hovering in
            withAnimation(.easeOut(duration: 0.12)) {
                hoveringHopCardID = hovering ? staged.id : nil
            }
        }
        .onDrag {
            draggingHopID = staged.id
            return NSItemProvider(object: staged.id.uuidString as NSString)
        }
        .onDrop(of: [.text], delegate: StagedHopDropDelegate(
            target: staged,
            items: $stagedHops,
            draggingHopID: $draggingHopID
        ))
    }

    // MARK: - Node picker

    private var filteredPickerNodes: [LibraryNode] {
        let query = nodePickerSearchText.trimmingCharacters(in: .whitespaces)
        guard !query.isEmpty else { return store.library }
        return store.library.filter { node in
            node.name.localizedCaseInsensitiveContains(query)
                || node.hop.host.localizedCaseInsensitiveContains(query)
                || node.hop.protocolConfig.displayName.localizedCaseInsensitiveContains(query)
        }
    }

    private var nodePickerSearchField: some View {
        HStack(spacing: 8) {
            Image(systemName: "magnifyingglass")
                .font(.system(size: 11))
                .foregroundStyle(palette.textFaint)
            TextField("Search nodes by name, host, or protocol", text: $nodePickerSearchText)
                .textFieldStyle(.plain)
                .font(.system(size: 12, design: .monospaced))
            if !nodePickerSearchText.isEmpty {
                Button {
                    nodePickerSearchText = ""
                } label: {
                    Image(systemName: "xmark.circle.fill").font(.system(size: 11))
                        .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .foregroundStyle(isHoveringNodePickerSearchClear ? palette.textDim : palette.textFaint)
                .hoverCursor($isHoveringNodePickerSearchClear)
            }
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 8)
        .background(palette.bgElevated, in: RoundedRectangle(cornerRadius: 8, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: 8, style: .continuous).strokeBorder(palette.border))
    }

    @ViewBuilder
    private var nodePickerOverlay: some View {
        if showingNodePicker {
            ZStack {
                Color.black.opacity(0.55)
                    .ignoresSafeArea()
                    .onTapGesture { showingNodePicker = false }

                VStack(alignment: .leading, spacing: 14) {
                    HStack {
                        Text("Choose a Node").font(.system(size: 15, weight: .semibold))
                        Spacer()
                        Button { showingNodePicker = false } label: {
                            Image(systemName: "xmark")
                                .foregroundStyle(isHoveringNodePickerClose ? palette.text : palette.textFaint)
                                .contentShape(Rectangle())
                        }
                        .buttonStyle(.plain)
                        .hoverCursor($isHoveringNodePickerClose)
                    }

                    if !store.library.isEmpty {
                        nodePickerSearchField
                    }

                    ScrollView {
                        VStack(spacing: 6) {
                            if store.library.isEmpty {
                                Text("No imported nodes yet — import a subscription from the Nodes panel first.")
                                    .font(.system(size: 12.5))
                                    .foregroundStyle(palette.textFaint)
                            } else if filteredPickerNodes.isEmpty {
                                Text("No nodes match your search.")
                                    .font(.system(size: 12.5))
                                    .foregroundStyle(palette.textFaint)
                            } else {
                                ForEach(filteredPickerNodes) { node in
                                    Button {
                                        insertStagedHop(StagedHop(libraryNodeID: node.id, hop: node.hop), at: nodePickerInsertIndex)
                                        showingNodePicker = false
                                    } label: {
                                        HStack(spacing: 9) {
                                            DashboardBadge(node.hop.protocolConfig.displayName, foreground: palette.textDim, background: palette.bgHover)
                                            VStack(alignment: .leading, spacing: 2) {
                                                Text(node.name).font(.system(size: 12.5)).foregroundStyle(palette.text)
                                                Text("\(node.hop.host):\(String(node.hop.port))")
                                                    .font(.system(size: 11, design: .monospaced))
                                                    .foregroundStyle(palette.textFaint)
                                            }
                                            Spacer()
                                        }
                                        .padding(10)
                                        .background(
                                            hoveringPickerNodeID == node.id ? palette.bgHover : palette.bgElevated,
                                            in: RoundedRectangle(cornerRadius: 8, style: .continuous)
                                        )
                                        .contentShape(Rectangle())
                                    }
                                    .buttonStyle(.plain)
                                    .hoverCursor(Binding(
                                        get: { hoveringPickerNodeID == node.id },
                                        set: { hoveringPickerNodeID = $0 ? node.id : nil }
                                    ))
                                    .accessibilityIdentifier("chainBuilder.nodePickerRow.\(node.name)")
                                }
                            }
                        }
                    }
                    .frame(maxHeight: 320)
                }
                .padding(20)
                .frame(width: 420)
                .background(palette.bgPanel, in: RoundedRectangle(cornerRadius: 12, style: .continuous))
                .overlay(RoundedRectangle(cornerRadius: 12, style: .continuous).strokeBorder(palette.border))
            }
        }
    }

    private func insertStagedHop(_ staged: StagedHop, at index: Int) {
        stagedHops.insert(staged, at: min(max(index, 0), stagedHops.count))
    }

    // MARK: - Saved chains

    /// Each saved chain used to get its own rounded, bordered, padded row --
    /// with four chains saved, that read as four little cards stacked with
    /// gaps between them rather than one list. This now reads as an actual
    /// table, matching the Nodes table's own layout language: one shared
    /// border from `DashboardCard`, a labeled column header, and hairline
    /// row dividers so every chain's name/route/hops/status line up in the
    /// same columns instead of each row free-forming its own layout.
    private var savedChainsCard: some View {
        DashboardCard(padding: 0) {
            VStack(alignment: .leading, spacing: 0) {
                Text("Saved Chains")
                    .font(.system(size: 15, weight: .semibold))
                    .foregroundStyle(palette.text)
                    .padding(.horizontal, 16)
                    .padding(.vertical, 14)

                Rectangle().fill(palette.border).frame(height: 1)

                savedChainsTable
            }
        }
    }

    /// A native `Table` in place of the old hand-rolled `HStack` rows, so
    /// NAME -- often a long "region -> hop" label -- gets a real,
    /// user-draggable column divider instead of a hardcoded truncation
    /// width. Trade-off (confirmed with the user before making this swap):
    /// the row hover wash, hairline dividers, and header type are all this
    /// app's custom palette; `Table`'s header row, row separators, and
    /// column-resize chrome are drawn by AppKit's table view and can't be
    /// recolored to match exactly. `.frame(maxHeight: .infinity)` lets the
    /// table claim whatever real, bounded height its ancestors have to give
    /// (see the `body` comment on why that ancestor chain is a plain
    /// `VStack` now, not a `ScrollView`) and fall back to its own native
    /// AppKit scrolling once there are more rows than fit -- this table
    /// scrolls on its own, instead of the whole builder page scrolling
    /// (and previously, instead of an oversized fixed `.frame(height:)` +
    /// `scrollDisabled(true)` hack that this replaced).
    private var savedChainsTable: some View {
        Table(store.settings.chains) {
            TableColumn("NAME") { chain in
                savedChainCell(chain) {
                    Text(chain.name.isEmpty ? "Unnamed" : chain.name)
                        .font(.system(size: 12.5, weight: .medium))
                        .foregroundStyle(palette.textDim)
                        .lineLimit(1)
                        .truncationMode(.tail)
                        .help(chain.name)
                }
                .overlay(alignment: .leading) {
                    if chain.id == store.settings.activeChainID {
                        RoundedRectangle(cornerRadius: 2, style: .continuous)
                            .fill(palette.green)
                            .frame(width: 3)
                    }
                }
            }
            .width(min: 90, ideal: 150, max: 360)

            TableColumn("ROUTE") { chain in
                savedChainCell(chain) {
                    Text(chainRouteSummary(chain))
                        .font(.system(size: 13, weight: .semibold))
                        .foregroundStyle(palette.text)
                        .lineLimit(1)
                        .truncationMode(.tail)
                        .help(chainRouteSummary(chain))
                }
            }
            .width(min: 140, ideal: 280)

            TableColumn("HOPS") { chain in
                savedChainCell(chain) {
                    Text("\(chain.hops.count) hop\(chain.hops.count == 1 ? "" : "s")")
                        .font(.system(size: 11.5, design: .monospaced))
                        .foregroundStyle(palette.textFaint)
                }
            }
            .width(min: 56, ideal: 64, max: 100)

            TableColumn("STATUS") { chain in
                savedChainCell(chain) {
                    let health = chainHealthSummary(chain)
                    HStack(spacing: 5) {
                        if let health {
                            DashboardDot(color: health.color, size: 6)
                            Text(health.label)
                                .font(.system(size: 10.5, design: .monospaced))
                                .foregroundStyle(health.color)
                                .lineLimit(1)
                        }
                    }
                    .help(health?.tooltip ?? "")
                }
            }
            .width(min: 70, ideal: 90, max: 160)

            TableColumn("") { chain in
                savedChainCell(chain, alignment: .trailing) {
                    SavedChainIconsCell(
                        chain: chain,
                        palette: palette,
                        onLoad: { loadIntoBuilder(chain) },
                        onDuplicate: { duplicateChain(chain) },
                        onDelete: {
                            store.deleteChain(chain)
                            if builderChainID == chain.id { resetBuilder() }
                        }
                    )
                    // Extra breathing room past `savedChainCell`'s own
                    // trailing padding, so the delete button's hit area
                    // never sits flush against the table's true right edge
                    // -- once `savedChainsTable` can scroll internally
                    // (see its own doc comment), that edge is exactly
                    // where AppKit draws the vertical scrollbar, and a
                    // flush-right button there loses its first click to
                    // the scroller's own hit-testing instead of the
                    // button underneath it.
                    .padding(.trailing, 8)
                }
            }
            // Icon cluster is 3 x 22pt buttons + 2 x 10pt gaps = 86pt, plus
            // `savedChainCell`'s 10pt horizontal padding on each side and
            // the 8pt trailing pad above = 114pt of actual content. The
            // previous 90pt column was already narrower than that even
            // before accounting for scrollbar clearance, so the delete
            // button was quietly overflowing past the column's own bounds
            // -- this locks the column to a width that comfortably fits it.
            .width(min: 118, ideal: 118, max: 118)
        }
        .tableStyle(.inset(alternatesRowBackgrounds: false))
        .frame(maxHeight: .infinity)
    }

    /// Shared chrome for every column's cell in `savedChainsTable`: the
    /// click-anywhere-to-activate gesture and the right-click menu -- what
    /// used to live once on the whole row in the old `HStack`-based layout,
    /// now applied per-column since `Table` renders each cell
    /// independently. No hover wash: per-column gray tiles (Table gives
    /// each column its own padding/gaps, so five independent tinted boxes
    /// never read as one continuous row highlight) read as more broken
    /// than helpful, so the active-chain green bar is the only highlight
    /// left.
    @ViewBuilder
    private func savedChainCell<Content: View>(
        _ chain: NamedProxyChain,
        alignment: Alignment = .leading,
        @ViewBuilder content: () -> Content
    ) -> some View {
        content()
            .padding(.horizontal, 10)
            .padding(.vertical, 8)
            .frame(maxWidth: .infinity, alignment: alignment)
            .contentShape(Rectangle())
            .onTapGesture { activateChain(chain) }
            .help(chain.id == store.settings.activeChainID ? "Currently active" : "Click to activate this chain")
            .contextMenu {
                Button("Edit Chain") { loadIntoBuilder(chain) }
                Button("Duplicate Chain") { duplicateChain(chain) }
                Button("Delete Chain", role: .destructive) {
                    store.deleteChain(chain)
                    if builderChainID == chain.id { resetBuilder() }
                }
            }
    }

    /// Each hop's saved-library name (falling back to its raw host when the
    /// hop no longer matches a library node), joined into a route string
    /// like "US-LA → HK-01" -- so a chain's composition is visible directly
    /// in the list instead of requiring a click into the builder to see it.
    private func chainRouteSummary(_ chain: NamedProxyChain) -> String {
        zip(chain.hops, store.resolvedLibraryNodes(for: chain))
            .map { hop, node in node?.name ?? hop.host }
            .joined(separator: " → ")
    }

    /// A quick health readout for the STATUS column, built from each hop's
    /// *last* `AppStore.testNode` result (the same data the Nodes table and
    /// the builder's hop cards already show) -- so a chain's reachability
    /// is visible in the saved-chains table without opening it. Returns nil
    /// (empty cell) unless every hop has actually been tested at least
    /// once; a partial reading would be misleading rather than helpful.
    private func chainHealthSummary(_ chain: NamedProxyChain) -> (color: Color, label: String, tooltip: String)? {
        var totalMs = 0
        var anyUnreachable = false
        var parts: [String] = []

        for node in store.resolvedLibraryNodes(for: chain) {
            guard let node, let latency = store.nodeLatencyMs[node.id] else {
                return nil
            }
            if let ms = latency {
                totalMs += ms
                parts.append("\(node.name): \(ms)ms")
            } else {
                anyUnreachable = true
                if let reason = store.nodeTestFailureReason[node.id] {
                    parts.append("\(node.name): Failed (\(reason))")
                } else {
                    parts.append("\(node.name): Failed")
                }
            }
        }

        if anyUnreachable {
            return (palette.red, "Failed", parts.joined(separator: ", "))
        }
        let color = totalMs > chain.hops.count * 150 ? palette.amber : palette.green
        return (color, "\(totalMs)ms", "\(totalMs)ms total (\(parts.joined(separator: ", ")))")
    }

    private func activateChain(_ chain: NamedProxyChain) {
        store.setActiveChain(chain.id)
        if builderChainID != nil { resetBuilder() }
    }

    private func duplicateChain(_ chain: NamedProxyChain) {
        store.addChain(
            NamedProxyChain(name: "\(chain.name) Copy", hops: chain.hops),
            hopLibraryNodeIDs: store.hopLibraryNodeIDs(forChainID: chain.id)
        )
    }

    // MARK: - Builder actions

    private func loadIntoBuilder(_ chain: NamedProxyChain) {
        builderChainID = chain.id
        draftName = chain.name
        stagedHops = zip(chain.hops, store.resolvedLibraryNodes(for: chain)).map { hop, node in
            StagedHop(libraryNodeID: node?.id, hop: hop)
        }
    }

    private func resetBuilder() {
        builderChainID = nil
        draftName = ""
        lastAutoName = ""
        stagedHops = []
    }

    private func saveChain() {
        let hops = stagedHops.map { staged -> ProxyHop in
            if let id = staged.libraryNodeID, let node = store.library.first(where: { $0.id == id }) {
                return node.hop
            }
            return staged.hop
        }
        let hopLibraryNodeIDs = stagedHops.map(\.libraryNodeID)

        if let id = builderChainID {
            store.updateChain(NamedProxyChain(id: id, name: draftName, hops: hops), hopLibraryNodeIDs: hopLibraryNodeIDs)
        } else {
            store.addChain(NamedProxyChain(name: draftName, hops: hops), hopLibraryNodeIDs: hopLibraryNodeIDs)
        }
        resetBuilder()
    }
}

/// The connector between two hops (or a hop and an end-cap) on the Chain
/// Builder canvas. This is the app's core "add a hop here" affordance, so it
/// needs to read as an interactive drop target -- but once the chain
/// actually has hops (`isConnected`), the resting state should read as a
/// plain, neutral "this route is built" arrow (like a flow diagram) rather
/// than as a placeholder waiting to be filled: no visible plus button at
/// all until hovered, just a solid gray line with a small arrowhead. While
/// the chain is still empty, or the moment it's hovered, the dashed
/// line/plus-circle affordance takes over so "click here to add a hop" is
/// still obvious.
private struct InsertHopButton: View {
    let palette: DashboardPalette
    var isConnected: Bool = false
    let action: () -> Void

    @State private var isHovering = false

    private var showsPlainArrow: Bool { isConnected && !isHovering }

    var body: some View {
        Button(action: action) {
            ZStack {
                // A hand-positioned `Path` line still left the vertical
                // center a fraction of a point off from where the ZStack
                // actually centers other siblings, which was subtle for a
                // 1-2pt line alone but obvious once an arrowhead had to
                // land exactly on it. `Rectangle().fill(...)` has none of
                // that ambiguity -- a filled rectangle's center *is* its
                // frame's center, full stop -- so the two states that
                // actually need to line up with the arrow (hover, and a
                // connected/solid line) use that instead. Only the
                // dashed placeholder state (no arrow, less scrutinized)
                // still needs `Path`/`.stroke(dash:)`, since a plain fill
                // can't dash.
                Group {
                    if isHovering || showsPlainArrow {
                        Rectangle()
                            .fill(showsPlainArrow ? palette.accent.opacity(0.5) : palette.accent)
                    } else {
                        Path { path in
                            path.move(to: CGPoint(x: 0, y: 0))
                            path.addLine(to: CGPoint(x: 44, y: 0))
                        }
                        .stroke(palette.textFaint, style: StrokeStyle(lineWidth: 1.25, dash: [4, 3]))
                    }
                }
                .frame(width: 44, height: isHovering ? 1.5 : 1.25)
                .overlay(alignment: .trailing) {
                    if showsPlainArrow {
                        Path { path in
                            path.move(to: CGPoint(x: 0, y: 0))
                            path.addLine(to: CGPoint(x: 5, y: 3))
                            path.addLine(to: CGPoint(x: 0, y: 6))
                            path.closeSubpath()
                        }
                        .fill(palette.accent)
                        .frame(width: 5, height: 6)
                    }
                }
                if !showsPlainArrow {
                    Circle()
                        .fill(isHovering ? palette.accent : palette.bgPanel)
                        .frame(width: isHovering ? 24 : 20, height: isHovering ? 24 : 20)
                        .overlay(Circle().strokeBorder(isHovering ? palette.accent : palette.border, lineWidth: 1.25))
                        .overlay(
                            Image(systemName: "plus")
                                .font(.system(size: 10, weight: .bold))
                                .foregroundStyle(isHovering ? .white : palette.textDim)
                        )
                        .shadow(color: isHovering ? palette.accent.opacity(0.35) : .clear, radius: 5)
                }
            }
            .frame(width: 44, height: 70)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .help("Insert a hop here")
        .onHover { hovering in
            withAnimation(.easeOut(duration: 0.12)) {
                isHovering = hovering
            }
            if hovering {
                NSCursor.pointingHand.push()
            } else {
                NSCursor.pop()
            }
        }
    }
}

/// Reorders `items` by dragging one `StagedHop` on top of another, using the
/// classic onDrag/onDrop trick (no `List`, since this canvas sits inside a
/// horizontal `ScrollView` and a nested List would fight it for scroll
/// gestures).
private struct StagedHopDropDelegate: DropDelegate {
    let target: StagedHop
    @Binding var items: [StagedHop]
    @Binding var draggingHopID: UUID?

    func dropEntered(info: DropInfo) {
        guard let draggingHopID, draggingHopID != target.id,
              let from = items.firstIndex(where: { $0.id == draggingHopID }),
              let to = items.firstIndex(where: { $0.id == target.id }) else { return }
        guard items[from].id != items[to].id else { return }
        items.move(fromOffsets: IndexSet(integer: from), toOffset: to > from ? to + 1 : to)
    }

    func dropUpdated(info: DropInfo) -> DropProposal? {
        DropProposal(operation: .move)
    }

    func performDrop(info: DropInfo) -> Bool {
        draggingHopID = nil
        return true
    }
}

/// The trailing edit/duplicate/delete icon cluster for a `savedChainsTable`
/// row's icons column. Broken out as its own `View` (rather than inlined in
/// the `TableColumn` closure) because `@State` can only live on a view
/// struct's stored properties, and this cluster owns three independent
/// hover flags plus the delete confirmation dialog's presented state --
/// each needs to stay scoped to one row, not shared across the table the
/// way `ChainBuilderView.hoveringChainID` is.
private struct SavedChainIconsCell: View {
    let chain: NamedProxyChain
    let palette: DashboardPalette
    let onLoad: () -> Void
    let onDuplicate: () -> Void
    let onDelete: () -> Void

    @State private var showingDeleteConfirm = false
    @State private var isHoveringEdit = false
    @State private var isHoveringDuplicate = false
    @State private var isHoveringDelete = false

    var body: some View {
        HStack(spacing: 10) {
            // Edit/duplicate/delete used to be buried one level deep
            // behind a "..." menu -- surfacing them as icons cuts that
            // click in half for the two most common actions, while
            // delete keeps its confirmation guard rail. Duplicate is
            // dimmed a step further than edit, so the harmless actions
            // don't sit close enough to the red, irreversible one to
            // invite a misclick.
            Button(action: onLoad) {
                Image(systemName: "pencil").font(.system(size: 11.5))
                    .frame(width: 22, height: 22)
                    .background(isHoveringEdit ? palette.bgHover : .clear, in: RoundedRectangle(cornerRadius: 5, style: .continuous))
            }
            .buttonStyle(.plain)
            .contentShape(Rectangle())
            .foregroundStyle(isHoveringEdit ? palette.accent : palette.textDim)
            .onHover { hovering in
                isHoveringEdit = hovering
                if hovering { NSCursor.pointingHand.push() } else { NSCursor.pop() }
            }
            .animation(.easeOut(duration: 0.12), value: isHoveringEdit)
            .help("Edit chain")

            Button(action: onDuplicate) {
                Image(systemName: "doc.on.doc").font(.system(size: 11.5))
                    .frame(width: 22, height: 22)
                    .background(isHoveringDuplicate ? palette.bgHover : .clear, in: RoundedRectangle(cornerRadius: 5, style: .continuous))
            }
            .buttonStyle(.plain)
            .contentShape(Rectangle())
            .foregroundStyle(isHoveringDuplicate ? palette.textDim : palette.textFaint)
            .onHover { hovering in
                isHoveringDuplicate = hovering
                if hovering { NSCursor.pointingHand.push() } else { NSCursor.pop() }
            }
            .animation(.easeOut(duration: 0.12), value: isHoveringDuplicate)
            .help("Duplicate chain")

            // Neutral gray at rest, red only on hover -- so delete
            // doesn't out-shout the other two icons at a glance; the
            // "this is dangerous" cue shows up right when you're about
            // to click it, not on every render.
            Button(action: { showingDeleteConfirm = true }) {
                Image(systemName: "trash").font(.system(size: 11.5))
                    .frame(width: 22, height: 22)
                    .background(isHoveringDelete ? palette.bgHover : .clear, in: RoundedRectangle(cornerRadius: 5, style: .continuous))
            }
            .buttonStyle(.plain)
            .contentShape(Rectangle())
            .foregroundStyle(isHoveringDelete ? palette.red : palette.textFaint)
            .onHover { hovering in
                isHoveringDelete = hovering
                if hovering { NSCursor.pointingHand.push() } else { NSCursor.pop() }
            }
            .animation(.easeOut(duration: 0.12), value: isHoveringDelete)
            .help("Delete chain")
            .confirmationDialog(
                "Delete \"\(chain.name)\"?",
                isPresented: $showingDeleteConfirm,
                titleVisibility: .visible
            ) {
                Button("Delete", role: .destructive, action: onDelete)
                Button("Cancel", role: .cancel) {}
            } message: {
                Text("This cannot be undone.")
            }
        }
    }
}
