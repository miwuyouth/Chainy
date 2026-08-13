import SwiftUI

struct NodeEditorSheet: View {
    @Environment(\.dismiss) private var dismiss
    let node: LibraryNode?
    let onSave: (LibraryNode) -> Void

    @State private var name: String
    @State private var draft: HopDraft

    init(node: LibraryNode?, onSave: @escaping (LibraryNode) -> Void) {
        self.node = node
        self.onSave = onSave
        _name = State(initialValue: node?.name ?? "")
        _draft = State(initialValue: node.map { HopDraft(hop: $0.hop) } ?? HopDraft())
    }

    var body: some View {
        VStack(spacing: 0) {
            Text(node == nil ? "Add Node" : "Edit Node")
                .font(.headline)
                .padding()

            Form {
                TextField("Name", text: $name)
                    .accessibilityIdentifier("nodeEditor.name")
                HopFieldsForm(draft: $draft)
            }
            .formStyle(.grouped)

            Divider()
            VStack(alignment: .trailing, spacing: 4) {
                HStack {
                    Spacer()
                    Button("Cancel") { dismiss() }
                        .accessibilityIdentifier("nodeEditor.cancel")
                    Button("Save") {
                        guard let hop = draft.makeHop() else { return }
                        let trimmedName = name.trimmingCharacters(in: .whitespaces)
                        let finalName = trimmedName.isEmpty ? "\(hop.host):\(hop.port)" : trimmedName
                        onSave(LibraryNode(id: node?.id ?? UUID(), name: finalName, hop: hop, subscriptionID: node?.subscriptionID))
                        dismiss()
                    }
                    .keyboardShortcut(.defaultAction)
                    .disabled(!draft.isValid)
                    .accessibilityIdentifier("nodeEditor.save")
                }
                if !draft.isValid {
                    Text("Enter a host and port to continue")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            .padding()
        }
        .frame(width: 420, height: 420)
    }
}
