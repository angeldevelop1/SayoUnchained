import SwiftUI
import UniformTypeIdentifiers

struct LibraryView: View {
    @EnvironmentObject var state: AppState
    @State private var urlPrompt = false
    @State private var urlText = ""
    @State private var segment = 0
    @State private var share: URL?
    @State private var search = ""

    var filteredLibrary: [LibraryApp] {
        search.isEmpty ? state.library : state.library.filter { $0.name.localizedCaseInsensitiveContains(search) || $0.bundleID.localizedCaseInsensitiveContains(search) }
    }

    var filteredSigned: [SignedApp] {
        search.isEmpty ? state.signed : state.signed.filter { $0.name.localizedCaseInsensitiveContains(search) || $0.bundleID.localizedCaseInsensitiveContains(search) }
    }

    var body: some View {
        NavigationView {
            ScrollView {
                VStack(spacing: 14) {
                    header
                    Picker("", selection: $segment) {
                        Text(L("Imported")).tag(0)
                        Text(L("Signed apps")).tag(1)
                    }
                    .pickerStyle(.segmented)
                    ForEach(state.downloads) { d in
                        Card {
                            VStack(alignment: .leading, spacing: 8) {
                                HStack {
                                    Text(d.name).font(.subheadline.weight(.semibold)).lineLimit(1)
                                    Spacer()
                                    Text("\(Int(d.progress * 100))%").font(.caption.monospacedDigit()).foregroundColor(.secondary)
                                }
                                ProgressView(value: d.progress).tint(Theme.rose)
                                Text(d.status).font(.caption).foregroundColor(.secondary)
                            }
                        }
                    }
                    if segment == 0 {
                        if filteredLibrary.isEmpty && state.downloads.isEmpty {
                            EmptyState(title: L("No apps yet"), subtitle: L("Import an .ipa from Files, open one with SayoUnchained, or grab apps from a source."))
                        }
                        ForEach(filteredLibrary) { app in
                            LibraryRow(app: app)
                                .contextMenu {
                                    Button { state.pendingSign = app } label: { Label(L("Sign"), systemImage: "signature") }
                                    Button { Task { await state.addUnsigned(app) } } label: {
                                        Label(L("Install without re-signing"), systemImage: "arrow.down.app")
                                    }
                                    Button(role: .destructive) { state.deleteLibrary(app) } label: { Label(L("Delete"), systemImage: "trash") }
                                }
                        }
                    } else {
                        if filteredSigned.isEmpty {
                            EmptyState(title: L("Nothing signed yet"), subtitle: L("Signed apps appear here, ready to install or share."))
                        }
                        ForEach(filteredSigned) { app in
                            SignedRow(app: app, share: $share)
                                .contextMenu {
                                    Button { share = state.ipaURL(app) } label: { Label(L("Share IPA"), systemImage: "square.and.arrow.up") }
                                    Button(role: .destructive) { state.deleteSigned(app) } label: { Label(L("Delete"), systemImage: "trash") }
                                }
                        }
                    }
                }
                .padding(.horizontal, 16)
                .padding(.bottom, 30)
            }
            .background(Color(.systemGroupedBackground).ignoresSafeArea())
            .navigationTitle("SayoUnchained")
            .searchable(text: $search, prompt: L("Search apps"))
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Menu {
                        Button { importFromFiles() } label: { Label(L("Import from Files"), systemImage: "folder") }
                        Button { urlPrompt = true } label: { Label(L("Download from URL"), systemImage: "link") }
                    } label: {
                        Image(systemName: "plus.circle.fill").font(.title2).symbolRenderingMode(.hierarchical)
                    }
                }
            }
            .alert(L("Download from URL"), isPresented: $urlPrompt) {
                TextField("https://…/app.ipa", text: $urlText)
                Button(L("Cancel"), role: .cancel) {}
                Button(L("Download")) {
                    if let u = URL(string: urlText.trimmingCharacters(in: .whitespaces)), u.scheme != nil {
                        Task { await state.download(u, name: u.lastPathComponent) }
                        urlText = ""
                    } else {
                        state.show(L("Invalid URL"))
                    }
                }
            }
            .sheet(item: Binding(get: { share.map { ShareItem(url: $0) } }, set: { share = $0?.url })) { item in
                ShareSheet(items: [item.url])
            }
        }
        .navigationViewStyle(.stack)
    }

    var header: some View {
        HStack(spacing: 14) {
            ZStack {
                Circle().fill(Theme.gradient).frame(width: 52, height: 52)
                Bow().fill(Color.white).frame(width: 28, height: 24)
            }
            VStack(alignment: .leading, spacing: 3) {
                if let c = state.selectedCertificate {
                    Text(c.nickname).font(.headline).lineLimit(1)
                    HStack(spacing: 6) {
                        StatusDot(status: c.ocsp, expired: c.isExpired)
                        Text(headerDaysText(c)).font(.caption).foregroundColor(.secondary)
                    }
                } else {
                    Text(L("No certificate")).font(.headline)
                    Text(L("Add a .p12 or sign in with Apple ID")).font(.caption).foregroundColor(.secondary)
                }
            }
            Spacer()
            Button(L("Change")) { state.tab = 1 }.buttonStyle(SmallButtonStyle(filled: false))
        }
        .padding(14)
        .glassy()
        .padding(.top, 6)
    }

    /// Uses the same UIKit picker as every other flow; SwiftUI's .fileImporter loses
    /// the picked files here (see FilePicker.swift). An empty result means the picker
    /// could not be presented, which is reported instead of failing silently.
    func importFromFiles() {
        FilePicker.shared.pick([.ipa, .tipa, .zip, .data], multiple: true) { urls in
            if urls.isEmpty {
                state.show(L("The Files picker could not be opened"))
                return
            }
            Task { for u in urls { await state.importIPA(u) } }
        }
    }

    /// For an Apple ID certificate the number that matters is the soonest expiring
    /// app signed with it (free profiles die in days), not the certificate's own
    /// ~1 year. Without such an app, say plainly that the days are the certificate's.
    func headerDaysText(_ c: StoredCertificate) -> String {
        if c.fromAppleID {
            let soonest = state.signed
                .filter { $0.viaAppleID == true && $0.certificateName == c.nickname }
                .map { $0.effectiveExpiry }.min()
            if let soonest = soonest {
                let d = max(0, Calendar.current.dateComponents([.day], from: Date(), to: soonest).day ?? 0)
                return LF("Next app expires in %d days", d)
            }
            return LF("Certificate: %d days left", c.daysLeft)
        }
        return LF("%d days left", c.daysLeft)
    }
}

struct ShareItem: Identifiable {
    var id: String { url.path }
    let url: URL
}

struct StatusDot: View {
    let status: OCSPStatus
    let expired: Bool
    var color: Color {
        if expired { return .gray }
        switch status {
        case .good: return .green
        case .revoked: return .red
        default: return .orange
        }
    }
    var text: String {
        if expired { return L("Expired") }
        switch status {
        case .good: return L("Signed")
        case .revoked: return L("Revoked")
        case .unknown: return L("Unknown")
        case .unchecked: return L("Checking…")
        }
    }
    var body: some View {
        HStack(spacing: 4) {
            Circle().fill(color).frame(width: 8, height: 8)
            Text(text).font(.caption.weight(.semibold)).foregroundColor(color)
        }
    }
}

struct LibraryRow: View {
    @EnvironmentObject var state: AppState
    let app: LibraryApp
    var body: some View {
        Card {
            HStack(spacing: 12) {
                AppIconView(image: state.icon(for: app))
                VStack(alignment: .leading, spacing: 3) {
                    Text(app.name).font(.headline).lineLimit(1)
                    Text(app.bundleID).font(.caption).foregroundColor(.secondary).lineLimit(1)
                    HStack(spacing: 6) {
                        Pill(text: "v" + app.version)
                        Pill(text: formatSize(app.size), color: .secondary)
                        if app.encrypted { Pill(text: L("Encrypted"), color: .red) }
                    }
                }
                Spacer(minLength: 6)
                Button(L("Sign")) { state.pendingSign = app }.buttonStyle(SmallButtonStyle())
            }
        }
    }
}

struct SignedRow: View {
    @EnvironmentObject var state: AppState
    let app: SignedApp
    @Binding var share: URL?
    @State private var installing = false

    var body: some View {
        Card {
            HStack(spacing: 12) {
                AppIconView(image: app.libraryID.flatMap { id in state.library.first { $0.id == id } }.flatMap { state.icon(for: $0) })
                VStack(alignment: .leading, spacing: 3) {
                    Text(app.name).font(.headline).lineLimit(1)
                    Text(app.bundleID).font(.caption).foregroundColor(.secondary).lineLimit(1)
                    HStack(spacing: 6) {
                        Pill(text: "v" + app.version)
                        Pill(text: app.certificateName, color: .secondary)
                        if !app.tweaks.isEmpty { Pill(text: LF("%d tweaks", app.tweaks.count), color: .purple) }
                        if app.container == true { Pill(text: L("Inside SayoUnchained"), color: .teal) }
                    }
                }
                Spacer(minLength: 6)
                VStack(spacing: 6) {
                    if app.container == true {
                        Button { runInside() } label: { Text(L("Run")) }
                            .buttonStyle(SmallButtonStyle())
                    } else {
                        Button {
                            Task { await install() }
                        } label: {
                            if installing { ProgressView().tint(.white) } else { Text(L("Install")) }
                        }
                        .buttonStyle(SmallButtonStyle())
                    }
                    Button { share = state.ipaURL(app) } label: { Image(systemName: "square.and.arrow.up") }
                        .buttonStyle(SmallButtonStyle(filled: false))
                }
            }
        }
    }

    func runInside() {
        Task {
            state.busy = L("Preparing")
            defer { state.busy = nil }
            do {
                let appDir = try await Container.prepare(app, ipa: state.ipaURL(app))
                state.show(LF("%@ starts when you open SayoUnchained again", app.name))
                try Container.run(app, appDir: appDir)
            } catch {
                state.show(error.localizedDescription)
            }
        }
    }

    func install() async {
        installing = true
        defer { installing = false }
        await state.installSigned(app)
    }
}
