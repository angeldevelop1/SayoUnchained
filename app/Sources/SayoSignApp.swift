import SwiftUI
import UniformTypeIdentifiers

struct SayoSignApp: App {
    @StateObject private var state = AppState.shared
    @StateObject private var certImport = CertificateImportCoordinator.shared

    var body: some Scene {
        WindowGroup {
            RootView()
                .environmentObject(state)
                .environmentObject(certImport)
                .tint(Theme.rose)
                .preferredColorScheme(state.settings.appearance == 1 ? .light : state.settings.appearance == 2 ? .dark : nil)
                .onOpenURL { state.handleOpen($0) }
        }
    }
}

struct RootView: View {
    @EnvironmentObject var state: AppState
    @EnvironmentObject var certImport: CertificateImportCoordinator
    @Environment(\.scenePhase) var phase

    var body: some View {
        TabView(selection: $state.tab) {
            LibraryView()
                .tabItem { Label(L("Library"), systemImage: "square.stack.3d.up.fill") }
                .tag(0)
            CertificatesView()
                .tabItem { Label(L("Certificates"), systemImage: "checkmark.seal.fill") }
                .tag(1)
            SourcesView()
                .tabItem { Label(L("Sources"), systemImage: "globe") }
                .tag(2)
            SettingsView()
                .tabItem { Label(L("Settings"), systemImage: "gearshape.fill") }
                .tag(3)
            AppleIDAppsView()
                .tabItem { Label(L("Apple ID"), systemImage: "person.crop.circle.fill") }
                .tag(4)
        }
        .statusOverlay()
        .sheet(isPresented: $certImport.presented) {
            ImportCertificateView(prefillP12: certImport.p12, prefillProfile: certImport.profile)
                .environmentObject(state)
        }
        .sheet(item: $state.pendingSign, onDismiss: installPending) { app in
            SignView(app: app).environmentObject(state)
        }
        .sheet(isPresented: $state.needsInstallSetup) {
            InstallSetupView().environmentObject(state)
        }
        .onChange(of: phase) { p in
            if p == .active { Task { await state.scanInbox() } }
        }
        .task {
            if Diagnostics.enabled { await Diagnostics.run(state) }
            await state.scanInbox()
            if state.certificates.contains(where: { $0.ocspChecked == nil || $0.ocspChecked! < Date().addingTimeInterval(-3600) }) {
                await state.refreshAllOCSP()
            }
        }
    }

    /// The Sign sheet hands its freshly signed app over as it closes; the
    /// install runs here so its busy pill, toasts and setup sheet are visible.
    func installPending() {
        guard let app = state.pendingInstall else { return }
        state.pendingInstall = nil
        Task { await state.installSigned(app) }
    }
}

extension UTType {
    static let ipa = UTType(filenameExtension: "ipa") ?? .data
    static let tipa = UTType(filenameExtension: "tipa") ?? .data
    static let p12 = UTType(filenameExtension: "p12") ?? .data
    static let mobileprovision = UTType(filenameExtension: "mobileprovision") ?? .data
    static let deb = UTType(filenameExtension: "deb") ?? .data
    static let dylib = UTType(filenameExtension: "dylib") ?? .data
}
