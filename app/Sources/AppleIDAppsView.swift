import SwiftUI

/// Apps signed with an Apple ID, with the countdown that actually decides whether
/// they still open: the provisioning profile's expiration (7 days for a free
/// account), not the development certificate's ~1 year shown elsewhere.
struct AppleIDAppsView: View {
    @EnvironmentObject var state: AppState

    var apps: [SignedApp] {
        state.signed.filter { $0.viaAppleID == true }.sorted { $0.signedAt > $1.signedAt }
    }

    var body: some View {
        NavigationView {
            ScrollView {
                VStack(spacing: 14) {
                    if apps.isEmpty {
                        EmptyState(title: L("No Apple ID apps yet"),
                                   subtitle: L("Apps you sign with a free Apple ID appear here with the countdown to their expiry."))
                    }
                    ForEach(apps) { app in
                        AppleIDAppRow(app: app)
                    }
                }
                .padding(.horizontal, 16)
                .padding(.bottom, 30)
                .padding(.top, 6)
            }
            .background(Color(.systemGroupedBackground).ignoresSafeArea())
            .navigationTitle(L("Apple ID"))
        }
        .navigationViewStyle(.stack)
    }
}

struct AppleIDAppRow: View {
    @EnvironmentObject var state: AppState
    let app: SignedApp

    var icon: UIImage? {
        app.libraryID.flatMap { id in state.library.first { $0.id == id } }.flatMap { state.icon(for: $0) }
    }

    var body: some View {
        // The countdown re-renders once a minute without any manual refreshing.
        TimelineView(.periodic(from: Date(), by: 60)) { context in
            content(now: context.date)
        }
    }

    func content(now: Date) -> some View {
        let expiry = app.effectiveExpiry
        let color = statusColor(expiry: expiry, now: now)
        return Card {
            VStack(alignment: .leading, spacing: 10) {
                HStack(spacing: 12) {
                    AppIconView(image: icon)
                    VStack(alignment: .leading, spacing: 3) {
                        Text(app.name).font(.headline).lineLimit(1)
                        Text(app.bundleID).font(.caption).foregroundColor(.secondary).lineLimit(1)
                        Text(LF("Signed %@", dateFormatter.string(from: app.signedAt)))
                            .font(.caption).foregroundColor(.secondary)
                    }
                    Spacer(minLength: 6)
                    Button(L("Re-sign")) { resign() }.buttonStyle(SmallButtonStyle())
                }
                ProgressView(value: remainingFraction(now: now)).tint(color)
                HStack {
                    Text(countdown(expiry: expiry, now: now)).font(.caption.weight(.semibold)).foregroundColor(color)
                    Spacer()
                    Text(LF("Expires %@", dateFormatter.string(from: expiry))).font(.caption).foregroundColor(.secondary)
                }
            }
        }
    }

    func statusColor(expiry: Date, now: Date) -> Color {
        let left = expiry.timeIntervalSince(now)
        if left <= 0 { return .gray }
        if left <= 24 * 3600 { return .red }
        if left <= 3 * 24 * 3600 { return .orange }
        return .green
    }

    func remainingFraction(now: Date) -> Double {
        let total = app.effectiveExpiry.timeIntervalSince(app.signedAt)
        guard total > 0 else { return 0 }
        return min(1, max(0, app.effectiveExpiry.timeIntervalSince(now) / total))
    }

    func countdown(expiry: Date, now: Date) -> String {
        let secs = Int(expiry.timeIntervalSince(now))
        if secs <= 0 { return L("Expired") }
        let days = secs / 86400
        let hours = (secs % 86400) / 3600
        if days > 0 { return LF("%d days, %d hours left", days, hours) }
        let minutes = (secs % 3600) / 60
        if hours > 0 { return LF("%d hours, %d minutes left", hours, minutes) }
        return LF("%d minutes left", max(minutes, 1))
    }

    /// Back to the sign flow for this app, with the Apple ID certificate it was
    /// signed with preselected; the sheet itself is presented by RootView.
    func resign() {
        guard let lib = app.libraryID.flatMap({ id in state.library.first { $0.id == id } }) else {
            state.show(L("The original app is no longer in the Library"))
            return
        }
        let cert = state.certificates.first { $0.fromAppleID && $0.nickname == app.certificateName }
            ?? state.certificates.first { $0.fromAppleID }
        if let cert = cert { state.settings.selectedCertificate = cert.id }
        state.tab = 0
        state.pendingSign = lib
    }
}
