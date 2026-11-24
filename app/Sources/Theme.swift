import SwiftUI
import UIKit

enum Theme {
    static let coral = Color(red: 0.94, green: 0.34, blue: 0.43)
    static let rose = Color(red: 0.86, green: 0.27, blue: 0.37)
    static let peach = Color(red: 1.0, green: 0.70, blue: 0.65)
    static let cream = Color(red: 1.0, green: 0.96, blue: 0.93)
    static let ribbon = Color(red: 0.87, green: 0.18, blue: 0.27)
    // Near-flat fills for a clean, ESign-style look (no heavy gradients).
    static let gradient = LinearGradient(colors: [coral, rose], startPoint: .top, endPoint: .bottom)
    static let soft = LinearGradient(colors: [coral.opacity(0.14), coral.opacity(0.10)], startPoint: .top, endPoint: .bottom)
}

struct Bow: Shape {
    func path(in r: CGRect) -> Path {
        var p = Path()
        let w = r.width, h = r.height
        let c = CGPoint(x: r.midX, y: r.minY + h * 0.38)
        p.move(to: c)
        p.addCurve(to: CGPoint(x: r.minX, y: r.minY + h * 0.08), control1: CGPoint(x: r.minX + w * 0.32, y: r.minY - h * 0.05), control2: CGPoint(x: r.minX + w * 0.05, y: r.minY - h * 0.05))
        p.addCurve(to: c, control1: CGPoint(x: r.minX - w * 0.04, y: r.minY + h * 0.55), control2: CGPoint(x: r.minX + w * 0.25, y: r.minY + h * 0.75))
        p.addCurve(to: CGPoint(x: r.maxX, y: r.minY + h * 0.08), control1: CGPoint(x: r.maxX - w * 0.32, y: r.minY - h * 0.05), control2: CGPoint(x: r.maxX - w * 0.05, y: r.minY - h * 0.05))
        p.addCurve(to: c, control1: CGPoint(x: r.maxX + w * 0.04, y: r.minY + h * 0.55), control2: CGPoint(x: r.maxX - w * 0.25, y: r.minY + h * 0.75))
        p.move(to: c)
        p.addLine(to: CGPoint(x: r.minX + w * 0.28, y: r.maxY))
        p.addLine(to: CGPoint(x: r.minX + w * 0.40, y: r.maxY - h * 0.08))
        p.addLine(to: c)
        p.addLine(to: CGPoint(x: r.maxX - w * 0.28, y: r.maxY))
        p.addLine(to: CGPoint(x: r.maxX - w * 0.40, y: r.maxY - h * 0.08))
        p.closeSubpath()
        p.addEllipse(in: CGRect(x: c.x - w * 0.09, y: c.y - h * 0.11, width: w * 0.18, height: h * 0.22))
        return p
    }
}

struct Card<Content: View>: View {
    let content: Content
    init(@ViewBuilder _ content: () -> Content) { self.content = content() }
    var body: some View {
        content
            .padding(15)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(
                RoundedRectangle(cornerRadius: 14, style: .continuous)
                    .fill(Color(.secondarySystemGroupedBackground))
                    .overlay(RoundedRectangle(cornerRadius: 14, style: .continuous).stroke(Color.primary.opacity(0.06), lineWidth: 0.5))
            )
    }
}

struct AppIconView: View {
    let image: UIImage?
    var url: String? = nil
    var size: CGFloat = 54
    var body: some View {
        Group {
            if let image = image {
                Image(uiImage: image).resizable()
            } else if let s = url, let u = URL(string: s), !s.isEmpty {
                AsyncImage(url: u) { phase in
                    if let img = phase.image { img.resizable() } else { placeholder }
                }
            } else {
                placeholder
            }
        }
        .frame(width: size, height: size)
        .clipShape(RoundedRectangle(cornerRadius: size * 0.225, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: size * 0.225, style: .continuous).stroke(Color.primary.opacity(0.08), lineWidth: 0.5))
    }

    var placeholder: some View {
        ZStack {
            Theme.gradient
            Bow().fill(Color.white.opacity(0.9)).padding(size * 0.22)
        }
    }
}

struct Pill: View {
    let text: String
    var color: Color = Theme.coral
    var body: some View {
        Text(text)
            .font(.caption2.weight(.semibold))
            .padding(.horizontal, 8)
            .padding(.vertical, 3)
            .background(Capsule().fill(color.opacity(0.16)))
            .foregroundColor(color)
    }
}

struct PrimaryButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.headline)
            .foregroundColor(.white)
            .frame(maxWidth: .infinity)
            .padding(.vertical, 14)
            .background(RoundedRectangle(cornerRadius: 13, style: .continuous).fill(Theme.coral))
            .opacity(configuration.isPressed ? 0.82 : 1)
            .animation(.easeOut(duration: 0.15), value: configuration.isPressed)
    }
}

struct SmallButtonStyle: ButtonStyle {
    var filled = true
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.subheadline.weight(.bold))
            .foregroundColor(filled ? .white : Theme.rose)
            .padding(.horizontal, 14)
            .padding(.vertical, 7)
            .background(RoundedRectangle(cornerRadius: 9, style: .continuous).fill(filled ? AnyShapeStyle(Theme.coral) : AnyShapeStyle(Theme.coral.opacity(0.14))))
            .opacity(configuration.isPressed ? 0.82 : 1)
    }
}

struct EmptyState: View {
    let title: String
    let subtitle: String
    var body: some View {
        VStack(spacing: 14) {
            Bow().fill(Theme.gradient).frame(width: 74, height: 64)
            Text(title).font(.title3.weight(.bold))
            Text(subtitle).font(.subheadline).foregroundColor(.secondary).multilineTextAlignment(.center)
        }
        .padding(32)
        .frame(maxWidth: .infinity)
    }
}

struct ToastView: View {
    let text: String
    var body: some View {
        HStack(spacing: 10) {
            Bow().fill(Color.white).frame(width: 18, height: 16)
            Text(text).font(.subheadline.weight(.semibold)).foregroundColor(.white).lineLimit(3)
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 12)
        .background(Capsule().fill(Theme.gradient).shadow(color: Theme.rose.opacity(0.35), radius: 14, y: 6))
        .padding(.horizontal, 20)
    }
}

/// The root view's toast and busy pill as a reusable overlay. A sheet renders
/// above the root view, so status shown only there stays hidden behind
/// whichever sheet is open; sheets that give status feedback apply this too.
struct StatusOverlay: ViewModifier {
    @EnvironmentObject var state: AppState

    func body(content: Content) -> some View {
        ZStack(alignment: .top) {
            content
            if let t = state.toast {
                ToastView(text: t)
                    .transition(.move(edge: .top).combined(with: .opacity))
                    .padding(.top, 8)
                    .onTapGesture { state.toast = nil }
                    .zIndex(10)
            }
            if let b = state.busy {
                HStack(spacing: 10) {
                    ProgressView()
                    Text(b).font(.subheadline.weight(.semibold))
                }
                .padding(.horizontal, 18)
                .padding(.vertical, 12)
                .glassy()
                .padding(.top, 8)
                .zIndex(9)
            }
        }
        .animation(.spring(response: 0.4, dampingFraction: 0.8), value: state.toast)
    }
}

struct ShareSheet: UIViewControllerRepresentable {
    let items: [Any]
    func makeUIViewController(context: Context) -> UIActivityViewController {
        UIActivityViewController(activityItems: items, applicationActivities: nil)
    }
    func updateUIViewController(_ vc: UIActivityViewController, context: Context) {}
}

extension View {
    func statusOverlay() -> some View { modifier(StatusOverlay()) }

    @ViewBuilder func glassy() -> some View {
        #if compiler(>=6.2)
        if #available(iOS 26.0, *) {
            self.glassEffect(.regular.tint(Theme.coral.opacity(0.15)), in: RoundedRectangle(cornerRadius: 20, style: .continuous))
        } else {
            self.background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 20, style: .continuous))
        }
        #else
        self.background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 20, style: .continuous))
        #endif
    }
}

let dateFormatter: DateFormatter = {
    let f = DateFormatter()
    f.dateStyle = .medium
    f.timeStyle = .none
    return f
}()
