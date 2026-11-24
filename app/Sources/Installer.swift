import AVFoundation
import Foundation
import Network
import Security
import UIKit

enum LocalCA {
    static let caTag = "dev.murk.sayosign.localca".data(using: .utf8)!
    static let leafTag = "dev.murk.sayosign.localhost".data(using: .utf8)!
    static let leafLabel = "SayoSign localhost"
    static var caFile: URL { Paths.support.appendingPathComponent("LocalCA.cer") }
    static var leafFile: URL { Paths.support.appendingPathComponent("localhost.cer") }

    static func key(tag: Data) -> SecKey? {
        let q: [String: Any] = [kSecClass as String: kSecClassKey,
                                kSecAttrApplicationTag as String: tag,
                                kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
                                kSecReturnRef as String: true]
        var out: CFTypeRef?
        guard SecItemCopyMatching(q as CFDictionary, &out) == errSecSuccess, let k = out else { return nil }
        return (k as! SecKey)
    }

    static func makeKey(tag: Data) throws -> SecKey {
        SecItemDelete([kSecClass as String: kSecClassKey, kSecAttrApplicationTag as String: tag] as CFDictionary)
        let attrs: [String: Any] = [kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
                                    kSecAttrKeySizeInBits as String: 2048,
                                    kSecPrivateKeyAttrs as String: [kSecAttrIsPermanent as String: true,
                                                                    kSecAttrApplicationTag as String: tag,
                                                                    kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly]]
        var err: Unmanaged<CFError>?
        guard let k = SecKeyCreateRandomKey(attrs as CFDictionary, &err) else {
            throw SayoError(L("Cannot create key") + ": " + (err?.takeRetainedValue().localizedDescription ?? ""))
        }
        return k
    }

    static func publicDER(_ key: SecKey) -> Data? {
        guard let pub = SecKeyCopyPublicKey(key) else { return nil }
        return SecKeyCopyExternalRepresentation(pub, nil) as Data?
    }

    static func sign(_ key: SecKey, _ data: Data) -> Data? {
        SecKeyCreateSignature(key, .rsaSignatureMessagePKCS1v15SHA256, data as CFData, nil) as Data?
    }

    static func buildCert(serial: UInt64, issuer: String, subject: String, days: Int, pub: Data, issuerPub: Data, ca: Bool,
                          dns: String?, ip: String?, signer: SecKey) -> Data? {
        let now = Int64(Date().timeIntervalSince1970)
        var tbs = sayo_buf()
        let rc = pub.withUnsafeBytes { p in
            issuerPub.withUnsafeBytes { ip2 in
                sayo_x509_tbs(serial, issuer, subject, "SayoSign", now - 86400, now + Int64(days) * 86400,
                              p.bindMemory(to: UInt8.self).baseAddress, pub.count,
                              ip2.bindMemory(to: UInt8.self).baseAddress, issuerPub.count,
                              ca ? 1 : 0, dns, ip, &tbs)
            }
        }
        guard rc == 0, let tp = tbs.data else { sayo_buf_free(&tbs); return nil }
        let tbsData = Data(bytes: tp, count: tbs.len)
        sayo_buf_free(&tbs)
        guard let sig = sign(signer, tbsData) else { return nil }
        var cert = sayo_buf()
        let frc = tbsData.withUnsafeBytes { t in
            sig.withUnsafeBytes { s in
                sayo_x509_finish(t.bindMemory(to: UInt8.self).baseAddress, tbsData.count,
                                 s.bindMemory(to: UInt8.self).baseAddress, sig.count, &cert)
            }
        }
        defer { sayo_buf_free(&cert) }
        guard frc == 0, let cp = cert.data else { return nil }
        return Data(bytes: cp, count: cert.len)
    }

    static var exists: Bool {
        FileManager.default.fileExists(atPath: caFile.path) && FileManager.default.fileExists(atPath: leafFile.path) &&
            key(tag: caTag) != nil && key(tag: leafTag) != nil
    }

    static func ensure() throws {
        if exists, let leaf = try? Data(contentsOf: leafFile), let d = SayoCore.certDetails(leaf), d.notAfter > Date().addingTimeInterval(86400 * 7) {
            return
        }
        let caKey: SecKey
        if let k = key(tag: caTag) {
            // The key survived: keep it, and rebuild the certificate file from it if that
            // is what went missing. Recreating the key would orphan the trust profile the
            // user already installed, and every OTA install would fail with no real error.
            caKey = k
            if !FileManager.default.fileExists(atPath: caFile.path) {
                guard let caPub = publicDER(caKey),
                      let caCert = buildCert(serial: UInt64(Date().timeIntervalSince1970), issuer: "SayoUnchained Local CA (\(UIDevice.current.name))",
                                             subject: "SayoUnchained Local CA (\(UIDevice.current.name))", days: 3650, pub: caPub, issuerPub: caPub,
                                             ca: true, dns: nil, ip: nil, signer: caKey) else {
                    throw SayoError(L("Cannot create local certificate authority"))
                }
                try caCert.write(to: caFile)
            }
        } else {
            caKey = try makeKey(tag: caTag)
            guard let caPub = publicDER(caKey),
                  let caCert = buildCert(serial: UInt64(Date().timeIntervalSince1970), issuer: "SayoUnchained Local CA (\(UIDevice.current.name))",
                                         subject: "SayoUnchained Local CA (\(UIDevice.current.name))", days: 3650, pub: caPub, issuerPub: caPub,
                                         ca: true, dns: nil, ip: nil, signer: caKey) else {
                throw SayoError(L("Cannot create local certificate authority"))
            }
            try caCert.write(to: caFile)
        }
        let caCert = try Data(contentsOf: caFile)
        guard let caPub = publicDER(caKey) else { throw SayoError(L("Cannot read CA key")) }
        let issuerName = SayoCore.certDetails(caCert)?.subject ?? "SayoUnchained Local CA"
        let leafKey = try makeKey(tag: leafTag)
        guard let leafPub = publicDER(leafKey),
              let leaf = buildCert(serial: UInt64(Date().timeIntervalSince1970) + 1, issuer: issuerName, subject: "localhost", days: 365,
                                   pub: leafPub, issuerPub: caPub, ca: false, dns: "localhost", ip: "127.0.0.1", signer: caKey) else {
            throw SayoError(L("Cannot create localhost certificate"))
        }
        try leaf.write(to: leafFile)
        SecItemDelete([kSecClass as String: kSecClassCertificate, kSecAttrLabel as String: leafLabel] as CFDictionary)
        guard let sc = SecCertificateCreateWithData(nil, leaf as CFData) else { throw SayoError(L("Invalid certificate")) }
        let st = SecItemAdd([kSecClass as String: kSecClassCertificate, kSecValueRef as String: sc,
                             kSecAttrLabel as String: leafLabel] as CFDictionary, nil)
        if st != errSecSuccess && st != errSecDuplicateItem { throw SayoError("Keychain error \(st)") }
    }

    static func identity() -> SecIdentity? {
        guard let leaf = try? Data(contentsOf: leafFile) else { return nil }
        let q: [String: Any] = [kSecClass as String: kSecClassIdentity,
                                kSecReturnRef as String: true,
                                kSecMatchLimit as String: kSecMatchLimitAll]
        var out: CFTypeRef?
        guard SecItemCopyMatching(q as CFDictionary, &out) == errSecSuccess, let arr = out as? [Any] else { return nil }
        for item in arr {
            let ident = item as! SecIdentity
            var c: SecCertificate?
            SecIdentityCopyCertificate(ident, &c)
            if let c = c, SecCertificateCopyData(c) as Data == leaf { return ident }
        }
        return nil
    }

    static func mobileconfig() -> Data? {
        guard let ca = try? Data(contentsOf: caFile) else { return nil }
        let inner: [String: Any] = ["PayloadType": "com.apple.security.root",
                                    "PayloadVersion": 1,
                                    "PayloadIdentifier": "dev.murk.sayosign.localca.cert",
                                    "PayloadUUID": UUID().uuidString,
                                    "PayloadDisplayName": "SayoUnchained Local CA",
                                    "PayloadDescription": "Lets SayoUnchained install apps from this iPhone. The private key never leaves the device.",
                                    "PayloadCertificateFileName": "SayoUnchainedLocalCA.cer",
                                    "PayloadContent": ca]
        let outer: [String: Any] = ["PayloadType": "Configuration",
                                    "PayloadVersion": 1,
                                    "PayloadIdentifier": "dev.murk.sayosign.localca",
                                    "PayloadUUID": UUID().uuidString,
                                    "PayloadDisplayName": "SayoUnchained Local Installer",
                                    "PayloadOrganization": "SayoUnchained",
                                    "PayloadDescription": "Trust for the on-device install server of SayoUnchained.",
                                    "PayloadRemovalDisallowed": false,
                                    "PayloadContent": [inner]]
        return try? PropertyListSerialization.data(fromPropertyList: outer, format: .xml, options: 0)
    }

    static func reset() {
        SecItemDelete([kSecClass as String: kSecClassKey, kSecAttrApplicationTag as String: caTag] as CFDictionary)
        SecItemDelete([kSecClass as String: kSecClassKey, kSecAttrApplicationTag as String: leafTag] as CFDictionary)
        SecItemDelete([kSecClass as String: kSecClassCertificate, kSecAttrLabel as String: leafLabel] as CFDictionary)
        try? FileManager.default.removeItem(at: caFile)
        try? FileManager.default.removeItem(at: leafFile)
    }
}

struct Served {
    var ipa: URL
    var bundleID: String
    var version: String
    var title: String
    var icon: Data?
    var token: String
}

final class InstallServer {
    static let shared = InstallServer()
    private var tls: NWListener?
    private var plain: NWListener?
    private let queue = DispatchQueue(label: "dev.murk.sayosign.server")
    private var served: Served?
    /// Recent installs, looked up by the token in each manifest's URLs: iOS may still be
    /// downloading the previous app when the next one is served, and it must get the bytes
    /// that belong to the manifest it read, not whatever was served last.
    private var recent: [Served] = []
    /// What iOS asked for during the last install, for Settings → Install log.
    private var events: [String] = []
    private var bytesSent: Int64 = 0

    func note(_ s: String) {
        let f = DateFormatter()
        f.dateFormat = "HH:mm:ss"
        let line = f.string(from: Date()) + "  " + s
        queue.async { self.events.append(line); if self.events.count > 60 { self.events.removeFirst() } }
    }
    func clearLog() { queue.sync { events = []; bytesSent = 0 } }
    func logLines() -> [String] { queue.sync { events } }
    private var port: UInt16 = 47616
    private var player: AVAudioPlayer?
    private var bgTask: UIBackgroundTaskIdentifier = .invalid
    /// keepAlive is shared by installs, pairing and UDID detection: it is reference
    /// counted so one flow finishing cannot pull the protection from another.
    private var keepAliveUsers = 0
    var onIPAFinished: (() -> Void)?

    var httpsBase: String { "https://localhost:\(port)" }
    var httpBase: String { "http://127.0.0.1:\(port + 1)" }

    func start(port: Int) throws {
        let p = UInt16(clamping: port)
        if tls != nil && plain != nil && p == self.port { return }
        stop()
        self.port = p
        try LocalCA.ensure()
        guard let ident = LocalCA.identity(), let secIdent = sec_identity_create(ident) else {
            throw SayoError(L("Local certificate is missing, reset the installer in Settings"))
        }
        let tlsOpts = NWProtocolTLS.Options()
        sec_protocol_options_set_local_identity(tlsOpts.securityProtocolOptions, secIdent)
        sec_protocol_options_set_min_tls_protocol_version(tlsOpts.securityProtocolOptions, .TLSv12)
        let tp = NWParameters(tls: tlsOpts, tcp: NWProtocolTCP.Options())
        tp.requiredInterfaceType = .loopback
        tp.allowLocalEndpointReuse = true
        let l1 = try NWListener(using: tp, on: NWEndpoint.Port(rawValue: p)!)
        l1.newConnectionHandler = { [weak self] c in self?.accept(c) }
        // A listener that fails to start (port busy) only says so here; without this the
        // failure is invisible and the install just dies at the relay.
        l1.stateUpdateHandler = { [weak self] state in
            if case .failed(let e) = state {
                self?.note("Install server (HTTPS) failed: \(e.localizedDescription)")
                self?.tls = nil
            }
        }
        l1.start(queue: queue)
        tls = l1
        let pp = NWParameters.tcp
        pp.requiredInterfaceType = .loopback
        pp.allowLocalEndpointReuse = true
        let l2 = try NWListener(using: pp, on: NWEndpoint.Port(rawValue: p + 1)!)
        l2.newConnectionHandler = { [weak self] c in self?.accept(c) }
        l2.stateUpdateHandler = { [weak self] state in
            if case .failed(let e) = state {
                self?.note("Install server (HTTP) failed: \(e.localizedDescription)")
                self?.plain = nil
            }
        }
        l2.start(queue: queue)
        plain = l2
    }

    /// Only the plain HTTP listener on 127.0.0.1: enough when the manifest comes from an
    /// HTTPS manifest service, and needs no certificate or profile.
    func startPlain(port: Int) throws {
        let p = UInt16(clamping: port)
        if plain != nil && p == self.port { return }
        stop()
        self.port = p
        let pp = NWParameters.tcp
        pp.requiredInterfaceType = .loopback
        pp.allowLocalEndpointReuse = true
        let l2 = try NWListener(using: pp, on: NWEndpoint.Port(rawValue: p + 1)!)
        l2.newConnectionHandler = { [weak self] c in self?.accept(c) }
        l2.stateUpdateHandler = { [weak self] state in
            if case .failed(let e) = state {
                self?.note("Install server (HTTP) failed: \(e.localizedDescription)")
                self?.plain = nil
            }
        }
        l2.start(queue: queue)
        plain = l2
    }

    func stop() {
        tls?.cancel()
        plain?.cancel()
        tls = nil
        plain = nil
    }

    func serve(_ s: Served) {
        queue.sync {
            served = s
            recent.removeAll { $0.token == s.token }
            recent.append(s)
            if recent.count > 3 { recent.removeFirst(recent.count - 3) }
        }
    }

    /// The app a request belongs to, by the token in its URL; requests without one (the
    /// UDID flow, the ping) get the most recently served app. Called on the server queue.
    private func served(for token: String?) -> Served? {
        if let token = token, !token.isEmpty, let s = recent.first(where: { $0.token == token }) { return s }
        return served
    }

    private func accept(_ c: NWConnection) {
        c.start(queue: queue)
        receive(c, buffer: Data())
    }

    private func receive(_ c: NWConnection, buffer: Data) {
        c.receive(minimumIncompleteLength: 1, maximumLength: 65536) { [weak self] data, _, done, err in
            guard let self = self else { return }
            var buf = buffer
            if let d = data { buf.append(d) }
            if let r = buf.range(of: Data("\r\n\r\n".utf8)) {
                let head = String(decoding: buf[..<r.lowerBound], as: UTF8.self)
                let body = buf[r.upperBound...]
                let length = head.components(separatedBy: "\r\n")
                    .first { $0.lowercased().hasPrefix("content-length:") }
                    .flatMap { Int($0.split(separator: ":", maxSplits: 1).last?.trimmingCharacters(in: .whitespaces) ?? "") } ?? 0
                if body.count >= min(length, 1 << 20) || done || err != nil {
                    self.handle(c, head: head, body: Data(body))
                    return
                }
            }
            if done || err != nil || buf.count > (1 << 20) + 65536 { c.cancel(); return }
            self.receive(c, buffer: buf)
        }
    }

    private func respond(_ c: NWConnection, status: String, type: String, body: Data, close: Bool = true) {
        var h = "HTTP/1.1 \(status)\r\nContent-Type: \(type)\r\nContent-Length: \(body.count)\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n"
        if type.contains("mobileconfig") { h = h.replacingOccurrences(of: "\r\n\r\n", with: "\r\nContent-Disposition: attachment; filename=\"SayoUnchained.mobileconfig\"\r\n\r\n") }
        var out = Data(h.utf8)
        out.append(body)
        c.send(content: out, completion: .contentProcessed { _ in if close { c.cancel() } })
    }

    private func handle(_ c: NWConnection, head: String, body: Data = Data()) {
        let first = head.components(separatedBy: "\r\n").first ?? ""
        let parts = first.split(separator: " ")
        guard parts.count >= 2 else { c.cancel(); return }
        let method = String(parts[0])
        var path = String(parts[1])
        var token: String?
        if let q = path.firstIndex(of: "?") {
            token = path[path.index(after: q)...].split(separator: "&").first { $0.hasPrefix("t=") }.map { String($0.dropFirst(2)) }
            path = String(path[..<q])
        }
        note("iOS → \(method) \(path)")
        switch path {
        case "/udid.mobileconfig":
            respond(c, status: "200 OK", type: "application/x-apple-aspen-config", body: InstallServer.udidProfile(base: httpsBase))
        case "/udid/receive":
            // iOS posts a signed plist with the device attributes (Profile Service).
            let text = String(decoding: body, as: UTF8.self)
            var udid: String?
            if let block = text.range(of: "<key>UDID</key>\\s*<string>[0-9A-Fa-f-]{20,50}</string>", options: .regularExpression) {
                let piece = String(text[block])
                if let v = piece.range(of: "[0-9A-Fa-f-]{20,50}(?=</string>)", options: .regularExpression) { udid = String(piece[v]) }
            }
            if let u = udid {
                note("UDID received")
                let to = "\(httpsBase)/udid/done?u=\(u)"
                let h = "HTTP/1.1 301 Moved Permanently\r\nLocation: \(to)\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                c.send(content: Data(h.utf8), completion: .contentProcessed { _ in c.cancel() })
                DispatchQueue.main.async { AppState.shared.handleOpen(URL(string: "sayosign://udid?value=\(u)")!) }
            } else {
                note("UDID: no UDID in the profile reply")
                respond(c, status: "400 Bad Request", type: "text/plain", body: Data("no UDID".utf8))
            }
        case "/udid/done":
            let q = head.components(separatedBy: "\r\n").first ?? ""
            let u = q.range(of: "[0-9A-Fa-f-]{20,50}", options: .regularExpression).map { String(q[$0]) } ?? ""
            let html = "<!doctype html><meta name=viewport content='width=device-width,initial-scale=1'><body style='font:17px -apple-system;text-align:center;padding:40px 20px;background:#111;color:#eee'><h2>UDID</h2><p style='word-break:break-all;font-family:monospace'>\(u)</p><p><a style='display:inline-block;padding:14px 28px;border-radius:14px;background:#e8506a;color:#fff;text-decoration:none' href='sayosign://udid?value=\(u)'>Open SayoUnchained</a></p><script>location.href='sayosign://udid?value=\(u)'</script>"
            respond(c, status: "200 OK", type: "text/html; charset=utf-8", body: Data(html.utf8))
        case "/ping":
            respond(c, status: "200 OK", type: "text/plain", body: Data("ok".utf8))
        case "/ca.mobileconfig":
            if let d = LocalCA.mobileconfig() {
                respond(c, status: "200 OK", type: "application/x-apple-aspen-config", body: d)
            } else {
                respond(c, status: "404 Not Found", type: "text/plain", body: Data())
            }
        case "/manifest.plist":
            guard let s = served(for: token) else { respond(c, status: "404 Not Found", type: "text/plain", body: Data()); return }
            respond(c, status: "200 OK", type: "text/xml", body: manifest(s))
        case "/icon.png":
            if let d = served(for: token)?.icon { respond(c, status: "200 OK", type: "image/png", body: d) }
            else if let d = UIImage(named: "Logo")?.pngData() { respond(c, status: "200 OK", type: "image/png", body: d) }
            else { respond(c, status: "404 Not Found", type: "text/plain", body: Data()) }
        case "/app.ipa":
            guard let s = served(for: token) else { respond(c, status: "404 Not Found", type: "text/plain", body: Data()); return }
            streamFile(c, url: s.ipa, head: method == "HEAD")
        default:
            respond(c, status: "404 Not Found", type: "text/plain", body: Data())
        }
    }

    private func manifest(_ s: Served) -> Data {
        let dict: [String: Any] = ["items": [[
            "assets": [["kind": "software-package", "url": "\(httpsBase)/app.ipa?t=\(s.token)"],
                       ["kind": "display-image", "url": "\(httpsBase)/icon.png?t=\(s.token)"],
                       ["kind": "full-size-image", "url": "\(httpsBase)/icon.png?t=\(s.token)"]],
            "metadata": ["bundle-identifier": s.bundleID, "bundle-version": s.version, "kind": "software", "title": s.title]
        ]]]
        return (try? PropertyListSerialization.data(fromPropertyList: dict, format: .xml, options: 0)) ?? Data()
    }

    private func streamFile(_ c: NWConnection, url: URL, head: Bool) {
        guard let h = try? FileHandle(forReadingFrom: url) else {
            respond(c, status: "404 Not Found", type: "text/plain", body: Data())
            return
        }
        let size = (try? FileManager.default.attributesOfItem(atPath: url.path)[.size] as? NSNumber)?.int64Value ?? 0
        bytesSent = 0
        note("IPA: sending \(size) bytes")
        let header = "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: \(size)\r\nConnection: close\r\n\r\n"
        // Cancel inside the send completion (as respond() does): cancelling synchronously
        // can win the race against the send and drop the headers before they leave.
        c.send(content: Data(header.utf8), completion: .contentProcessed { _ in if head { c.cancel() } })
        if head { try? h.close(); return }
        func pump() {
            let chunk = (try? h.read(upToCount: 1 << 18)) ?? Data()
            if chunk.isEmpty {
                note("IPA: all \(bytesSent) bytes sent")
                try? h.close()
                c.send(content: nil, contentContext: .finalMessage, isComplete: true, completion: .contentProcessed { [weak self] _ in
                    c.cancel()
                    DispatchQueue.main.async { self?.onIPAFinished?() }
                })
                return
            }
            c.send(content: chunk, completion: .contentProcessed { err in
                if let err = err {
                    self.note("IPA: stopped after \(self.bytesSent) bytes: \(err)")
                    try? h.close(); c.cancel(); return
                }
                self.bytesSent += Int64(chunk.count)
                pump()
            })
        }
        pump()
    }

    func keepAlive(_ on: Bool) {
        DispatchQueue.main.async {
            if on {
                self.keepAliveUsers += 1
                if self.bgTask == .invalid {
                    self.bgTask = UIApplication.shared.beginBackgroundTask(withName: "install") { [weak self] in
                        if let t = self?.bgTask { UIApplication.shared.endBackgroundTask(t) }
                        self?.bgTask = .invalid
                    }
                }
                guard AppState.shared.settings.keepAliveAudio, self.player == nil else { return }
                // The silent audio is what actually keeps the server alive in the
                // background: if it does not start, say so in the install log instead
                // of letting a long download be cut off in silence.
                do {
                    try AVAudioSession.sharedInstance().setCategory(.playback, options: [.mixWithOthers])
                    try AVAudioSession.sharedInstance().setActive(true)
                    let p = try AVAudioPlayer(data: InstallServer.silentWAV())
                    p.numberOfLoops = -1
                    p.volume = 0
                    p.play()
                    self.player = p
                    if !p.isPlaying { self.note("Keep-alive audio did not start; long installs may be cut off") }
                } catch {
                    self.note("Keep-alive audio failed: \(error.localizedDescription)")
                }
            } else {
                self.keepAliveUsers = max(0, self.keepAliveUsers - 1)
                guard self.keepAliveUsers == 0 else { return }
                self.player?.stop()
                self.player = nil
                try? AVAudioSession.sharedInstance().setActive(false, options: [.notifyOthersOnDeactivation])
                if self.bgTask != .invalid {
                    UIApplication.shared.endBackgroundTask(self.bgTask)
                    self.bgTask = .invalid
                }
            }
        }
    }

    /// Profile Service request: iOS sends this iPhone's UDID to SayoSign's own server.
    static func udidProfile(base: String) -> Data {
        let content: [String: Any] = ["URL": "\(base)/udid/receive", "DeviceAttributes": ["UDID", "PRODUCT"]]
        let p: [String: Any] = ["PayloadContent": content, "PayloadOrganization": "SayoUnchained",
                                "PayloadDisplayName": "SayoUnchained UDID",
                                "PayloadDescription": "Sends this iPhone's UDID to the SayoUnchained app on this iPhone. Nothing is installed.",
                                "PayloadIdentifier": "dev.murk.sayosign.udid", "PayloadUUID": UUID().uuidString,
                                "PayloadType": "Profile Service", "PayloadVersion": 1]
        return (try? PropertyListSerialization.data(fromPropertyList: p, format: .xml, options: 0)) ?? Data()
    }

    static func silentWAV() -> Data {
        let rate: UInt32 = 8000
        let samples: UInt32 = rate
        var d = Data()
        func u32(_ v: UInt32) { var x = v.littleEndian; d.append(Data(bytes: &x, count: 4)) }
        func u16(_ v: UInt16) { var x = v.littleEndian; d.append(Data(bytes: &x, count: 2)) }
        d.append(Data("RIFF".utf8)); u32(36 + samples * 2); d.append(Data("WAVE".utf8))
        d.append(Data("fmt ".utf8)); u32(16); u16(1); u16(1); u32(rate); u32(rate * 2); u16(2); u16(16)
        d.append(Data("data".utf8)); u32(samples * 2)
        d.append(Data(count: Int(samples) * 2))
        return d
    }
}

enum Installer {
    static func trusted(port: Int) async -> Bool {
        guard let u = URL(string: "https://localhost:\(port)/ping") else { return false }
        // The listener was started a moment ago and NWListener comes up asynchronously:
        // a single immediate ping can lose that race and report a healthy setup as
        // missing, so retry a few times before concluding anything.
        for attempt in 0..<5 {
            if attempt > 0 { try? await Task.sleep(nanoseconds: 400_000_000) }
            var r = URLRequest(url: u)
            r.timeoutInterval = 4
            let s = URLSession(configuration: .ephemeral)
            let ok = (try? await s.data(for: r)).map { (d, resp) in
                (resp as? HTTPURLResponse)?.statusCode == 200 && String(decoding: d, as: UTF8.self) == "ok"
            } ?? false
            s.invalidateAndCancel()
            if ok { return true }
        }
        return false
    }

    static func bundleInfo(ipa: URL, fallbackID: String, fallbackVersion: String) -> (String, String) {
        (fallbackID, fallbackVersion)
    }

    /// The manifest service base URL, or nil when installs go through the local HTTPS server.
    @MainActor
    static func manifestService(_ state: AppState) -> URL? {
        var s = state.settings.manifestService.trimmingCharacters(in: .whitespacesAndNewlines)
        if s.isEmpty { return nil }
        if !s.contains("://") { s = "https://" + s }
        guard let u = URL(string: s), u.scheme == "https" else { return nil }
        return u
    }

    /// Whether this app goes through the pairing tunnel instead of an over-the-air install.
    @MainActor
    static func usesPairing(_ app: SignedApp, state: AppState) -> Bool {
        switch state.settings.installMethod {
        case 1: return false
        case 2: return true
        default: return app.viaAppleID == true && DeviceLink.isPaired
        }
    }

    /// Installs the app. Returns true when it is already installed (pairing tunnel), false when
    /// iOS now shows its own install prompt (over the air).
    @MainActor
    @discardableResult
    static func install(_ app: SignedApp, state: AppState) async throws -> Bool {
        // iOS refuses to replace the app that is serving the install ("Unable to install").
        // This happens when SayoSign itself was signed with the same explicit-ID profile.
        if let own = Bundle.main.bundleIdentifier, own.caseInsensitiveCompare(app.bundleID) == .orderedSame {
            throw SayoError(LF("This app got SayoUnchained's own bundle ID (%@), so installing it would replace SayoUnchained and iOS refuses. Sign SayoUnchained with another certificate, or use an Apple ID or a wildcard certificate for this app.", own))
        }
        // Automatic mode must never send a free Apple ID app down the OTA route when this
        // iPhone is not paired: iOS creates the Home Screen placeholder from the manifest
        // and then refuses the development-profile package, leaving a dead icon and no
        // error anywhere. A method the user picked explicitly stays as chosen.
        if app.viaAppleID == true, state.settings.installMethod != 1, state.settings.installMethod != 2, !DeviceLink.isPaired {
            throw SayoError(L("Apps signed with a free Apple ID cannot be installed over the air. Pair this iPhone first (Settings → Install method → Pair this iPhone), keep LocalDevVPN connected, and install again."))
        }
        if usesPairing(app, state: state) {
            state.busy = L("Connecting to this iPhone")
            defer { state.busy = nil }
            try await DeviceLink.install(ipa: state.ipaURL(app), address: state.settings.tunnelAddress, port: 49152) { pct, stage in
                switch stage {
                case "tunnel": state.busy = L("Connecting to this iPhone")
                case "upload": state.busy = L("Uploading")
                case "install": state.busy = LF("Installing %d%%", pct)
                default: break
                }
            }
            return true
        }
        let server = InstallServer.shared
        let service = manifestService(state)
        // The package must travel over HTTPS too: iOS refuses an http:// package even
        // when the manifest itself came from an HTTPS service, so the full local server
        // (with its trusted certificate) runs in both cases.
        try server.start(port: state.settings.serverPort)
        if !(await trusted(port: state.settings.serverPort)) {
            throw InstallNeedsSetup()
        }
        let token = UUID().uuidString.prefix(8)
        var iconData: Data?
        var version = app.version
        if let lib = app.libraryID.flatMap({ id in state.library.first { $0.id == id } }) {
            if let img = state.icon(for: lib) { iconData = img.pngData() }
            // An app without CFBundleShortVersionString would put an empty
            // bundle-version in the manifest, which iOS can refuse outright.
            if version.isEmpty { version = lib.build }
        }
        server.serve(Served(ipa: state.ipaURL(app), bundleID: app.bundleID, version: version, title: app.name,
                            icon: iconData, token: String(token)))
        server.keepAlive(true)
        var keepAliveOff = false
        let endKeepAlive = {
            if keepAliveOff { return }
            keepAliveOff = true
            server.keepAlive(false)
        }
        server.onIPAFinished = {
            DispatchQueue.main.asyncAfter(deadline: .now() + 20) { endKeepAlive() }
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + 600) { endKeepAlive() }
        var manifest = "\(server.httpsBase)/manifest.plist?t=\(token)"
        if let base = service {
            // The service only turns these parameters into the manifest iOS asks for;
            // the IPA itself still comes straight from this iPhone, over HTTPS.
            let strict = CharacterSet(charactersIn: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
            func q(_ v: String) -> String { v.addingPercentEncoding(withAllowedCharacters: strict) ?? "" }
            let params = [("url", "\(server.httpsBase)/app.ipa?t=\(token)"), ("id", app.bundleID),
                          ("v", version), ("name", app.name)]
            let query = params.map { "\($0.0)=\(q($0.1))" }.joined(separator: "&")
            var b = base.absoluteString
            while b.hasSuffix("/") { b.removeLast() }
            manifest = b + "/?" + query
        }
        server.clearLog()
        server.note(service != nil ? "Manifest from \(service!.host ?? "service"), IPA over \(server.httpsBase)" : "Manifest from local HTTPS server")
        let enc = manifest.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed.subtracting(CharacterSet(charactersIn: "&=?"))) ?? manifest
        guard let u = URL(string: "itms-services://?action=download-manifest&url=\(enc)") else { return false }
        await UIApplication.shared.open(u)
        // An OTA install reports nothing back. If iOS never comes for the IPA, the user
        // is left with a dead placeholder and no explanation, so check the server log
        // once, after a generous window, and say so.
        DispatchQueue.main.asyncAfter(deadline: .now() + 90) {
            if !InstallServer.shared.logLines().contains(where: { $0.contains("/app.ipa") }) {
                AppState.shared.show(L("iOS did not download the app. If it does not appear on the Home Screen, the install failed — see Settings → Install log."))
            }
        }
        return false
    }

    static func openTrollStore(_ ipa: URL) -> Bool {
        guard let u = URL(string: "apple-magnifier://install?url=" + (ipa.absoluteString.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? "")),
              UIApplication.shared.canOpenURL(u) else { return false }
        UIApplication.shared.open(u)
        return true
    }
}

struct InstallNeedsSetup: LocalizedError {
    var errorDescription: String? { L("The local installer needs a one-time setup") }
}
