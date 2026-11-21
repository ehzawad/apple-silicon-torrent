import Foundation

/// Pre-built bencode dictionary keys used by KRPC (avoids re-encoding strings per packet).
enum KRPCKey {
    static let t = Data("t".utf8)
    static let y = Data("y".utf8)
    static let q = Data("q".utf8)
    static let a = Data("a".utf8)
    static let r = Data("r".utf8)
    static let e = Data("e".utf8)
    static let v = Data("v".utf8)
    static let ip = Data("ip".utf8)
    static let ro = Data("ro".utf8)
    static let id = Data("id".utf8)
    static let target = Data("target".utf8)
    static let infoHash = Data("info_hash".utf8)
    static let token = Data("token".utf8)
    static let nodes = Data("nodes".utf8)
    static let nodes6 = Data("nodes6".utf8)
    static let values = Data("values".utf8)
    static let want = Data("want".utf8)
    static let port = Data("port".utf8)
    static let impliedPort = Data("implied_port".utf8)
}

/// KRPC error codes (BEP 5).
enum KRPCErrorCode {
    static let generic = 201
    static let server = 202
    static let protocolError = 203
    static let methodUnknown = 204
}

/// A DHT contact: node id + UDP endpoint.
struct DHTNodeInfo: Hashable, Sendable {
    var id: DHTID
    var addr: PeerAddress
}

/// "Compact node info" (BEP 5 / BEP 32): 20-byte id followed by the compact
/// endpoint — 26 bytes per IPv4 node, 38 bytes per IPv6 node.
enum CompactNodeInfo {
    static func stride(v6: Bool) -> Int { v6 ? 38 : 26 }

    /// Encode nodes of the requested family (others are skipped).
    static func encode(_ nodes: [DHTNodeInfo], v6: Bool) -> Data {
        var out = Data(capacity: nodes.count * stride(v6: v6))
        for n in nodes where n.addr.ip.isV6 == v6 {
            out.append(contentsOf: n.id.bytes)
            out.append(contentsOf: n.addr.compact)
        }
        return out
    }

    /// Decode a concatenated list; malformed / unusable entries are skipped and a
    /// trailing partial entry is ignored.
    static func decode(_ data: Data, v6: Bool) -> [DHTNodeInfo] {
        let s = stride(v6: v6)
        let b = [UInt8](data)
        guard b.count >= s else { return [] }
        var out: [DHTNodeInfo] = []
        out.reserveCapacity(b.count / s)
        var i = 0
        while i + s <= b.count {
            if let id = DHTID(bytes: Array(b[i..<(i + 20)])),
               let addr = PeerAddress(compact: b[(i + 20)..<(i + s)]),
               addr.ip.isV6 == v6, addr.port != 0, !addr.ip.isUnusable {
                out.append(DHTNodeInfo(id: id, addr: addr))
            }
            i += s
        }
        return out
    }
}

/// One KRPC message (BEP 5): a bencoded dictionary with `t` (transaction id),
/// `y` (q / r / e) and the body, plus the optional `v` (client version, BEP 5),
/// `ip` (requester's external endpoint, BEP 42) and `ro` (read-only, BEP 43) keys.
struct KRPCMessage: Equatable {
    enum Body: Equatable {
        case query(method: String, args: [Data: BValue])
        case response([Data: BValue])
        case error(code: Int, message: String)
    }

    var transactionID: Data
    var body: Body
    var version: Data?
    var yourIP: PeerAddress?
    var readOnly = false

    init(transactionID: Data, body: Body, version: Data? = nil, yourIP: PeerAddress? = nil, readOnly: Bool = false) {
        self.transactionID = transactionID
        self.body = body
        self.version = version
        self.yourIP = yourIP
        self.readOnly = readOnly
    }

    /// Parse a datagram. Returns nil for anything that is not a well-formed KRPC
    /// message (never throws, never traps).
    static func decode(_ data: Data) -> KRPCMessage? {
        guard data.first == UInt8(ascii: "d"), data.count <= 65_536 else { return nil }
        // Lenient about trailing bytes after the top-level dictionary.
        guard let (value, _) = try? BDecoder.decodePrefix(data), let d = value.dict else { return nil }
        guard let t = d[KRPCKey.t]?.data, t.count <= 64,
              let y = d[KRPCKey.y]?.data, y.count == 1, let kind = y.first else { return nil }
        let body: Body
        switch kind {
        case UInt8(ascii: "q"):
            guard let m = d[KRPCKey.q]?.data, !m.isEmpty, m.count <= 64 else { return nil }
            body = .query(method: String(decoding: m, as: UTF8.self), args: d[KRPCKey.a]?.dict ?? [:])
        case UInt8(ascii: "r"):
            guard let r = d[KRPCKey.r]?.dict else { return nil }
            body = .response(r)
        case UInt8(ascii: "e"):
            var code = KRPCErrorCode.generic
            var message = ""
            if let l = d[KRPCKey.e]?.list {
                for item in l {
                    if let c = item.int { code = Int(clamping: c) } else if let s = item.string { message = s }
                }
            } else if let s = d[KRPCKey.e]?.string {
                message = s
            }
            body = .error(code: code, message: message)
        default:
            return nil
        }
        var msg = KRPCMessage(transactionID: t, body: body)
        msg.version = d[KRPCKey.v]?.data
        if let ip = d[KRPCKey.ip]?.data, ip.count == 6 || ip.count == 18 { msg.yourIP = PeerAddress(compact: ip) }
        msg.readOnly = d[KRPCKey.ro]?.int == 1
        return msg
    }

    var encoded: Data {
        var d: [Data: BValue] = [KRPCKey.t: .bytes(transactionID)]
        switch body {
        case .query(let method, let args):
            d[KRPCKey.y] = .string("q")
            d[KRPCKey.q] = .string(method)
            d[KRPCKey.a] = .dict(args)
        case .response(let r):
            d[KRPCKey.y] = .string("r")
            d[KRPCKey.r] = .dict(r)
        case .error(let code, let message):
            d[KRPCKey.y] = .string("e")
            d[KRPCKey.e] = .list([.int(Int64(code)), .string(message)])
        }
        if let version { d[KRPCKey.v] = .bytes(version) }
        if let yourIP { d[KRPCKey.ip] = .bytes(Data(yourIP.compact)) }
        if readOnly { d[KRPCKey.ro] = .int(1) }
        return BValue.dict(d).encoded
    }

    // MARK: Accessors

    var isQuery: Bool { if case .query = body { return true }; return false }

    /// Arguments of a query or values of a response.
    var payload: [Data: BValue] {
        switch body {
        case .query(_, let a): return a
        case .response(let r): return r
        case .error: return [:]
        }
    }

    /// The sender's node id (`a.id` / `r.id`).
    var senderID: DHTID? { DHTID(payload[KRPCKey.id]?.data) }
}
