import Foundation

/// Stateless BEP 14 (Local Service Discovery) wire encoder and parser.
enum LSDWire {
    static let multicastIPv4 = "239.192.152.143"
    static let multicastIPv6 = "ff15::efc0:988f"
    static let multicastPort: UInt16 = 6771
    static let hostHeaderV4 = "\(multicastIPv4):\(multicastPort)"
    static let hostHeaderV6 = "[\(multicastIPv6)]:\(multicastPort)"

    /// BEP 14 recommends keeping each announce packet small (at most ~5 infohashes).
    static let maxHashesPerPacket = 5
    /// BEP 14 rate limit: at most 1 announce per torrent per 5 minutes.
    static let minAnnounceInterval: Double = 300.0

    struct Message: Sendable, Equatable {
        let host: String
        let port: UInt16
        let infoHashes: [Data]
        let cookie: String?
    }

    /// Encode a BEP 14 `BT-SEARCH` announce datagram (terminated with `\r\n\r\n\r\n` per BEP 14).
    /// Returns empty `Data` if `port == 0` or no valid 20-byte infohashes are provided.
    static func encode(host: String, port: UInt16, infoHashes: [Data], cookie: String?) -> Data {
        let validHashes = infoHashes.filter { $0.count == 20 }
        guard port > 0, !validHashes.isEmpty else { return Data() }
        let cleanHost = stripCRLF(host)
        guard !cleanHost.isEmpty else { return Data() }

        var msg = "BT-SEARCH * HTTP/1.1\r\n"
        msg += "Host: \(cleanHost)\r\n"
        msg += "Port: \(port)\r\n"
        for hash in validHashes.prefix(maxHashesPerPacket) {
            msg += "Infohash: \(hash.hex)\r\n"
        }
        if let cookie {
            let cleanCookie = stripCRLF(cookie)
            if !cleanCookie.isEmpty {
                msg += "cookie: \(cleanCookie)\r\n"
            }
        }
        // BEP 14 specifies two trailing CRLFs after the final CRLF-terminated header.
        msg += "\r\n\r\n"
        return Data(msg.utf8)
    }

    /// Parse a BEP 14 `BT-SEARCH` announce datagram.
    /// Accepts `\r\n\r\n` and BEP 14 `\r\n\r\n\r\n`, LF-only line endings, stray `\r`, and case-insensitive headers.
    static func parse(_ data: Data) -> Message? {
        guard !data.isEmpty, data.count <= 8192,
              let text = String(data: data, encoding: .utf8) ?? String(data: data, encoding: .isoLatin1) else {
            return nil
        }

        // Collapse \r\n and any stray \r (e.g. \r\r\n) before splitting headers cleanly.
        let normalized = text
            .replacingOccurrences(of: "\r\n", with: "\n")
            .replacingOccurrences(of: "\r", with: "")
        let lines = normalized.split(separator: "\n", omittingEmptySubsequences: false)
        guard let firstLine = lines.first else { return nil }
        let reqParts = firstLine.trimmingCharacters(in: .whitespaces).split(separator: " ", omittingEmptySubsequences: true)
        let httpVer = reqParts.count == 3 ? reqParts[2].uppercased() : ""
        guard reqParts.count == 3,
              reqParts[0] == "BT-SEARCH",
              reqParts[1] == "*",
              (httpVer == "HTTP/1.1" || httpVer == "HTTP/1.0") else {
            return nil
        }

        var host: String?
        var port: UInt16?
        var cookie: String?
        var hashes: [Data] = []
        var seenHashes = Set<Data>()
        var sawTerminatingBlankLine = false

        for line in lines.dropFirst() {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.isEmpty {
                sawTerminatingBlankLine = true
                break
            }
            guard let colon = trimmed.firstIndex(of: ":") else { continue }
            let name = trimmed[..<colon].trimmingCharacters(in: .whitespaces).lowercased()
            let value = trimmed[trimmed.index(after: colon)...].trimmingCharacters(in: .whitespaces)
            switch name {
            case "host":
                if !value.isEmpty { host = value }
            case "port":
                if let p = UInt16(value), p > 0 { port = p }
            case "infohash":
                if value.count == 40, let h = Data(hex: value), h.count == 20, seenHashes.insert(h).inserted {
                    hashes.append(h)
                }
            case "cookie":
                if !value.isEmpty { cookie = value }
            default:
                break
            }
        }

        guard sawTerminatingBlankLine,
              let validHost = host,
              let validPort = port,
              !hashes.isEmpty else {
            return nil
        }
        return Message(host: validHost, port: validPort, infoHashes: hashes, cookie: cookie)
    }

    private static func stripCRLF(_ s: String) -> String {
        s.replacingOccurrences(of: "\r", with: "").replacingOccurrences(of: "\n", with: "")
    }
}
