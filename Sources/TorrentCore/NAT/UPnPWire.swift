import Foundation

// MARK: - SSDP (UPnP Device Architecture 1.0 / 1.1)

/// Stateless SSDP M-SEARCH encoder and HTTP/UDP response parser.
enum SSDPWire {
    static let multicastIP = "239.255.255.250"
    static let multicastPort: UInt16 = 1900

    static let primarySearchTargets: [String] = [
        "urn:schemas-upnp-org:device:InternetGatewayDevice:2",
        "urn:schemas-upnp-org:device:InternetGatewayDevice:1",
    ]

    static let fallbackSearchTargets: [String] = [
        "urn:schemas-upnp-org:service:WANIPConnection:2",
        "urn:schemas-upnp-org:service:WANIPConnection:1",
        "urn:schemas-upnp-org:service:WANPPPConnection:2",
        "urn:schemas-upnp-org:service:WANPPPConnection:1",
    ]

    struct Response: Sendable, Equatable {
        let location: URL
        let st: String?
        let usn: String?
        let server: String?
        let headers: [String: String]
    }

    static func encodeMSearch(st: String, mx: Int = 2) -> Data {
        let cleanST = stripLineBreaks(st)
        let msg = "M-SEARCH * HTTP/1.1\r\n"
            + "HOST: \(multicastIP):\(multicastPort)\r\n"
            + "MAN: \"ssdp:discover\"\r\n"
            + "MX: \(mx)\r\n"
            + "ST: \(cleanST)\r\n"
            + "\r\n"
        return Data(msg.utf8)
    }

    /// Parse an SSDP unicast response (`HTTP/1.1 200 OK\r\n...`).
    static func parseResponse(_ data: Data) -> Response? {
        guard let text = String(data: data, encoding: .utf8) ?? String(data: data, encoding: .isoLatin1) else {
            return nil
        }
        // Normalize CRLF and strip stray bare CR (e.g. embedded routers emitting \r\r\n).
        let normalized = text
            .replacingOccurrences(of: "\r\n", with: "\n")
            .replacingOccurrences(of: "\r", with: "")
        let lines = normalized.split(separator: "\n", omittingEmptySubsequences: false)
        guard let statusLine = lines.first else { return nil }
        let statusParts = statusLine.trimmingCharacters(in: .whitespaces).split(separator: " ", maxSplits: 2)
        let version = statusParts.first?.uppercased()
        guard statusParts.count >= 2,
              (version == "HTTP/1.1" || version == "HTTP/1.0"),
              statusParts[1] == "200" else {
            return nil
        }

        var headers: [String: String] = [:]
        for line in lines.dropFirst() {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.isEmpty { break }
            guard let colon = trimmed.firstIndex(of: ":") else { continue }
            let name = trimmed[..<colon].trimmingCharacters(in: .whitespaces).lowercased()
            let value = trimmed[trimmed.index(after: colon)...].trimmingCharacters(in: .whitespaces)
            if !name.isEmpty {
                headers[name] = value
            }
        }

        guard let locStr = headers["location"],
              let url = URL(string: locStr),
              let scheme = url.scheme?.lowercased(),
              (scheme == "http" || scheme == "https"),
              let host = url.host, !host.isEmpty else {
            return nil
        }

        return Response(
            location: url,
            st: headers["st"],
            usn: headers["usn"],
            server: headers["server"],
            headers: headers
        )
    }

    /// True if `url` uses `http`/`https` and points to a private/link-local LAN IP address
    /// (prevents a spoofed SSDP response or malicious `rootDesc.xml` from redirecting HTTP
    /// requests to external internet hosts, local files, or localhost services).
    static func isSafeLocationURL(_ url: URL, allowLoopback: Bool = false) -> Bool {
        guard let scheme = url.scheme?.lowercased(),
              (scheme == "http" || scheme == "https"),
              var host = url.host, !host.isEmpty else {
            return false
        }
        // Strip IPv6 zone identifier (%25en0 or %en0) if present.
        if let pct = host.firstIndex(of: "%") {
            host = String(host[..<pct])
        }
        guard let ip = IPAddress(host), !ip.isUnusable else { return false }
        if ip.isLoopback { return allowLoopback }
        return ip.isPrivate
    }
}

// MARK: - UPnP IGD rootDesc.xml Parser

struct UPnPService: Sendable, Equatable {
    let serviceType: String
    let controlURL: URL
    let priority: Int

    /// Supported IGD port-mapping service types in preference order (v2 before v1, IP before PPP).
    static let supportedServicePriorities: [String: Int] = [
        "urn:schemas-upnp-org:service:wanipconnection:2": 0,
        "urn:schemas-upnp-org:service:wanipconnection:1": 1,
        "urn:schemas-upnp-org:service:wanpppconnection:2": 2,
        "urn:schemas-upnp-org:service:wanpppconnection:1": 3,
    ]
}

enum UPnPRootDescriptionParser {
    /// Parse a UPnP `rootDesc.xml` document and extract supported IGD connection services
    /// (`WANIPConnection:2`, `WANIPConnection:1`, `WANPPPConnection:2`, `WANPPPConnection:1`),
    /// sorted by preference. Rejects unsafe `<URLBase>` or `<controlURL>` targets (SSRF protection).
    static func parse(_ xmlData: Data, locationURL: URL, allowLoopback: Bool = false) -> [UPnPService] {
        let delegate = RootDescDelegate()
        let parser = XMLParser(data: xmlData)
        // Keep shouldProcessNamespaces = false and strip prefixes ourselves so routers with
        // undeclared XML prefixes still parse cleanly.
        parser.shouldProcessNamespaces = false
        parser.delegate = delegate
        guard parser.parse() else { return [] }

        let baseURL: URL
        if let rawBase = delegate.urlBase?.trimmingCharacters(in: .whitespacesAndNewlines),
           !rawBase.isEmpty,
           let parsedBase = URL(string: rawBase),
           SSDPWire.isSafeLocationURL(parsedBase, allowLoopback: allowLoopback) {
            baseURL = parsedBase
        } else {
            baseURL = locationURL
        }

        var services: [UPnPService] = []
        var seen = Set<String>()
        for entry in delegate.rawServices {
            let st = entry.serviceType.trimmingCharacters(in: .whitespacesAndNewlines)
            let ctrl = entry.controlURL.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !st.isEmpty, !ctrl.isEmpty,
                  let prio = UPnPService.supportedServicePriorities[st.lowercased()],
                  let resolved = resolveControlURL(ctrl, base: baseURL),
                  SSDPWire.isSafeLocationURL(resolved, allowLoopback: allowLoopback) else {
                continue
            }
            let dedupKey = "\(st.lowercased())|\(resolved.absoluteString)"
            if seen.insert(dedupKey).inserted {
                services.append(UPnPService(serviceType: st, controlURL: resolved, priority: prio))
            }
        }
        return services.sorted { $0.priority < $1.priority }
    }

    static func resolveControlURL(_ controlURL: String, base: URL) -> URL? {
        if let direct = URL(string: controlURL), direct.scheme != nil {
            guard direct.host != nil else { return nil }
            return direct
        }
        return URL(string: controlURL, relativeTo: base)?.absoluteURL
    }

    private final class RootDescDelegate: NSObject, XMLParserDelegate {
        struct RawService {
            var serviceType = ""
            var controlURL = ""
        }

        var urlBase: String?
        var rawServices: [RawService] = []

        private var stack: [String] = []
        private var textStack: [String] = []
        private var serviceDepth: Int?
        private var currentServiceType = ""
        private var currentControlURL = ""

        func parser(_ parser: XMLParser, didStartElement elementName: String,
                    namespaceURI: String?, qualifiedName qName: String?,
                    attributes attributeDict: [String: String] = [:]) {
            let local = localElementName(elementName).lowercased()
            stack.append(local)
            textStack.append("")
            // Only enter a <service> when directly inside <serviceList> and not already inside a service.
            if local == "service", serviceDepth == nil,
               stack.count >= 2, stack[stack.count - 2] == "servicelist" {
                serviceDepth = stack.count
                currentServiceType = ""
                currentControlURL = ""
            }
        }

        func parser(_ parser: XMLParser, foundCharacters string: String) {
            guard !textStack.isEmpty else { return }
            textStack[textStack.count - 1] += string
        }

        func parser(_ parser: XMLParser, foundCDATA CDATABlock: Data) {
            guard !textStack.isEmpty, let s = String(data: CDATABlock, encoding: .utf8) else { return }
            textStack[textStack.count - 1] += s
        }

        func parser(_ parser: XMLParser, didEndElement elementName: String,
                    namespaceURI: String?, qualifiedName qName: String?) {
            let local = localElementName(elementName).lowercased()
            let text = textStack.popLast() ?? ""
            let depth = stack.count

            if stack == ["root", "urlbase"], urlBase == nil {
                urlBase = text
            } else if let sDepth = serviceDepth {
                if depth == sDepth + 1 {
                    switch local {
                    case "servicetype":
                        currentServiceType = text
                    case "controlurl":
                        currentControlURL = text
                    default:
                        break
                    }
                } else if depth == sDepth && local == "service" {
                    rawServices.append(RawService(serviceType: currentServiceType, controlURL: currentControlURL))
                    serviceDepth = nil
                }
            }
            if !stack.isEmpty { stack.removeLast() }
        }
    }
}

// MARK: - UPnP SOAP Envelopes & Parsers

enum UPnPSOAPError: Error, Sendable, Equatable, CustomStringConvertible {
    case fault(code: Int, description: String)
    case httpError(Int)
    case invalidResponse(String)
    case noExternalAddress

    var description: String {
        switch self {
        case .fault(let code, let desc):
            return desc.isEmpty ? "UPnP error \(code)" : "UPnP error \(code): \(desc)"
        case .httpError(let status):
            return "UPnP HTTP \(status)"
        case .invalidResponse(let msg):
            return "UPnP invalid response: \(msg)"
        case .noExternalAddress:
            return "UPnP returned no usable external IP"
        }
    }
}

enum UPnPSOAP {
    /// Well-known UPnP IGD SOAP error codes.
    static let errorConflictInMappingEntry = 718
    static let errorOnlyPermanentLeasesSupported = 725

    struct Request: Sendable, Equatable {
        let soapAction: String
        let body: Data
    }

    static func escapeXML(_ s: String) -> String {
        var out = ""
        out.reserveCapacity(s.count)
        for ch in s {
            switch ch {
            case "&": out += "&amp;"
            case "<": out += "&lt;"
            case ">": out += "&gt;"
            case "\"": out += "&quot;"
            case "'": out += "&apos;"
            default: out.append(ch)
            }
        }
        return out
    }

    static func buildGetExternalIPAddress(serviceType: String) -> Request {
        let action = "GetExternalIPAddress"
        let cleanST = sanitizeHeaderToken(serviceType)
        let escapedST = escapeXML(cleanST)
        // Explicit closing tag for compatibility with legacy router XML parsers.
        let xml = """
        <?xml version="1.0" encoding="utf-8"?>\r
        <s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">\r
        <s:Body><u:\(action) xmlns:u="\(escapedST)"></u:\(action)></s:Body>\r
        </s:Envelope>
        """
        return Request(soapAction: "\"\(cleanST)#\(action)\"", body: Data(xml.utf8))
    }

    static func buildAddPortMapping(
        serviceType: String,
        remoteHost: String = "",
        externalPort: UInt16,
        proto: PortProtocol,
        internalPort: UInt16,
        internalClient: String,
        enabled: Bool = true,
        description: String = "Astor",
        leaseDuration: UInt32 = 3600
    ) -> Request {
        buildPortMappingAction(
            action: "AddPortMapping",
            serviceType: serviceType,
            remoteHost: remoteHost,
            externalPort: externalPort,
            proto: proto,
            internalPort: internalPort,
            internalClient: internalClient,
            enabled: enabled,
            description: description,
            leaseDuration: leaseDuration
        )
    }

    /// IGD v2 (`WANIPConnection:2`) action that assigns an available external port on conflict.
    static func buildAddAnyPortMapping(
        serviceType: String,
        remoteHost: String = "",
        externalPort: UInt16,
        proto: PortProtocol,
        internalPort: UInt16,
        internalClient: String,
        enabled: Bool = true,
        description: String = "Astor",
        leaseDuration: UInt32 = 3600
    ) -> Request {
        buildPortMappingAction(
            action: "AddAnyPortMapping",
            serviceType: serviceType,
            remoteHost: remoteHost,
            externalPort: externalPort,
            proto: proto,
            internalPort: internalPort,
            internalClient: internalClient,
            enabled: enabled,
            description: description,
            leaseDuration: leaseDuration
        )
    }

    private static func buildPortMappingAction(
        action: String,
        serviceType: String,
        remoteHost: String,
        externalPort: UInt16,
        proto: PortProtocol,
        internalPort: UInt16,
        internalClient: String,
        enabled: Bool,
        description: String,
        leaseDuration: UInt32
    ) -> Request {
        let cleanST = sanitizeHeaderToken(serviceType)
        let escapedST = escapeXML(cleanST)
        let xml = """
        <?xml version="1.0" encoding="utf-8"?>\r
        <s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">\r
        <s:Body><u:\(action) xmlns:u="\(escapedST)">\
        <NewRemoteHost>\(escapeXML(remoteHost))</NewRemoteHost>\
        <NewExternalPort>\(externalPort)</NewExternalPort>\
        <NewProtocol>\(proto.name)</NewProtocol>\
        <NewInternalPort>\(internalPort)</NewInternalPort>\
        <NewInternalClient>\(escapeXML(internalClient))</NewInternalClient>\
        <NewEnabled>\(enabled ? "1" : "0")</NewEnabled>\
        <NewPortMappingDescription>\(escapeXML(description))</NewPortMappingDescription>\
        <NewLeaseDuration>\(leaseDuration)</NewLeaseDuration>\
        </u:\(action)></s:Body>\r
        </s:Envelope>
        """
        return Request(soapAction: "\"\(cleanST)#\(action)\"", body: Data(xml.utf8))
    }

    static func buildDeletePortMapping(
        serviceType: String,
        remoteHost: String = "",
        externalPort: UInt16,
        proto: PortProtocol
    ) -> Request {
        let action = "DeletePortMapping"
        let cleanST = sanitizeHeaderToken(serviceType)
        let escapedST = escapeXML(cleanST)
        let xml = """
        <?xml version="1.0" encoding="utf-8"?>\r
        <s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">\r
        <s:Body><u:\(action) xmlns:u="\(escapedST)">\
        <NewRemoteHost>\(escapeXML(remoteHost))</NewRemoteHost>\
        <NewExternalPort>\(externalPort)</NewExternalPort>\
        <NewProtocol>\(proto.name)</NewProtocol>\
        </u:\(action)></s:Body>\r
        </s:Envelope>
        """
        return Request(soapAction: "\"\(cleanST)#\(action)\"", body: Data(xml.utf8))
    }

    static func parseGetExternalIPAddressResponse(_ xmlData: Data, statusCode: Int = 200) -> Result<IPAddress, UPnPSOAPError> {
        let parsed = parseSOAPElements(xmlData)
        if let fault = parsed.fault {
            return .failure(.fault(code: fault.code, description: fault.description))
        }
        guard (200..<300).contains(statusCode) else {
            return .failure(.httpError(statusCode))
        }
        guard parsed.ok, parsed.isSOAPEnvelope else {
            return .failure(.invalidResponse("malformed SOAP XML"))
        }
        guard let rawIP = parsed.bodyValues["newexternalipaddress"]?.trimmingCharacters(in: .whitespacesAndNewlines),
              !rawIP.isEmpty,
              let ip = IPAddress(rawIP),
              !ip.isUnusable else {
            return .failure(.noExternalAddress)
        }
        return .success(ip)
    }

    static func parseAddPortMappingResponse(_ xmlData: Data, statusCode: Int = 200) -> Result<Void, UPnPSOAPError> {
        let parsed = parseSOAPElements(xmlData)
        if let fault = parsed.fault {
            return .failure(.fault(code: fault.code, description: fault.description))
        }
        guard (200..<300).contains(statusCode) else {
            return .failure(.httpError(statusCode))
        }
        guard parsed.ok, parsed.isSOAPEnvelope,
              parsed.seenBodyElements.contains("addportmappingresponse") || parsed.seenElements.contains("body") else {
            return .failure(.invalidResponse("invalid SOAP AddPortMapping response"))
        }
        return .success(())
    }

    static func parseAddAnyPortMappingResponse(_ xmlData: Data, statusCode: Int = 200) -> Result<UInt16, UPnPSOAPError> {
        let parsed = parseSOAPElements(xmlData)
        if let fault = parsed.fault {
            return .failure(.fault(code: fault.code, description: fault.description))
        }
        guard (200..<300).contains(statusCode) else {
            return .failure(.httpError(statusCode))
        }
        guard parsed.ok, parsed.isSOAPEnvelope,
              let rawPort = parsed.bodyValues["newreservedport"]?.trimmingCharacters(in: .whitespacesAndNewlines),
              let port = UInt16(rawPort), port > 0 else {
            return .failure(.invalidResponse("missing NewReservedPort"))
        }
        return .success(port)
    }

    static func parseDeletePortMappingResponse(_ xmlData: Data, statusCode: Int = 200) -> Result<Void, UPnPSOAPError> {
        let parsed = parseSOAPElements(xmlData)
        if let fault = parsed.fault {
            return .failure(.fault(code: fault.code, description: fault.description))
        }
        guard (200..<300).contains(statusCode) else {
            return .failure(.httpError(statusCode))
        }
        guard parsed.ok, parsed.isSOAPEnvelope,
              parsed.seenBodyElements.contains("deleteportmappingresponse") || parsed.seenElements.contains("body") else {
            return .failure(.invalidResponse("invalid SOAP DeletePortMapping response"))
        }
        return .success(())
    }

    private struct SOAPParseResult {
        var ok: Bool
        var isSOAPEnvelope: Bool
        var seenElements: Set<String>
        var seenBodyElements: Set<String>
        var bodyValues: [String: String]
        var fault: (code: Int, description: String)?
    }

    private static func parseSOAPElements(_ xmlData: Data) -> SOAPParseResult {
        guard !xmlData.isEmpty else {
            return SOAPParseResult(ok: false, isSOAPEnvelope: false, seenElements: [], seenBodyElements: [], bodyValues: [:], fault: nil)
        }
        let delegate = SOAPDelegate()
        let parser = XMLParser(data: xmlData)
        parser.shouldProcessNamespaces = false
        parser.delegate = delegate
        let ok = parser.parse()

        var fault: (code: Int, description: String)?
        if delegate.sawFault {
            if let codeStr = delegate.faultValues["errorcode"], let code = Int(codeStr) {
                let desc = delegate.faultValues["errordescription"] ?? ""
                fault = (code, desc)
            } else {
                let desc = delegate.faultValues["faultstring"] ?? "SOAP Fault"
                fault = (-1, desc)
            }
        }
        let isEnvelope = delegate.seenElements.contains("envelope")
        return SOAPParseResult(
            ok: ok,
            isSOAPEnvelope: isEnvelope,
            seenElements: delegate.seenElements,
            seenBodyElements: delegate.seenBodyElements,
            bodyValues: delegate.bodyValues,
            fault: fault
        )
    }

    private final class SOAPDelegate: NSObject, XMLParserDelegate {
        var seenElements: Set<String> = []
        var seenBodyElements: Set<String> = []
        var bodyValues: [String: String] = [:]
        var faultValues: [String: String] = [:]
        var sawFault = false

        private var stack: [String] = []
        private var textStack: [String] = []
        private var bodyDepth: Int?
        private var faultDepth: Int?

        func parser(_ parser: XMLParser, didStartElement elementName: String,
                    namespaceURI: String?, qualifiedName qName: String?,
                    attributes attributeDict: [String: String] = [:]) {
            let local = localElementName(elementName).lowercased()
            stack.append(local)
            textStack.append("")
            seenElements.insert(local)
            if local == "body", bodyDepth == nil {
                bodyDepth = stack.count
            } else if bodyDepth != nil {
                seenBodyElements.insert(local)
            }
            if (local == "fault" || local == "upnperror"), faultDepth == nil {
                sawFault = true
                faultDepth = stack.count
            }
        }

        func parser(_ parser: XMLParser, foundCharacters string: String) {
            guard !textStack.isEmpty else { return }
            textStack[textStack.count - 1] += string
        }

        func parser(_ parser: XMLParser, foundCDATA CDATABlock: Data) {
            guard !textStack.isEmpty, let s = String(data: CDATABlock, encoding: .utf8) else { return }
            textStack[textStack.count - 1] += s
        }

        func parser(_ parser: XMLParser, didEndElement elementName: String,
                    namespaceURI: String?, qualifiedName qName: String?) {
            let local = localElementName(elementName).lowercased()
            let text = (textStack.popLast() ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
            let depth = stack.count

            if !text.isEmpty {
                if faultDepth != nil {
                    if faultValues[local] == nil {
                        faultValues[local] = text
                    }
                } else if bodyDepth != nil {
                    if bodyValues[local] == nil {
                        bodyValues[local] = text
                    }
                }
            }

            if let fDepth = faultDepth, depth == fDepth {
                faultDepth = nil
            }
            if let bDepth = bodyDepth, depth == bDepth {
                bodyDepth = nil
            }
            if !stack.isEmpty { stack.removeLast() }
        }
    }
}

@inline(__always)
private func localElementName(_ name: String) -> String {
    if let idx = name.lastIndex(of: ":") {
        return String(name[name.index(after: idx)...])
    }
    return name
}

private func stripLineBreaks(_ s: String) -> String {
    s.replacingOccurrences(of: "\r", with: "").replacingOccurrences(of: "\n", with: "")
}

private func sanitizeHeaderToken(_ s: String) -> String {
    stripLineBreaks(s).replacingOccurrences(of: "\"", with: "")
}
