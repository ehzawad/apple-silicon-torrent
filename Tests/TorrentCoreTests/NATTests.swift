import Testing
import Foundation
import Darwin
@testable import TorrentCore

// MARK: - Offline Wire Format, XML, SOAP & Route-Table Tests

@Suite struct NATWireTests {

    // MARK: PCP (RFC 6887)

    @Test func pcpEncodeMapRequestIPv4() {
        let clientIP = IPAddress("192.168.1.106")!
        let nonce = Data([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C])
        let pkt = PCPWire.encodeMapRequest(
            clientIP: clientIP,
            nonce: nonce,
            proto: .tcp,
            internalPort: 51413,
            suggestedExternalPort: 51413,
            suggestedExternalIP: nil,
            lifetime: 3600
        )

        #expect(pkt.count == 60)
        #expect(pkt.byte(0) == 2)       // Version 2
        #expect(pkt.byte(1) == 1)       // R=0 | Opcode=1 (MAP)
        #expect(pkt.be16(2) == 0)       // Reserved
        #expect(pkt.be32(4) == 3600)    // Lifetime
        #expect(Array(pkt[8..<24]) == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 192, 168, 1, 106])
        #expect(Data(pkt[24..<36]) == nonce)
        #expect(pkt.byte(36) == 6)      // IANA TCP
        #expect(Array(pkt[37..<40]) == [0, 0, 0])
        #expect(pkt.be16(40) == 51413)
        #expect(pkt.be16(42) == 51413)
        #expect(Array(pkt[44..<60]) == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 0, 0, 0, 0])

        // Delete request (UDP, lifetime=0, suggested port=0)
        let del = PCPWire.encodeMapRequest(
            clientIP: clientIP,
            nonce: nonce,
            proto: .udp,
            internalPort: 51413,
            suggestedExternalPort: 0,
            suggestedExternalIP: nil,
            lifetime: 0
        )
        #expect(del.count == 60)
        #expect(del.be32(4) == 0)
        #expect(del.byte(36) == 17)     // IANA UDP
        #expect(del.be16(40) == 51413)
        #expect(del.be16(42) == 0)
    }

    @Test func pcpEncodeMapRequestIPv6UnspecifiedAndExplicit() {
        let clientV6 = IPAddress("2001:db8::42")!
        let extV4 = IPAddress("203.0.113.7")!
        let nonce = Data(repeating: 0xAA, count: 12)

        // When client is IPv6 and suggestedExternalIP is nil, RFC 6887 §11.1/§15.1 requires `::` (16 zero bytes)
        let v6Default = PCPWire.encodeMapRequest(
            clientIP: clientV6,
            nonce: nonce,
            proto: .tcp,
            internalPort: 6881,
            suggestedExternalPort: 0,
            suggestedExternalIP: nil,
            lifetime: 0
        )
        #expect(v6Default.count == 60)
        #expect(Array(v6Default[8..<24]) == clientV6.bytes)
        #expect(Array(v6Default[44..<60]) == [UInt8](repeating: 0, count: 16))

        // Explicit IPv4 suggestedExternalIP encodes as ::ffff:a.b.c.d
        let withV4 = PCPWire.encodeMapRequest(
            clientIP: clientV6,
            nonce: nonce,
            proto: .udp,
            internalPort: 6881,
            suggestedExternalPort: 6881,
            suggestedExternalIP: extV4,
            lifetime: 7200
        )
        #expect(Array(withV4[44..<60]) == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 203, 0, 113, 7])
    }

    @Test func pcpDecodeMapResponseAndOptionsValidation() {
        let nonce = Data([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12])
        func baseMapResp() -> Data {
            var resp = Data()
            resp.append(2)
            resp.append(0x80 | 1)
            resp.append(0)
            resp.append(0)
            resp.appendBE32(3600)
            resp.appendBE32(98765)
            resp.append(Data(count: 12))
            resp.append(nonce)
            resp.append(6)
            resp.append(contentsOf: [0, 0, 0])
            resp.appendBE16(51413)
            resp.appendBE16(51414)
            resp.append(contentsOf: PCPWire.encodeAddress(IPAddress("203.0.113.7")!))
            return resp
        }

        // Valid optional PCP option (code 128 >= 128, length 4, 4 data bytes)
        var withValidOpt = baseMapResp()
        withValidOpt.append(contentsOf: [128, 0, 0, 4, 0, 0, 0, 0])
        #expect(PCPWire.decodeResponse(withValidOpt) == .map(PCPWire.MapResponse(
            lifetime: 3600,
            epoch: 98765,
            nonce: nonce,
            proto: .tcp,
            internalPort: 51413,
            externalPort: 51414,
            externalAddress: IPAddress("203.0.113.7")!
        )))

        // Malformed option (length overflows packet) -> MUST reject
        var withTruncOpt = baseMapResp()
        withTruncOpt.append(contentsOf: [128, 0, 0xFF, 0xFF, 0, 0, 0, 0])
        #expect(PCPWire.decodeResponse(withTruncOpt) == nil)

        // Unrequested mandatory-to-process option (code 1 < 128) -> MUST reject
        var withMandatoryOpt = baseMapResp()
        withMandatoryOpt.append(contentsOf: [1, 0, 0, 4, 0, 0, 0, 0])
        #expect(PCPWire.decodeResponse(withMandatoryOpt) == nil)
    }

    @Test func pcpDecodeErrorsAndAllRFC6887FallbackForms() {
        // 24-byte PCP v2 UNSUPP_VERSION error
        var pcpErr = Data()
        pcpErr.append(contentsOf: [2, 0x81, 0, PCPResultCode.unsuppVersion.rawValue])
        pcpErr.appendBE32(0)
        pcpErr.appendBE32(1234)
        pcpErr.append(Data(count: 12))
        #expect(PCPWire.decodeResponse(pcpErr) == .error(
            opcode: 1,
            resultCode: PCPResultCode.unsuppVersion.rawValue,
            lifetime: 0,
            epoch: 1234,
            nonce: nil,
            proto: nil,
            internalPort: nil
        ))

        // Draft PCP v1 UNSUPP_VERSION reply
        var pcpV1Err = pcpErr
        pcpV1Err[0] = 1
        #expect(PCPWire.decodeResponse(pcpV1Err) == .error(
            opcode: 1,
            resultCode: PCPResultCode.unsuppVersion.rawValue,
            lifetime: 0,
            epoch: 1234,
            nonce: nil,
            proto: nil,
            internalPort: nil
        ))

        // Strictly RFC 6886 §3.5 compliant NAT-PMP v0 UNSUPP_VERSION reply: OP = 0 (R bit = 0)!
        var v0Strict = Data([0, 0x00])
        v0Strict.appendBE16(NATPMPResultCode.unsupportedVersion.rawValue)
        v0Strict.appendBE32(42)
        #expect(PCPWire.decodeResponse(v0Strict) == .natpmpUnsupportedVersion(opcode: 0, epoch: 42))

        // MiniUPnPd style NAT-PMP v0 UNSUPP_VERSION reply: OP = 0x81 (R bit = 1)
        var v0Mini = Data([0, 0x81])
        v0Mini.appendBE16(NATPMPResultCode.unsupportedVersion.rawValue)
        v0Mini.appendBE32(555)
        #expect(PCPWire.decodeResponse(v0Mini) == .natpmpUnsupportedVersion(opcode: 1, epoch: 555))

        // Reject invalid packets
        #expect(PCPWire.decodeResponse(Data([2, 0x01, 0, 0])) == nil)
        var reqBitZero = Data(count: 60)
        reqBitZero[0] = 2; reqBitZero[1] = 1
        #expect(PCPWire.decodeResponse(reqBitZero) == nil)
        var notMult4 = Data(count: 61)
        notMult4[0] = 2; notMult4[1] = 0x81
        #expect(PCPWire.decodeResponse(notMult4) == nil)
    }

    // MARK: NAT-PMP (RFC 6886)

    @Test func natpmpEncodeAndDecode() {
        #expect(NATPMPWire.encodeExternalAddressRequest() == Data([0x00, 0x00]))

        let udpReq = NATPMPWire.encodeMapRequest(proto: .udp, internalPort: 6881, suggestedExternalPort: 6881, lifetime: 3600)
        #expect(udpReq.count == 12)
        #expect(udpReq.byte(0) == 0)
        #expect(udpReq.byte(1) == 1)
        #expect(udpReq.be16(2) == 0)
        #expect(udpReq.be16(4) == 6881)
        #expect(udpReq.be16(6) == 6881)
        #expect(udpReq.be32(8) == 3600)

        let tcpDel = NATPMPWire.encodeMapRequest(proto: .tcp, internalPort: 6881, suggestedExternalPort: 0, lifetime: 0)
        #expect(tcpDel.count == 12)
        #expect(tcpDel.byte(1) == 2)
        #expect(tcpDel.be16(6) == 0)
        #expect(tcpDel.be32(8) == 0)

        // Exact 12-byte external address response
        var extResp = Data([0, 0x80])
        extResp.appendBE16(0)
        extResp.appendBE32(42000)
        extResp.append(contentsOf: [203, 0, 113, 7])
        #expect(NATPMPWire.decodeResponse(extResp) == .externalAddress(NATPMPWire.ExternalAddressResponse(
            resultCode: 0,
            epoch: 42000,
            externalAddress: IPAddress("203.0.113.7")!
        )))
        // Trailing garbage rejected
        #expect(NATPMPWire.decodeResponse(extResp + Data([0x99])) == nil)

        // Exact 16-byte TCP map response
        var mapResp = Data([0, 0x82])
        mapResp.appendBE16(0)
        mapResp.appendBE32(42001)
        mapResp.appendBE16(51413)
        mapResp.appendBE16(51413)
        mapResp.appendBE32(3600)
        #expect(NATPMPWire.decodeResponse(mapResp) == .map(NATPMPWire.MapResponse(
            proto: .tcp,
            resultCode: 0,
            epoch: 42001,
            internalPort: 51413,
            externalPort: 51413,
            lifetime: 3600
        )))
        #expect(NATPMPWire.decodeResponse(mapResp + Data([0x00])) == nil)

        // RFC 6886 §3.5 OP=0 UNSUPPORTED_VERSION (R bit = 0)
        var unsupp = Data([0, 0x00])
        unsupp.appendBE16(NATPMPResultCode.unsupportedVersion.rawValue)
        unsupp.appendBE32(77)
        #expect(NATPMPWire.decodeResponse(unsupp) == .error(opcode: 0, resultCode: 1, epoch: 77))

        // 8-byte NAT-PMP error response (NOT_AUTHORIZED)
        var errResp = Data([0, 0x81])
        errResp.appendBE16(NATPMPResultCode.notAuthorized.rawValue)
        errResp.appendBE32(100)
        #expect(NATPMPWire.decodeResponse(errResp) == .error(opcode: 1, resultCode: 2, epoch: 100))

        // Unknown opcode with result=0 -> MUST return nil
        var unknownOK = Data([0, 0x83])
        unknownOK.appendBE16(0)
        unknownOK.appendBE32(100)
        #expect(NATPMPWire.decodeResponse(unknownOK) == nil)

        // Reject malformed
        #expect(NATPMPWire.decodeResponse(Data([0, 0x80, 0, 0])) == nil)
        #expect(NATPMPWire.decodeResponse(Data([1, 0x80, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4])) == nil)
        #expect(NATPMPWire.decodeResponse(Data([0, 0x00, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4])) == nil)
    }

    // MARK: SSDP

    @Test func ssdpEncodeParseAndSafety() {
        let req = SSDPWire.encodeMSearch(st: "urn:schemas-upnp-org:device:InternetGatewayDevice:1", mx: 2)
        let reqText = String(decoding: req, as: UTF8.self)
        #expect(reqText.hasPrefix("M-SEARCH * HTTP/1.1\r\n"))
        #expect(reqText.contains("HOST: 239.255.255.250:1900\r\n"))
        #expect(reqText.contains("MAN: \"ssdp:discover\"\r\n"))
        #expect(reqText.contains("MX: 2\r\n"))
        #expect(reqText.contains("ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n"))
        #expect(reqText.hasSuffix("\r\n\r\n"))

        // Typical MiniUPnPd SSDP response
        let rawResp = """
        HTTP/1.1 200 OK\r
        CACHE-CONTROL: max-age=120\r
        ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r
        USN: uuid:60550722-6ec2-4431-8fd7-c5ebe272be56::urn:schemas-upnp-org:device:InternetGatewayDevice:1\r
        EXT:\r
        SERVER: Linux UPnP/1.1 MiniUPnPd/2.3\r
        LOCATION: http://192.168.1.1:1900/upnp/rootDesc.xml\r
        \r
        """
        let parsed = SSDPWire.parseResponse(Data(rawResp.utf8))
        #expect(parsed != nil)
        #expect(parsed?.location.absoluteString == "http://192.168.1.1:1900/upnp/rootDesc.xml")
        #expect(parsed?.st == "urn:schemas-upnp-org:device:InternetGatewayDevice:1")
        #expect(parsed?.server == "Linux UPnP/1.1 MiniUPnPd/2.3")
        #expect(SSDPWire.isSafeLocationURL(parsed!.location))

        // Embedded router quirk: \r\r\n line endings and LF-only
        let crCrLf = "HTTP/1.1 200 OK\r\r\nLOCATION: http://10.0.0.1:5000/desc.xml\r\r\n\r\n"
        #expect(SSDPWire.parseResponse(Data(crCrLf.utf8))?.location.absoluteString == "http://10.0.0.1:5000/desc.xml")

        // Reject bogus HTTP version, non-200, NOTIFY, missing LOCATION
        #expect(SSDPWire.parseResponse(Data("HTTP/1.XYZ 200 OK\r\nLOCATION: http://192.168.1.1/a.xml\r\n\r\n".utf8)) == nil)
        #expect(SSDPWire.parseResponse(Data("HTTP/1.1 404 Not Found\r\nLOCATION: http://192.168.1.1/a.xml\r\n\r\n".utf8)) == nil)
        #expect(SSDPWire.parseResponse(Data("NOTIFY * HTTP/1.1\r\nLOCATION: http://192.168.1.1/a.xml\r\n\r\n".utf8)) == nil)
        #expect(SSDPWire.parseResponse(Data("HTTP/1.1 200 OK\r\nSERVER: foo\r\n\r\n".utf8)) == nil)

        // SSRF checks: allow RFC1918/link-local, reject public IP, file://, and loopback by default
        #expect(!SSDPWire.isSafeLocationURL(URL(string: "http://8.8.8.8:1900/rootDesc.xml")!))
        #expect(!SSDPWire.isSafeLocationURL(URL(string: "file://127.0.0.1/etc/passwd")!, allowLoopback: true))
        #expect(!SSDPWire.isSafeLocationURL(URL(string: "http://127.0.0.1:1900/rootDesc.xml")!))
        #expect(SSDPWire.isSafeLocationURL(URL(string: "http://127.0.0.1:1900/rootDesc.xml")!, allowLoopback: true))
    }

    // MARK: rootDesc.xml Parsing (incl. SSRF, Hierarchy & CDATA)

    @Test func parseRootDescWANIPConnectionTPLink() {
        let xml = """
        <?xml version="1.0"?>
        <root xmlns="urn:schemas-upnp-org:device-1-0">
          <specVersion><major>1</major><minor>0</minor></specVersion>
          <device>
            <deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>
            <serviceList>
              <service>
                <serviceType>urn:schemas-upnp-org:service:Layer3Forwarding:1</serviceType>
                <controlURL>/upnp/ctl/L3F</controlURL>
              </service>
            </serviceList>
            <deviceList>
              <device>
                <deviceType>urn:schemas-upnp-org:device:WANDevice:1</deviceType>
                <deviceList>
                  <device>
                    <deviceType>urn:schemas-upnp-org:device:WANConnectionDevice:1</deviceType>
                    <serviceList>
                      <service>
                        <serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>
                        <serviceId>urn:upnp-org:serviceId:WANIPConn1</serviceId>
                        <controlURL>/upnp/ctl/IPConn</controlURL>
                      </service>
                    </serviceList>
                  </device>
                </deviceList>
              </device>
            </deviceList>
          </device>
        </root>
        """
        let loc = URL(string: "http://192.168.1.1:1900/upnp/rootDesc.xml")!
        let services = UPnPRootDescriptionParser.parse(Data(xml.utf8), locationURL: loc)
        #expect(services.count == 1)
        #expect(services[0].serviceType == "urn:schemas-upnp-org:service:WANIPConnection:1")
        #expect(services[0].controlURL.absoluteString == "http://192.168.1.1:1900/upnp/ctl/IPConn")
    }

    @Test func parseRootDescWANPPPConnectionPriorityCDATAHierarchyAndSSRF() {
        // WANPPPConnection:1 + URLBase + CDATA + nested vendor extension tags (must NOT corrupt hierarchy)
        let pppXML = """
        <?xml version="1.0"?>
        <root xmlns="urn:schemas-upnp-org:device-1-0">
          <URLBase>http://192.168.1.1:5000/upnp/</URLBase>
          <device>
            <ext:meta><ext:URLBase></ext:URLBase></ext:meta>
            <deviceList>
              <device>
                <deviceList>
                  <device>
                    <serviceList>
                      <service>
                        <serviceType><![CDATA[urn:schemas-upnp-org:service:WANPPPConnection:1]]></serviceType>
                        <controlURL><![CDATA[ctl/PPPConn]]></controlURL>
                        <ext:meta><ext:service><ext:controlURL>/wrong</ext:controlURL></ext:service></ext:meta>
                      </service>
                    </serviceList>
                  </device>
                </deviceList>
              </device>
            </deviceList>
          </device>
        </root>
        """
        let loc = URL(string: "http://192.168.1.1:49152/rootDesc.xml")!
        let pppServices = UPnPRootDescriptionParser.parse(Data(pppXML.utf8), locationURL: loc)
        #expect(pppServices.count == 1)
        #expect(pppServices[0].serviceType == "urn:schemas-upnp-org:service:WANPPPConnection:1")
        #expect(pppServices[0].controlURL.absoluteString == "http://192.168.1.1:5000/upnp/ctl/PPPConn")

        // Multi-service IGD v1 + v2 -> sorted WANIPConnection:2 first
        let multiXML = """
        <root>
          <device>
            <serviceList>
              <service>
                <serviceType>urn:schemas-upnp-org:service:WANPPPConnection:1</serviceType>
                <controlURL>/ctl/ppp1</controlURL>
              </service>
              <service>
                <serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>
                <controlURL>/ctl/ip1</controlURL>
              </service>
              <service>
                <serviceType>urn:schemas-upnp-org:service:WANIPConnection:2</serviceType>
                <controlURL>http://192.168.1.1:5001/ctl/ip2</controlURL>
              </service>
            </serviceList>
          </device>
        </root>
        """
        let multi = UPnPRootDescriptionParser.parse(Data(multiXML.utf8), locationURL: loc)
        #expect(multi.map(\.serviceType) == [
            "urn:schemas-upnp-org:service:WANIPConnection:2",
            "urn:schemas-upnp-org:service:WANIPConnection:1",
            "urn:schemas-upnp-org:service:WANPPPConnection:1",
        ])

        // SSRF attacks via external controlURL, protocol-relative URL, file://, and loopback -> ALL REJECTED
        let ssrfXML = """
        <root>
          <URLBase>http://8.8.8.8:80/</URLBase>
          <device>
            <serviceList>
              <service>
                <serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>
                <controlURL>https://93.184.216.34/exfil</controlURL>
              </service>
              <service>
                <serviceType>urn:schemas-upnp-org:service:WANIPConnection:2</serviceType>
                <controlURL>//8.8.8.8/exfil</controlURL>
              </service>
              <service>
                <serviceType>urn:schemas-upnp-org:service:WANPPPConnection:1</serviceType>
                <controlURL>file:///etc/passwd</controlURL>
              </service>
              <service>
                <serviceType>urn:schemas-upnp-org:service:WANPPPConnection:2</serviceType>
                <controlURL>http://127.0.0.1:8080/admin</controlURL>
              </service>
            </serviceList>
          </device>
        </root>
        """
        #expect(UPnPRootDescriptionParser.parse(Data(ssrfXML.utf8), locationURL: loc).isEmpty)
    }

    // MARK: SOAP Envelopes & Parsing

    @Test func soapBuildAndParseAllActionsAndEdgeCases() {
        let st = "urn:schemas-upnp-org:service:WANIPConnection:1"

        // GetExternalIPAddress uses explicit closing tag for router compatibility
        let getIPReq = UPnPSOAP.buildGetExternalIPAddress(serviceType: st)
        #expect(getIPReq.soapAction == "\"\(st)#GetExternalIPAddress\"")
        #expect(String(decoding: getIPReq.body, as: UTF8.self).contains("<u:GetExternalIPAddress xmlns:u=\"\(st)\"></u:GetExternalIPAddress>"))

        // Supports CDATA and ignores non-fault <errorCode> outside <Fault>
        let getIPResp = """
        <?xml version="1.0"?>
        <s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
          <s:Body>
            <u:GetExternalIPAddressResponse xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">
              <NewExternalIPAddress><![CDATA[203.0.113.7]]></NewExternalIPAddress>
            </u:GetExternalIPAddressResponse>
          </s:Body>
        </s:Envelope>
        """
        #expect(UPnPSOAP.parseGetExternalIPAddressResponse(Data(getIPResp.utf8)) == .success(IPAddress("203.0.113.7")!))

        let zeroIPResp = "<s:Envelope><s:Body><u:GetExternalIPAddressResponse><NewExternalIPAddress>0.0.0.0</NewExternalIPAddress></u:GetExternalIPAddressResponse></s:Body></s:Envelope>"
        #expect(UPnPSOAP.parseGetExternalIPAddressResponse(Data(zeroIPResp.utf8)) == .failure(.noExternalAddress))

        // AddPortMapping with XML escaping
        let addReq = UPnPSOAP.buildAddPortMapping(
            serviceType: st,
            externalPort: 51413,
            proto: .tcp,
            internalPort: 51413,
            internalClient: "192.168.1.106",
            description: "Astor <TCP> & \"1\"",
            leaseDuration: 3600
        )
        let addStr = String(decoding: addReq.body, as: UTF8.self)
        #expect(addStr.contains("<NewPortMappingDescription>Astor &lt;TCP&gt; &amp; &quot;1&quot;</NewPortMappingDescription>"))

        let addOK = "<s:Envelope><s:Body><u:AddPortMappingResponse xmlns:u=\"\(st)\"/></s:Body></s:Envelope>"
        if case .failure(let err) = UPnPSOAP.parseAddPortMappingResponse(Data(addOK.utf8), statusCode: 200) {
            Issue.record("Expected success, got \(err)")
        }

        // Non-SOAP HTML page with HTTP 200 MUST be rejected for both Add and Delete
        let htmlPage = Data("<html><body>OK</body></html>".utf8)
        if case .success = UPnPSOAP.parseAddPortMappingResponse(htmlPage, statusCode: 200) {
            Issue.record("Expected HTML page to fail AddPortMapping parse")
        }
        if case .success = UPnPSOAP.parseDeletePortMappingResponse(htmlPage, statusCode: 200) {
            Issue.record("Expected HTML page to fail DeletePortMapping parse")
        }
        // Empty/truncated Delete response MUST fail
        if case .success = UPnPSOAP.parseDeletePortMappingResponse(Data(), statusCode: 200) {
            Issue.record("Expected empty DeletePortMapping response to fail")
        }

        // SOAP Fault 725 with CDATA
        let fault725 = """
        <s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
          <s:Body>
            <s:Fault>
              <faultcode>s:Client</faultcode>
              <faultstring>UPnPError</faultstring>
              <detail>
                <UPnPError xmlns="urn:schemas-upnp-org:control-1-0">
                  <errorCode><![CDATA[725]]></errorCode>
                  <errorDescription>OnlyPermanentLeasesSupported</errorDescription>
                </UPnPError>
              </detail>
            </s:Fault>
          </s:Body>
        </s:Envelope>
        """
        if case .failure(let err) = UPnPSOAP.parseAddPortMappingResponse(Data(fault725.utf8), statusCode: 500) {
            #expect(err == .fault(code: 725, description: "OnlyPermanentLeasesSupported"))
        } else {
            Issue.record("Expected SOAP fault 725")
        }

        // AddAnyPortMapping response
        let anyResp = "<s:Envelope><s:Body><u:AddAnyPortMappingResponse><NewReservedPort>54321</NewReservedPort></u:AddAnyPortMappingResponse></s:Body></s:Envelope>"
        #expect(UPnPSOAP.parseAddAnyPortMappingResponse(Data(anyResp.utf8), statusCode: 200) == .success(54321))

        // DeletePortMapping
        let delOK = "<s:Envelope><s:Body><u:DeletePortMappingResponse/></s:Body></s:Envelope>"
        if case .failure(let err) = UPnPSOAP.parseDeletePortMappingResponse(Data(delOK.utf8), statusCode: 200) {
            Issue.record("Expected delete success, got \(err)")
        }
    }

    // MARK: Darwin Route Table Parser & Epoch Reset Logic

    @Test func routeTableSkipsTunnelsTruncatedMasksDownInterfacesAndWrongType() {
        func makeSockaddrIn(_ ip: IPAddress) -> Data {
            var d = Data(count: 16)
            d[0] = 16
            d[1] = UInt8(AF_INET)
            let b = ip.bytes
            d[4] = b[0]; d[5] = b[1]; d[6] = b[2]; d[7] = b[3]
            return d
        }

        func makeRouteMsg(
            ifIndex: UInt16,
            flags: Int32,
            dst: IPAddress,
            gw: IPAddress,
            netmask: Data,
            rtmType: UInt8 = RouteDiscovery.rtmGet,
            version: UInt8 = RouteDiscovery.rtmVersion,
            truncateBytes: Int = 0
        ) -> Data {
            let addrs: Int32 = RouteDiscovery.rtaDst | RouteDiscovery.rtaGateway | RouteDiscovery.rtaNetmask
            var payload = Data()
            payload.append(makeSockaddrIn(dst))
            payload.append(makeSockaddrIn(gw))
            payload.append(netmask)
            let pad = RouteDiscovery.roundUpSockAddrLen(netmask.count) - netmask.count
            if pad > 0 { payload.append(Data(count: pad)) }
            if truncateBytes > 0, payload.count > truncateBytes {
                payload.removeLast(truncateBytes)
            }

            let totalLen = RouteDiscovery.rtMsgHdrSize + payload.count
            var hdr = Data(count: RouteDiscovery.rtMsgHdrSize)
            hdr[0] = UInt8(totalLen & 0xFF)
            hdr[1] = UInt8((totalLen >> 8) & 0xFF)
            hdr[2] = version
            hdr[3] = rtmType
            hdr[4] = UInt8(ifIndex & 0xFF)
            hdr[5] = UInt8((ifIndex >> 8) & 0xFF)
            let f = UInt32(bitPattern: flags)
            hdr[8] = UInt8(f & 0xFF); hdr[9] = UInt8((f >> 8) & 0xFF)
            hdr[10] = UInt8((f >> 16) & 0xFF); hdr[11] = UInt8((f >> 24) & 0xFF)
            let a = UInt32(bitPattern: addrs)
            hdr[12] = UInt8(a & 0xFF); hdr[13] = UInt8((a >> 8) & 0xFF)
            hdr[14] = UInt8((a >> 16) & 0xFF); hdr[15] = UInt8((a >> 24) & 0xFF)
            return hdr + payload
        }

        let zeroMask = Data()
        let slash24Mask = makeSockaddrIn(IPAddress("255.255.255.0")!)

        var table = Data()
        // 1. Tunnel interface utun8 -> SKIP
        table.append(makeRouteMsg(
            ifIndex: 29, flags: RouteDiscovery.rtfUp | RouteDiscovery.rtfGateway,
            dst: IPAddress("0.0.0.0")!, gw: IPAddress("10.0.0.1")!, netmask: zeroMask
        ))
        // 2. Non-default /24 route -> SKIP
        table.append(makeRouteMsg(
            ifIndex: 16, flags: RouteDiscovery.rtfUp | RouteDiscovery.rtfGateway,
            dst: IPAddress("10.20.30.0")!, gw: IPAddress("192.168.1.254")!, netmask: slash24Mask
        ))
        // 3. Truncated /24 netmask (would have sliceLen <= 4 if clamped!) -> MUST SKIP
        table.append(makeRouteMsg(
            ifIndex: 16, flags: RouteDiscovery.rtfUp | RouteDiscovery.rtfGateway,
            dst: IPAddress("0.0.0.0")!, gw: IPAddress("192.168.99.1")!, netmask: slash24Mask, truncateBytes: 12
        ))
        // 4. Wrong rtm_type (RTM_IFINFO = 0x0e) -> MUST SKIP
        table.append(makeRouteMsg(
            ifIndex: 16, flags: RouteDiscovery.rtfUp | RouteDiscovery.rtfGateway,
            dst: IPAddress("0.0.0.0")!, gw: IPAddress("192.168.77.1")!, netmask: zeroMask, rtmType: 0x0e
        ))
        // 5. Down/unplugged physical interface (missing IFF_RUNNING) -> MUST SKIP
        table.append(makeRouteMsg(
            ifIndex: 8, flags: RouteDiscovery.rtfUp | RouteDiscovery.rtfGateway,
            dst: IPAddress("0.0.0.0")!, gw: IPAddress("192.168.55.1")!, netmask: zeroMask
        ))
        // 6. Orphan/deleted interface index (if_indextoname returns nil) -> MUST SKIP
        table.append(makeRouteMsg(
            ifIndex: 99, flags: RouteDiscovery.rtfUp | RouteDiscovery.rtfGateway,
            dst: IPAddress("0.0.0.0")!, gw: IPAddress("192.168.44.1")!, netmask: zeroMask
        ))
        // 7. Scoped en1 default route (active) -> MUST SELECT
        table.append(makeRouteMsg(
            ifIndex: 16, flags: RouteDiscovery.rtfUp | RouteDiscovery.rtfGateway | RouteDiscovery.rtfIfScope,
            dst: IPAddress("0.0.0.0")!, gw: IPAddress("192.168.1.1")!, netmask: zeroMask
        ))

        let names: [UInt16: String] = [29: "utun8", 16: "en1", 8: "en2"]
        let flags: [String: UInt32] = [
            "utun8": UInt32(IFF_UP | IFF_RUNNING | IFF_POINTOPOINT),
            "en1": UInt32(IFF_UP | IFF_RUNNING | IFF_BROADCAST | IFF_MULTICAST),
            "en2": UInt32(IFF_UP | IFF_BROADCAST | IFF_MULTICAST), // NOT running
        ]

        let selected = RouteDiscovery.selectDefaultGateway(
            from: table,
            interfaceName: { names[$0] },
            interfaceFlags: { flags[$0] }
        )
        #expect(selected?.gateway == IPAddress("192.168.1.1")!)
        #expect(selected?.interfaceName == "en1")
    }

    @Test func epochResetDetectionIsOverflowSafeAndRFC6887Compliant() {
        // UInt32.max boundary MUST NOT crash with arithmetic overflow
        #expect(!PortMapper.isEpochReset(prev: UInt32.max, current: UInt32.max, clientElapsed: 1.0))
        #expect(PortMapper.isEpochReset(prev: 100, current: UInt32.max, clientElapsed: 1.0))
        #expect(PortMapper.isEpochReset(prev: UInt32.max, current: 5, clientElapsed: 10.0))

        // Normal clock progression over 30-minute renewal (1800s)
        #expect(!PortMapper.isEpochReset(prev: 100, current: 1900, clientElapsed: 1800.0))
        #expect(!PortMapper.isEpochReset(prev: 100, current: 1899, clientElapsed: 1800.0))
        // Immediate back-to-back packets with 1s quantization jitter
        #expect(!PortMapper.isEpochReset(prev: 100, current: 99, clientElapsed: 0.1))

        // Backwards jump (> 1s) -> reboot detected
        #expect(PortMapper.isEpochReset(prev: 100, current: 98, clientElapsed: 1.0))
        // Router rebooted mid-lease: prev=100 at t=0, rebooted at t=1200, at t=1800 epoch=600 -> MUST detect reboot!
        #expect(PortMapper.isEpochReset(prev: 100, current: 600, clientElapsed: 1800.0))
    }
}

// MARK: - Offline End-to-End PortMapper State Machine Tests (Local Mock Servers)

@Suite(.serialized) struct NATMapperTests {

    @Test func pcpSuccessRenewalMismatchedNonceIgnoredDeleteAndDeinit() throws {
        let loop = EventLoop(label: "test.nat.pcp")
        let externalIP = IPAddress("203.0.113.42")!
        let localIP = IPAddress("127.0.0.1")!

        let state = MockPCPState()
        let server = try loop.sync { try UDPSocket(port: 0, v6: false, loop: loop) }
        defer { loop.sync { server.close() } }

        let mappedSem = DispatchSemaphore(value: 0)
        let renewedSem = DispatchSemaphore(value: 0)
        let deletedSem = DispatchSemaphore(value: 0)

        loop.sync {
            server.onDatagram = { [weak server] data, from in
                guard let server, data.count == 60, data.byte(0) == 2, data.byte(1) == 1 else { return }
                let reqLifetime = data.be32(4)
                let nonce = Data(data[24..<36])
                let protoByte = data.byte(36)
                let intPort = data.be16(40)
                let sugPort = data.be16(42)

                if reqLifetime == 0 {
                    state.deletes.append((protoByte, intPort, sugPort, nonce))
                    if state.deletes.count == 2 { deletedSem.signal() }
                    return
                }

                // Inject a spoofed 60-byte PCP error with a WRONG nonce before answering -> must be ignored!
                if state.createOrRenewCount[protoByte, default: 0] == 0 {
                    var badErr = Data()
                    badErr.append(contentsOf: [2, 0x81, 0, PCPResultCode.notAuthorized.rawValue])
                    badErr.appendBE32(0)
                    badErr.appendBE32(1000)
                    badErr.append(Data(count: 12))
                    badErr.append(Data(repeating: 0xEE, count: 12)) // wrong nonce!
                    badErr.append(protoByte)
                    badErr.append(contentsOf: [0, 0, 0])
                    badErr.appendBE16(intPort)
                    badErr.appendBE16(0)
                    badErr.append(Data(count: 16))
                    server.send(badErr, to: from)
                }

                state.createOrRenewCount[protoByte, default: 0] += 1
                state.noncesSeen[protoByte, default: []].append(nonce)

                var reply = Data()
                reply.append(2)
                reply.append(0x81)
                reply.append(0)
                reply.append(0) // SUCCESS
                reply.appendBE32(2) // 2s lease -> renews at 1.0s
                reply.appendBE32(1000)
                reply.append(Data(count: 12))
                reply.append(nonce)
                reply.append(protoByte)
                reply.append(contentsOf: [0, 0, 0])
                reply.appendBE16(intPort)
                reply.appendBE16(intPort + 1)
                reply.append(contentsOf: PCPWire.encodeAddress(externalIP))
                server.send(reply, to: from)

                if state.createOrRenewCount[6, default: 0] >= 2 && state.createOrRenewCount[17, default: 0] >= 2 {
                    renewedSem.signal()
                }
            }
            server.start()
        }

        let startTime = monotonicNow()
        weak var weakMapper: PortMapper?
        do {
            let mapper = PortMapper(
                loop: loop,
                methods: [.pcp, .natpmp],
                leaseDuration: 2,
                gatewayOverride: localIP,
                gatewayPort: server.port,
                clientIPOverride: localIP,
                initialRetransmit: 0.5 // well above LAN RTT so initial retransmit cannot fake renewal
            )
            weakMapper = mapper
            loop.sync {
                mapper.onChange = { [weak mapper] in
                    guard let mapper else { return }
                    if mapper.statuses.count == 2 && mapper.statuses.allSatisfy({ $0.error == nil }) {
                        mappedSem.signal()
                    }
                }
                mapper.start(port: 51413)
            }

            #expect(mappedSem.wait(timeout: .now() + 2) == .success)

            let (statuses, extAddr) = loop.sync { (mapper.statuses, mapper.externalAddress) }
            #expect(extAddr == externalIP)
            #expect(statuses.count == 2)
            #expect(statuses.allSatisfy { $0.method == "PCP" && $0.externalPort == 51414 && $0.externalAddress == externalIP && $0.error == nil })

            // Wait for automatic 50% lease renewal (~1.0s) and confirm it happened near 1s (not an early retransmit)
            #expect(renewedSem.wait(timeout: .now() + 3) == .success)
            let elapsed = monotonicNow() - startTime
            #expect(elapsed >= 0.85, "Expected 50% renewal at ~1.0s, fired too early at \(elapsed)s")

            loop.sync { mapper.stop() }
            #expect(deletedSem.wait(timeout: .now() + 2) == .success)
        }

        // Confirm zero retain cycles (PortMapper deallocated cleanly)
        loop.sync {}
        #expect(weakMapper == nil)

        loop.sync {
            #expect(Set(state.noncesSeen[6] ?? []).count == 1)
            #expect(Set(state.noncesSeen[17] ?? []).count == 1)
            for del in state.deletes {
                #expect(del.intPort == 51413)
                #expect(del.sugPort == 0)
                #expect(del.nonce == state.noncesSeen[del.proto]?.first)
            }
        }
    }

    @Test func pcpFallbackToNATPMPOnStrictRFC6886UnsupportedVersion() throws {
        let loop = EventLoop(label: "test.nat.fallback.unsupp")
        let externalIP = IPAddress("198.51.100.7")!
        let localIP = IPAddress("127.0.0.1")!
        let state = MockNATPMPState()

        let server = try loop.sync { try UDPSocket(port: 0, v6: false, loop: loop) }
        defer { loop.sync { server.close() } }

        let readySem = DispatchSemaphore(value: 0)
        let deletedSem = DispatchSemaphore(value: 0)

        loop.sync {
            server.onDatagram = { [weak server] data, from in
                guard let server, data.count >= 2 else { return }
                let ver = data.byte(0)
                let op = data.byte(1)
                if ver == 2 {
                    // Strictly RFC 6886 §3.5 compliant NAT-PMP v0 reply: OP = 0 (R bit 0), result = 1
                    state.sawPCPProbe = true
                    var err = Data([0, 0x00])
                    err.appendBE16(NATPMPResultCode.unsupportedVersion.rawValue)
                    err.appendBE32(500)
                    server.send(err, to: from)
                } else if ver == 0 {
                    if op == 0 {
                        var ext = Data([0, 0x80])
                        ext.appendBE16(0)
                        ext.appendBE32(500)
                        ext.append(contentsOf: externalIP.bytes)
                        server.send(ext, to: from)
                    } else if (op == 1 || op == 2), data.count == 12 {
                        let intPort = data.be16(4)
                        let lifetime = data.be32(8)
                        if lifetime == 0 {
                            state.deletes.append((op, intPort))
                            if state.deletes.count == 2 { deletedSem.signal() }
                            return
                        }
                        var map = Data([0, 0x80 | op])
                        map.appendBE16(0)
                        map.appendBE32(500)
                        map.appendBE16(intPort)
                        map.appendBE16(intPort)
                        map.appendBE32(3600)
                        server.send(map, to: from)
                    }
                }
            }
            server.start()
        }

        let mapper = PortMapper(
            loop: loop,
            methods: [.pcp, .natpmp],
            leaseDuration: 3600,
            gatewayOverride: localIP,
            gatewayPort: server.port,
            clientIPOverride: localIP,
            initialRetransmit: 0.05
        )
        loop.sync {
            mapper.onChange = { [weak mapper] in
                guard let mapper else { return }
                if mapper.externalAddress != nil,
                   mapper.statuses.count == 2,
                   mapper.statuses.allSatisfy({ $0.error == nil }) {
                    readySem.signal()
                }
            }
            mapper.start(port: 51413)
        }

        #expect(readySem.wait(timeout: .now() + 2) == .success)
        let (statuses, extAddr, sawPCP) = loop.sync { (mapper.statuses, mapper.externalAddress, state.sawPCPProbe) }
        #expect(sawPCP)
        #expect(extAddr == externalIP)
        #expect(statuses.count == 2)
        #expect(statuses.allSatisfy { $0.method == "NAT-PMP" && $0.externalPort == 51413 && $0.externalAddress == externalIP })

        loop.sync { mapper.stop() }
        #expect(deletedSem.wait(timeout: .now() + 2) == .success)
        #expect(loop.sync { state.deletes.count } == 2)
    }

    @Test func pcpFallbackToNATPMPOnTimeout() throws {
        let loop = EventLoop(label: "test.nat.fallback.timeout")
        let externalIP = IPAddress("198.51.100.88")!
        let localIP = IPAddress("127.0.0.1")!
        let state = MockNATPMPState()

        let server = try loop.sync { try UDPSocket(port: 0, v6: false, loop: loop) }
        defer { loop.sync { server.close() } }

        let readySem = DispatchSemaphore(value: 0)
        loop.sync {
            server.onDatagram = { [weak server] data, from in
                guard let server, data.count >= 2 else { return }
                let ver = data.byte(0)
                let op = data.byte(1)
                if ver == 2 {
                    state.pcpPacketsDropped += 1
                    return
                }
                if ver == 0 && op == 0 {
                    var ext = Data([0, 0x80])
                    ext.appendBE16(0)
                    ext.appendBE32(900)
                    ext.append(contentsOf: externalIP.bytes)
                    server.send(ext, to: from)
                } else if ver == 0 && (op == 1 || op == 2), data.count == 12 {
                    let intPort = data.be16(4)
                    guard data.be32(8) > 0 else { return }
                    var map = Data([0, 0x80 | op])
                    map.appendBE16(0)
                    map.appendBE32(900)
                    map.appendBE16(intPort)
                    map.appendBE16(intPort)
                    map.appendBE32(3600)
                    server.send(map, to: from)
                }
            }
            server.start()
        }

        let mapper = PortMapper(
            loop: loop,
            methods: [.pcp, .natpmp],
            leaseDuration: 3600,
            gatewayOverride: localIP,
            gatewayPort: server.port,
            clientIPOverride: localIP,
            initialRetransmit: 0.02,
            pcpMaxAttempts: 2
        )
        loop.sync {
            mapper.onChange = { [weak mapper] in
                guard let mapper else { return }
                if mapper.externalAddress != nil,
                   mapper.statuses.count == 2,
                   mapper.statuses.allSatisfy({ $0.error == nil }) {
                    readySem.signal()
                }
            }
            mapper.start(port: 51415)
        }

        #expect(readySem.wait(timeout: .now() + 2) == .success)
        let (statuses, dropped) = loop.sync { (mapper.statuses, state.pcpPacketsDropped) }
        #expect(dropped >= 4)
        #expect(statuses.count == 2)
        #expect(statuses.allSatisfy { $0.method == "NAT-PMP" && $0.externalPort == 51415 })
        loop.sync { mapper.stop() }
    }

    @Test func pcpRenewalFailureSurfacesErrorAndRecoversOnRetry() throws {
        let loop = EventLoop(label: "test.nat.renew.retry")
        let externalIP = IPAddress("203.0.113.55")!
        let localIP = IPAddress("127.0.0.1")!
        let state = MockPCPState()

        let server = try loop.sync { try UDPSocket(port: 0, v6: false, loop: loop) }
        defer { loop.sync { server.close() } }

        let initialSem = DispatchSemaphore(value: 0)
        let errorSem = DispatchSemaphore(value: 0)
        let recoveredSem = DispatchSemaphore(value: 0)

        loop.sync {
            server.onDatagram = { [weak server] data, from in
                guard let server, data.count == 60, data.byte(0) == 2, data.byte(1) == 1 else { return }
                let reqLifetime = data.be32(4)
                guard reqLifetime > 0 else { return }
                let nonce = Data(data[24..<36])
                let protoByte = data.byte(36)
                let intPort = data.be16(40)

                state.createOrRenewCount[protoByte, default: 0] += 1
                let count = state.createOrRenewCount[protoByte]!

                if count == 2 {
                    // Fail the first renewal attempt with transient NO_RESOURCES (code 8)
                    var errReply = Data()
                    errReply.append(contentsOf: [2, 0x81, 0, PCPResultCode.noResources.rawValue])
                    errReply.appendBE32(0)
                    errReply.appendBE32(2000)
                    errReply.append(Data(count: 12))
                    errReply.append(nonce)
                    errReply.append(protoByte)
                    errReply.append(contentsOf: [0, 0, 0])
                    errReply.appendBE16(intPort)
                    errReply.appendBE16(0)
                    errReply.append(Data(count: 16))
                    server.send(errReply, to: from)
                    return
                }

                var reply = Data()
                reply.append(contentsOf: [2, 0x81, 0, 0])
                reply.appendBE32(2) // 2s lease -> renew at 1s, retry after failure at 0.5s
                reply.appendBE32(2000)
                reply.append(Data(count: 12))
                reply.append(nonce)
                reply.append(protoByte)
                reply.append(contentsOf: [0, 0, 0])
                reply.appendBE16(intPort)
                reply.appendBE16(intPort)
                reply.append(contentsOf: PCPWire.encodeAddress(externalIP))
                server.send(reply, to: from)
            }
            server.start()
        }

        let mapper = PortMapper(
            loop: loop,
            methods: [.pcp],
            leaseDuration: 2,
            gatewayOverride: localIP,
            gatewayPort: server.port,
            clientIPOverride: localIP,
            initialRetransmit: 0.5
        )
        let phase = PhaseTracker()
        loop.sync {
            mapper.onChange = { [weak mapper] in
                guard let mapper else { return }
                if phase.step == 0, mapper.statuses.count == 2, mapper.statuses.allSatisfy({ $0.error == nil }) {
                    phase.step = 1
                    initialSem.signal()
                } else if phase.step == 1, mapper.statuses.contains(where: { $0.error?.contains("NO_RESOURCES") == true }) {
                    phase.step = 2
                    errorSem.signal()
                } else if phase.step == 2, mapper.statuses.count == 2, mapper.statuses.allSatisfy({ $0.error == nil }) {
                    phase.step = 3
                    recoveredSem.signal()
                }
            }
            mapper.start(port: 51418)
        }

        #expect(initialSem.wait(timeout: .now() + 2) == .success)
        #expect(errorSem.wait(timeout: .now() + 3) == .success)
        #expect(recoveredSem.wait(timeout: .now() + 3) == .success)
        loop.sync { mapper.stop() }
    }

    @Test func upnpFullPipelineConflict718AddAnyPortAnd725PermanentFallback() throws {
        let loop = EventLoop(label: "test.nat.upnp.mock")
        let localIP = IPAddress("127.0.0.1")!
        let externalIP = IPAddress("203.0.113.99")!

        let httpState = MockUPnPHTTPState()
        let httpListener = try loop.sync { try TCPListener(port: 0, loop: loop) }
        defer {
            loop.sync {
                for s in httpState.connections { s.close() }
                httpState.connections.removeAll()
                httpListener.close()
            }
        }
        let httpPort = httpListener.port

        let ssdpResponder = try loop.sync { try UDPSocket(port: 0, v6: false, loop: loop) }
        defer { loop.sync { ssdpResponder.close() } }

        // Advertise WANIPConnection:2 to exercise 718 -> AddAnyPortMapping -> 725 -> AddAnyPortMapping(lease=0)!
        let serviceType = "urn:schemas-upnp-org:service:WANIPConnection:2"
        let rootDescXML = """
        <?xml version="1.0"?>
        <root xmlns="urn:schemas-upnp-org:device-1-0">
          <device>
            <deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:2</deviceType>
            <deviceList>
              <device>
                <deviceType>urn:schemas-upnp-org:device:WANDevice:2</deviceType>
                <deviceList>
                  <device>
                    <deviceType>urn:schemas-upnp-org:device:WANConnectionDevice:2</deviceType>
                    <serviceList>
                      <service>
                        <serviceType>\(serviceType)</serviceType>
                        <controlURL>/ctl/IPConn2</controlURL>
                      </service>
                    </serviceList>
                  </device>
                </deviceList>
              </device>
            </deviceList>
          </device>
        </root>
        """

        loop.sync {
            httpListener.onAccept = { stream in
                httpState.connections.append(stream)
                var buf = Data()
                stream.onClose = { [weak stream] _ in
                    if let stream {
                        httpState.connections.removeAll { $0 === stream }
                    }
                }
                stream.onRead = { [weak stream] chunk in
                    guard let stream else { return }
                    buf.append(chunk)
                    guard let headerEnd = buf.range(of: Data("\r\n\r\n".utf8)) else { return }
                    let headStr = String(decoding: buf[..<headerEnd.lowerBound], as: UTF8.self)
                    var contentLength = 0
                    for line in headStr.split(separator: "\r\n") {
                        if line.lowercased().hasPrefix("content-length:") {
                            contentLength = Int(line.split(separator: ":")[1].trimmingCharacters(in: .whitespaces)) ?? 0
                        }
                    }
                    let bodyStart = headerEnd.upperBound
                    guard buf.count - bodyStart >= contentLength else { return }
                    let body = String(decoding: buf[bodyStart..<(bodyStart + contentLength)], as: UTF8.self)
                    let firstLine = headStr.split(separator: "\r\n").first.map(String.init) ?? ""

                    let statusLine: String
                    let respBody: String
                    if firstLine.hasPrefix("GET /rootDesc.xml") {
                        statusLine = "HTTP/1.1 200 OK"
                        respBody = rootDescXML
                    } else if headStr.contains("#GetExternalIPAddress") {
                        statusLine = "HTTP/1.1 200 OK"
                        respBody = "<s:Envelope><s:Body><u:GetExternalIPAddressResponse><NewExternalIPAddress>\(externalIP)</NewExternalIPAddress></u:GetExternalIPAddressResponse></s:Body></s:Envelope>"
                    } else if headStr.contains("#AddPortMapping\"") {
                        // Return 718 ConflictInMappingEntry so IGD v2 switches to AddAnyPortMapping
                        httpState.conflicts718 += 1
                        statusLine = "HTTP/1.1 500 Internal Server Error"
                        respBody = "<s:Envelope><s:Body><s:Fault><detail><UPnPError><errorCode>718</errorCode><errorDescription>ConflictInMappingEntry</errorDescription></UPnPError></detail></s:Fault></s:Body></s:Envelope>"
                    } else if headStr.contains("#AddAnyPortMapping\"") {
                        if body.contains("<NewLeaseDuration>3600</NewLeaseDuration>") {
                            httpState.rejectedFiniteLeases += 1
                            statusLine = "HTTP/1.1 500 Internal Server Error"
                            respBody = "<s:Envelope><s:Body><s:Fault><detail><UPnPError><errorCode>725</errorCode><errorDescription>OnlyPermanentLeasesSupported</errorDescription></UPnPError></detail></s:Fault></s:Body></s:Envelope>"
                        } else {
                            httpState.addedMappings += 1
                            statusLine = "HTTP/1.1 200 OK"
                            respBody = "<s:Envelope><s:Body><u:AddAnyPortMappingResponse><NewReservedPort>54321</NewReservedPort></u:AddAnyPortMappingResponse></s:Body></s:Envelope>"
                        }
                    } else if headStr.contains("#DeletePortMapping\"") {
                        httpState.deletedMappings += 1
                        statusLine = "HTTP/1.1 200 OK"
                        respBody = "<s:Envelope><s:Body><u:DeletePortMappingResponse/></s:Body></s:Envelope>"
                    } else {
                        statusLine = "HTTP/1.1 404 Not Found"
                        respBody = ""
                    }

                    let respBytes = Data(respBody.utf8)
                    let httpResp = "\(statusLine)\r\nContent-Type: text/xml; charset=\"utf-8\"\r\nContent-Length: \(respBytes.count)\r\nConnection: close\r\n\r\n"
                    stream.write(Data(httpResp.utf8) + respBytes)
                    buf = Data()
                }
                stream.activate()
            }
            httpListener.start()

            ssdpResponder.onDatagram = { [weak ssdpResponder] data, from in
                guard let ssdpResponder else { return }
                let text = String(decoding: data, as: UTF8.self)
                guard text.hasPrefix("M-SEARCH ") else { return }
                let reply = "HTTP/1.1 200 OK\r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:2\r\nLOCATION: http://127.0.0.1:\(httpPort)/rootDesc.xml\r\n\r\n"
                ssdpResponder.send(Data(reply.utf8), to: from)
            }
            ssdpResponder.start()
        }

        // Also run a silent UDP gateway socket in parallel to confirm UPnP wins the race quickly!
        let silentGW = try loop.sync { try UDPSocket(port: 0, v6: false, loop: loop) }
        defer { loop.sync { silentGW.close() } }
        loop.sync { silentGW.start() }

        let readySem = DispatchSemaphore(value: 0)
        let deleteDoneSem = DispatchSemaphore(value: 0)

        let mapper = PortMapper(
            loop: loop,
            methods: [.pcp, .natpmp, .upnp],
            leaseDuration: 3600,
            gatewayOverride: localIP,
            gatewayPort: silentGW.port,
            clientIPOverride: localIP,
            initialRetransmit: 0.5,
            ssdpTargetOverride: PeerAddress(ip: localIP, port: ssdpResponder.port)
        )

        loop.sync {
            mapper.onChange = { [weak mapper] in
                guard let mapper else { return }
                if mapper.externalAddress == externalIP,
                   mapper.statuses.count == 2,
                   mapper.statuses.allSatisfy({ $0.method == "UPnP" && $0.error == nil }) {
                    readySem.signal()
                }
            }
            mapper.onDeleteCompleted = { deleteDoneSem.signal() }
            mapper.start(port: 51416)
        }

        #expect(readySem.wait(timeout: .now() + 4) == .success)
        let (statuses, extAddr, conflicts, rejected725, added) = loop.sync {
            (mapper.statuses, mapper.externalAddress, httpState.conflicts718, httpState.rejectedFiniteLeases, httpState.addedMappings)
        }
        #expect(extAddr == externalIP)
        #expect(conflicts == 2)
        #expect(rejected725 == 2)
        #expect(added == 2)
        #expect(statuses.count == 2)
        #expect(statuses.allSatisfy { $0.method == "UPnP" && $0.externalPort == 54321 && $0.error == nil })

        loop.sync { mapper.stop() }
        #expect(deleteDoneSem.wait(timeout: .now() + 4) == .success)
        #expect(loop.sync { httpState.deletedMappings } == 2)
    }

    @Test func reportsErrorsWhenAllBackendsFailAndZeroLifetimeRejected() throws {
        let loop = EventLoop(label: "test.nat.failall")
        let localIP = IPAddress("127.0.0.1")!

        // Gateway responds with PCP lifetime = 0 (RFC 6887 §15.1 deleted) -> MUST NOT install active mapping!
        let zeroGW = try loop.sync { try UDPSocket(port: 0, v6: false, loop: loop) }
        let silentSSDP = try loop.sync { try UDPSocket(port: 0, v6: false, loop: loop) }
        defer {
            loop.sync {
                zeroGW.close()
                silentSSDP.close()
            }
        }
        loop.sync {
            zeroGW.onDatagram = { [weak zeroGW] data, from in
                guard let zeroGW, data.count == 60, data.byte(0) == 2, data.byte(1) == 1 else { return }
                var reply = Data()
                reply.append(contentsOf: [2, 0x81, 0, 0])
                reply.appendBE32(0) // zero lifetime!
                reply.appendBE32(100)
                reply.append(Data(count: 12))
                reply.append(Data(data[24..<36]))
                reply.append(data.byte(36))
                reply.append(contentsOf: [0, 0, 0])
                reply.appendBE16(data.be16(40))
                reply.appendBE16(data.be16(40))
                reply.append(contentsOf: PCPWire.encodeAddress(IPAddress("203.0.113.1")!))
                zeroGW.send(reply, to: from)
            }
            zeroGW.start()
            silentSSDP.start()
        }

        let doneSem = DispatchSemaphore(value: 0)
        let mapper = PortMapper(
            loop: loop,
            methods: [.pcp, .upnp],
            leaseDuration: 3600,
            gatewayOverride: localIP,
            gatewayPort: zeroGW.port,
            clientIPOverride: localIP,
            initialRetransmit: 0.02,
            pcpMaxAttempts: 2,
            ssdpRetryDelays: [0.02],
            ssdpDiscoveryTimeout: 0.05,
            ssdpTargetOverride: PeerAddress(ip: localIP, port: silentSSDP.port)
        )
        loop.sync {
            mapper.onChange = { [weak mapper] in
                guard let mapper else { return }
                if mapper.statuses.count == 2 && mapper.statuses.allSatisfy({ $0.error != nil }) {
                    doneSem.signal()
                }
            }
            mapper.start(port: 51417)
        }

        #expect(doneSem.wait(timeout: .now() + 2) == .success)
        let (statuses, extAddr) = loop.sync { (mapper.statuses, mapper.externalAddress) }
        #expect(extAddr == nil)
        #expect(statuses.count == 2)
        #expect(statuses.map(\.proto) == ["TCP", "UDP"])
        #expect(statuses.allSatisfy { $0.externalPort == nil && $0.error?.contains("zero lifetime") == true })
        loop.sync { mapper.stop() }
    }
}

private final class MockPCPState: @unchecked Sendable {
    var createOrRenewCount: [UInt8: Int] = [:]
    var noncesSeen: [UInt8: [Data]] = [:]
    var deletes: [(proto: UInt8, intPort: UInt16, sugPort: UInt16, nonce: Data)] = []
}

private final class MockNATPMPState: @unchecked Sendable {
    var sawPCPProbe = false
    var pcpPacketsDropped = 0
    var deletes: [(op: UInt8, intPort: UInt16)] = []
}

private final class MockUPnPHTTPState: @unchecked Sendable {
    var connections: [TCPStream] = []
    var conflicts718 = 0
    var rejectedFiniteLeases = 0
    var addedMappings = 0
    var deletedMappings = 0
}

private final class PhaseTracker: @unchecked Sendable {
    var step = 0
}

// MARK: - Live LAN Gateway Tests (Gated by ASTOR_LIVE=1)

@Suite(.serialized) struct NATLiveTests {

    @Test(.enabled(if: ProcessInfo.processInfo.environment["ASTOR_LIVE"] == "1"))
    func liveGatewayPortMappingCreateAndDelete() throws {
        let gateway = PortMapper.defaultGateway()
        #expect(gateway != nil, "Expected physical LAN default gateway via sysctl")
        print("[ASTOR_LIVE] Discovered default gateway: \(gateway?.description ?? "nil")")

        let loop = EventLoop(label: "test.nat.live")
        let testPort: UInt16 = 58421
        // Use the public convenience init(loop:) to exercise the exact binding contract end-to-end.
        let mapper = PortMapper(loop: loop)
        let readySem = DispatchSemaphore(value: 0)
        let deleteSem = DispatchSemaphore(value: 0)

        loop.sync {
            mapper.onChange = { [weak mapper] in
                guard let mapper else { return }
                if mapper.externalAddress != nil,
                   mapper.statuses.count == 2,
                   mapper.statuses.allSatisfy({ $0.error == nil && $0.externalPort != nil }) {
                    readySem.signal()
                }
            }
            mapper.onDeleteCompleted = { deleteSem.signal() }
            mapper.start(port: testPort)
        }

        defer {
            loop.sync { mapper.stop() }
            _ = deleteSem.wait(timeout: .now() + 4)
            Thread.sleep(forTimeInterval: 0.1)
            print("[ASTOR_LIVE] Deleted temporary mapping for port \(testPort)")
        }

        let waitResult = readySem.wait(timeout: .now() + 8)
        let (statuses, extAddr) = loop.sync { (mapper.statuses, mapper.externalAddress) }
        for s in statuses {
            print("[ASTOR_LIVE] Status: method=\(s.method) proto=\(s.proto) internal=\(s.internalPort) external=\(s.externalPort.map(String.init) ?? "nil") extIP=\(s.externalAddress?.description ?? "nil") error=\(s.error ?? "none")")
        }
        print("[ASTOR_LIVE] External address: \(extAddr?.description ?? "nil")")

        #expect(waitResult == .success, "Timed out waiting for live port mapping")
        #expect(extAddr != nil)
        #expect(statuses.count == 2)
        #expect(statuses.allSatisfy { $0.error == nil && $0.externalPort != nil })
    }

    @Test(.enabled(if: ProcessInfo.processInfo.environment["ASTOR_LIVE"] == "1"))
    func liveUPnPCreateAndDelete() throws {
        let loop = EventLoop(label: "test.nat.live.upnp")
        let testPort: UInt16 = 58422
        // Short 60s test lease so even in an abrupt crash no long-lived lease remains on the router.
        let mapper = PortMapper(loop: loop, methods: [.upnp], leaseDuration: 60)
        let readySem = DispatchSemaphore(value: 0)
        let deleteSem = DispatchSemaphore(value: 0)

        loop.sync {
            mapper.onChange = { [weak mapper] in
                guard let mapper else { return }
                if mapper.externalAddress != nil,
                   mapper.statuses.count == 2,
                   mapper.statuses.allSatisfy({ $0.error == nil && $0.externalPort != nil }) {
                    readySem.signal()
                }
            }
            mapper.onDeleteCompleted = { deleteSem.signal() }
            mapper.start(port: testPort)
        }

        var deleteSucceeded = false
        defer {
            loop.sync { mapper.stop() }
            deleteSucceeded = deleteSem.wait(timeout: .now() + 5) == .success
            print("[ASTOR_LIVE][UPnP] DeletePortMapping completed: \(deleteSucceeded)")
            #expect(deleteSucceeded, "Expected UPnP DeletePortMapping to complete")
        }

        let waitResult = readySem.wait(timeout: .now() + 8)
        let (statuses, extAddr) = loop.sync { (mapper.statuses, mapper.externalAddress) }
        for s in statuses {
            print("[ASTOR_LIVE][UPnP] Status: method=\(s.method) proto=\(s.proto) internal=\(s.internalPort) external=\(s.externalPort.map(String.init) ?? "nil") extIP=\(s.externalAddress?.description ?? "nil") error=\(s.error ?? "none")")
        }

        #expect(waitResult == .success, "Timed out waiting for live UPnP mapping")
        #expect(extAddr != nil)
        #expect(statuses.count == 2)
        #expect(statuses.allSatisfy { $0.method == "UPnP" && $0.error == nil && $0.externalPort != nil })
    }
}
