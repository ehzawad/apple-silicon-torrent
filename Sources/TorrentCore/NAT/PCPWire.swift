import Foundation

/// Transport protocol for a port mapping.
enum PortProtocol: CaseIterable, Hashable, Sendable {
    case tcp
    case udp

    var name: String {
        switch self {
        case .tcp: return "TCP"
        case .udp: return "UDP"
        }
    }

    /// IANA protocol number used in PCP MAP requests/responses (RFC 6887 §11.1).
    var pcpNumber: UInt8 {
        switch self {
        case .tcp: return 6
        case .udp: return 17
        }
    }

    /// NAT-PMP mapping opcode (RFC 6886 §3.3): 1 = UDP, 2 = TCP.
    var natpmpOpcode: UInt8 {
        switch self {
        case .udp: return 1
        case .tcp: return 2
        }
    }

    init?(pcpNumber: UInt8) {
        switch pcpNumber {
        case 6: self = .tcp
        case 17: self = .udp
        default: return nil
        }
    }

    init?(natpmpOpcode: UInt8) {
        switch natpmpOpcode {
        case 1: self = .udp
        case 2: self = .tcp
        default: return nil
        }
    }
}

// MARK: - PCP (RFC 6887)

/// PCP Result Codes (RFC 6887 §7.4).
enum PCPResultCode: UInt8, Sendable, Equatable, CustomStringConvertible {
    case success = 0
    case unsuppVersion = 1
    case notAuthorized = 2
    case malformedRequest = 3
    case unsuppOpcode = 4
    case unsuppOption = 5
    case malformedOption = 6
    case networkFailure = 7
    case noResources = 8
    case unsuppProtocol = 9
    case userExQuota = 10
    case cannotProvideExternal = 11
    case addressMismatch = 12
    case excessiveRemotePeers = 13

    var description: String {
        switch self {
        case .success: return "SUCCESS"
        case .unsuppVersion: return "UNSUPP_VERSION"
        case .notAuthorized: return "NOT_AUTHORIZED"
        case .malformedRequest: return "MALFORMED_REQUEST"
        case .unsuppOpcode: return "UNSUPP_OPCODE"
        case .unsuppOption: return "UNSUPP_OPTION"
        case .malformedOption: return "MALFORMED_OPTION"
        case .networkFailure: return "NETWORK_FAILURE"
        case .noResources: return "NO_RESOURCES"
        case .unsuppProtocol: return "UNSUPP_PROTOCOL"
        case .userExQuota: return "USER_EX_QUOTA"
        case .cannotProvideExternal: return "CANNOT_PROVIDE_EXTERNAL"
        case .addressMismatch: return "ADDRESS_MISMATCH"
        case .excessiveRemotePeers: return "EXCESSIVE_REMOTE_PEERS"
        }
    }
}

/// Stateless wire encoder/decoder for PCP (RFC 6887).
enum PCPWire {
    static let version: UInt8 = 2
    static let port: UInt16 = 5351
    static let opcodeAnnounce: UInt8 = 0
    static let opcodeMap: UInt8 = 1
    static let opcodePeer: UInt8 = 2
    static let responseBit: UInt8 = 0x80
    static let headerSize = 24
    static let mapPayloadSize = 36
    static let mapPacketSize = headerSize + mapPayloadSize // 60 bytes
    static let maxPacketSize = 1100

    struct MapResponse: Sendable, Equatable {
        let lifetime: UInt32
        let epoch: UInt32
        let nonce: Data
        let proto: PortProtocol
        let internalPort: UInt16
        let externalPort: UInt16
        let externalAddress: IPAddress
    }

    enum DecodedResponse: Sendable, Equatable {
        case map(MapResponse)
        case error(opcode: UInt8, resultCode: UInt8, lifetime: UInt32, epoch: UInt32, nonce: Data?, proto: PortProtocol?, internalPort: UInt16?)
        /// A NAT-PMP-only server replying to a PCP v2 request returns a v0 UNSUPP_VERSION error (RFC 6886 §3.5 / RFC 6887 §9).
        case natpmpUnsupportedVersion(opcode: UInt8, epoch: UInt32)
    }

    /// Encode an IPAddress in PCP's 128-bit format:
    /// IPv4 as `::ffff:a.b.c.d`, IPv6 as 16 raw bytes.
    /// When `ip == nil`, encodes `::` for IPv6 (`defaultV6 == true`) or `::ffff:0.0.0.0` for IPv4 (RFC 6887 §11.1 / §15.1).
    static func encodeAddress(_ ip: IPAddress?, defaultV6: Bool = false) -> [UInt8] {
        guard let ip else {
            if defaultV6 {
                return [UInt8](repeating: 0, count: 16)
            }
            return [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 0, 0, 0, 0]
        }
        switch ip {
        case .v4:
            return [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF] + ip.bytes
        case .v6:
            return ip.bytes
        }
    }

    /// Encode a 60-byte PCP MAP request (RFC 6887 §11.1).
    /// Pass `lifetime = 0`, `suggestedExternalPort = 0`, `suggestedExternalIP = nil` to delete a mapping (RFC 6887 §15.1).
    static func encodeMapRequest(
        clientIP: IPAddress,
        nonce: Data,
        proto: PortProtocol,
        internalPort: UInt16,
        suggestedExternalPort: UInt16,
        suggestedExternalIP: IPAddress? = nil,
        lifetime: UInt32
    ) -> Data {
        precondition(nonce.count == 12, "PCP mapping nonce must be 12 bytes")
        var out = Data()
        out.reserveCapacity(mapPacketSize)
        // Common 24-byte PCP request header
        out.append(version)              // 0: Version = 2
        out.append(opcodeMap)            // 1: R=0 | Opcode=1 (MAP)
        out.appendBE16(0)                // 2..3: Reserved
        out.appendBE32(lifetime)         // 4..7: Requested Lifetime
        out.append(contentsOf: encodeAddress(clientIP)) // 8..23: Client IP (128-bit)
        // 36-byte MAP opcode payload
        out.append(nonce)                // 24..35: Mapping Nonce (96-bit)
        out.append(proto.pcpNumber)      // 36: Protocol (6=TCP, 17=UDP)
        out.append(contentsOf: [0, 0, 0]) // 37..39: Reserved
        out.appendBE16(internalPort)     // 40..41: Internal Port
        out.appendBE16(suggestedExternalPort) // 42..43: Suggested External Port
        out.append(contentsOf: encodeAddress(suggestedExternalIP, defaultV6: clientIP.isV6)) // 44..59: Suggested External IP
        return out
    }

    /// Decode a PCP response (or a NAT-PMP v0 / PCP v1 UNSUPP_VERSION fallback reply per RFC 6886 §3.5 & RFC 6887 §9).
    static func decodeResponse(_ data: Data) -> DecodedResponse? {
        guard data.count >= 8, data.count <= maxPacketSize else { return nil }
        let ver = data.byte(0)
        let rOpcode = data.byte(1)

        // RFC 6886 §3.5 / RFC 6887 §9: A NAT-PMP-only server answers PCP v2 with an 8-byte v0 UNSUPP_VERSION reply.
        // Strictly compliant RFC 6886 servers send OP=0 (R bit 0), while some (e.g. MiniUPnPd) send OP=0x80|reqOP.
        if ver == NATPMPWire.version {
            guard data.count == 8,
                  (rOpcode == 0 || (rOpcode & responseBit) != 0) else { return nil }
            let result = data.be16(2)
            let epoch = data.be32(4)
            if result == NATPMPResultCode.unsupportedVersion.rawValue {
                return .natpmpUnsupportedVersion(opcode: rOpcode & 0x7F, epoch: epoch)
            }
            return nil
        }

        // Standard PCP response: R bit must be 1, >= 24 bytes, multiple of 4 bytes (RFC 6887 §7.2).
        guard (rOpcode & responseBit) != 0, data.count >= headerSize, data.count % 4 == 0 else { return nil }
        let opcode = rOpcode & 0x7F
        let resultCode = data.byte(3)
        let lifetime = data.be32(4)
        let epoch = data.be32(8)

        // Draft PCP v1 server replying with UNSUPP_VERSION (RFC 6887 §9) -> trigger fallback cleanly.
        if ver == 1 {
            guard resultCode == PCPResultCode.unsuppVersion.rawValue else { return nil }
            return .error(
                opcode: opcode,
                resultCode: resultCode,
                lifetime: lifetime,
                epoch: epoch,
                nonce: nil,
                proto: nil,
                internalPort: nil
            )
        }

        guard ver == version else { return nil }

        if resultCode != PCPResultCode.success.rawValue {
            var nonce: Data?
            var proto: PortProtocol?
            var internalPort: UInt16?
            if opcode == opcodeMap, data.count >= mapPacketSize {
                let s = data.startIndex
                nonce = Data(data[(s + 24)..<(s + 36)])
                proto = PortProtocol(pcpNumber: data.byte(36))
                internalPort = data.be16(40)
            }
            return .error(
                opcode: opcode,
                resultCode: resultCode,
                lifetime: lifetime,
                epoch: epoch,
                nonce: nonce,
                proto: proto,
                internalPort: internalPort
            )
        }

        guard opcode == opcodeMap, data.count >= mapPacketSize else { return nil }
        // Validate trailing PCP options (RFC 6887 §7.3): 4-byte header + 4-byte-padded payload.
        guard validateOptions(data, startingAt: mapPacketSize) else { return nil }

        let s = data.startIndex
        let nonce = Data(data[(s + 24)..<(s + 36)])
        guard let proto = PortProtocol(pcpNumber: data.byte(36)) else { return nil }
        let internalPort = data.be16(40)
        let externalPort = data.be16(42)
        guard let externalAddress = IPAddress(bytes: data[(s + 44)..<(s + 60)]) else { return nil }

        return .map(MapResponse(
            lifetime: lifetime,
            epoch: epoch,
            nonce: nonce,
            proto: proto,
            internalPort: internalPort,
            externalPort: externalPort,
            externalAddress: externalAddress
        ))
    }

    /// Validate structural framing of trailing PCP Options (RFC 6887 §7.3).
    /// Rejects truncated/out-of-bounds options and unrequested mandatory-to-process options (`code < 128`).
    private static func validateOptions(_ data: Data, startingAt start: Int) -> Bool {
        var off = start
        while off < data.count {
            guard off + 4 <= data.count else { return false }
            let code = data.byte(off)
            let optLen = Int(data.be16(off + 2))
            // RFC 6887 §7.3: option data is padded to a multiple of 4 octets.
            let paddedLen = (optLen + 3) & ~3
            guard paddedLen <= data.count - (off + 4) else { return false }
            // We do not send mandatory options (0..127); reject unexpected mandatory options in responses.
            if code < 128 { return false }
            off += 4 + paddedLen
        }
        return off == data.count
    }

    static func describeResultCode(_ raw: UInt8) -> String {
        if let known = PCPResultCode(rawValue: raw) { return "\(known.description) (\(raw))" }
        return "PCP_ERROR_\(raw)"
    }
}

// MARK: - NAT-PMP (RFC 6886)

/// NAT-PMP Result Codes (RFC 6886 §3.5).
enum NATPMPResultCode: UInt16, Sendable, Equatable, CustomStringConvertible {
    case success = 0
    case unsupportedVersion = 1
    case notAuthorized = 2
    case networkFailure = 3
    case outOfResources = 4
    case unsupportedOpcode = 5

    var description: String {
        switch self {
        case .success: return "SUCCESS"
        case .unsupportedVersion: return "UNSUPPORTED_VERSION"
        case .notAuthorized: return "NOT_AUTHORIZED"
        case .networkFailure: return "NETWORK_FAILURE"
        case .outOfResources: return "OUT_OF_RESOURCES"
        case .unsupportedOpcode: return "UNSUPPORTED_OPCODE"
        }
    }
}

/// Stateless wire encoder/decoder for NAT-PMP (RFC 6886).
enum NATPMPWire {
    static let version: UInt8 = 0
    static let port: UInt16 = 5351
    static let opcodeExternalAddress: UInt8 = 0
    static let opcodeMapUDP: UInt8 = 1
    static let opcodeMapTCP: UInt8 = 2
    static let responseBit: UInt8 = 0x80

    struct ExternalAddressResponse: Sendable, Equatable {
        let resultCode: UInt16
        let epoch: UInt32
        let externalAddress: IPAddress?
    }

    struct MapResponse: Sendable, Equatable {
        let proto: PortProtocol
        let resultCode: UInt16
        let epoch: UInt32
        let internalPort: UInt16
        let externalPort: UInt16
        let lifetime: UInt32
    }

    enum DecodedResponse: Sendable, Equatable {
        case externalAddress(ExternalAddressResponse)
        case map(MapResponse)
        case error(opcode: UInt8, resultCode: UInt16, epoch: UInt32)
    }

    /// Encode a 2-byte NAT-PMP external address request (RFC 6886 §3.2).
    static func encodeExternalAddressRequest() -> Data {
        Data([version, opcodeExternalAddress])
    }

    /// Encode a 12-byte NAT-PMP mapping request (RFC 6886 §3.3).
    /// Pass `lifetime = 0` and `suggestedExternalPort = 0` to destroy a mapping (RFC 6886 §3.4).
    static func encodeMapRequest(
        proto: PortProtocol,
        internalPort: UInt16,
        suggestedExternalPort: UInt16,
        lifetime: UInt32
    ) -> Data {
        var out = Data()
        out.reserveCapacity(12)
        out.append(version)              // 0: Version = 0
        out.append(proto.natpmpOpcode)   // 1: Opcode (1=UDP, 2=TCP)
        out.appendBE16(0)                // 2..3: Reserved
        out.appendBE16(internalPort)     // 4..5: Internal Port
        out.appendBE16(suggestedExternalPort) // 6..7: Suggested External Port
        out.appendBE32(lifetime)         // 8..11: Requested Lifetime
        return out
    }

    /// Decode a NAT-PMP response (RFC 6886 §3.2, §3.3, §3.5).
    static func decodeResponse(_ data: Data) -> DecodedResponse? {
        guard data.count >= 8 else { return nil }
        guard data.byte(0) == version else { return nil }
        let rOpcode = data.byte(1)
        let resultCode = data.be16(2)
        let epoch = data.be32(4)

        // RFC 6886 §3.5: Unsupported Version response has OP = 0 (R bit 0), result = 1, 8 bytes.
        if rOpcode == 0 {
            guard data.count == 8, resultCode == NATPMPResultCode.unsupportedVersion.rawValue else { return nil }
            return .error(opcode: 0, resultCode: resultCode, epoch: epoch)
        }

        guard (rOpcode & responseBit) != 0 else { return nil }
        let opcode = rOpcode & 0x7F

        switch opcode {
        case opcodeExternalAddress:
            if resultCode != NATPMPResultCode.success.rawValue {
                guard data.count == 8 || data.count == 12 else { return nil }
                return .externalAddress(ExternalAddressResponse(
                    resultCode: resultCode,
                    epoch: epoch,
                    externalAddress: nil
                ))
            }
            guard data.count == 12 else { return nil }
            let s = data.startIndex
            let ip = IPAddress(bytes: data[(s + 8)..<(s + 12)])
            return .externalAddress(ExternalAddressResponse(
                resultCode: resultCode,
                epoch: epoch,
                externalAddress: ip
            ))

        case opcodeMapUDP, opcodeMapTCP:
            guard let proto = PortProtocol(natpmpOpcode: opcode) else { return nil }
            if resultCode != NATPMPResultCode.success.rawValue {
                if data.count == 16 {
                    return .map(MapResponse(
                        proto: proto,
                        resultCode: resultCode,
                        epoch: epoch,
                        internalPort: data.be16(8),
                        externalPort: data.be16(10),
                        lifetime: data.be32(12)
                    ))
                }
                guard data.count == 8 else { return nil }
                return .error(opcode: opcode, resultCode: resultCode, epoch: epoch)
            }
            guard data.count == 16 else { return nil }
            return .map(MapResponse(
                proto: proto,
                resultCode: resultCode,
                epoch: epoch,
                internalPort: data.be16(8),
                externalPort: data.be16(10),
                lifetime: data.be32(12)
            ))

        default:
            guard resultCode != NATPMPResultCode.success.rawValue, data.count == 8 else { return nil }
            return .error(opcode: opcode, resultCode: resultCode, epoch: epoch)
        }
    }

    static func describeResultCode(_ raw: UInt16) -> String {
        if let known = NATPMPResultCode(rawValue: raw) { return "\(known.description) (\(raw))" }
        return "NATPMP_ERROR_\(raw)"
    }
}
