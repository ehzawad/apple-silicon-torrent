import Foundation
import Darwin

/// Status of one port-mapping attempt or active mapping (TCP or UDP).
public struct PortMappingStatus: Sendable, Equatable {
    public var method: String          // "PCP", "NAT-PMP", "UPnP"
    public var proto: String           // "TCP" / "UDP"
    public var internalPort: UInt16
    public var externalPort: UInt16?
    public var externalAddress: IPAddress?
    public var error: String?

    public init(
        method: String,
        proto: String,
        internalPort: UInt16,
        externalPort: UInt16? = nil,
        externalAddress: IPAddress? = nil,
        error: String? = nil
    ) {
        self.method = method
        self.proto = proto
        self.internalPort = internalPort
        self.externalPort = externalPort
        self.externalAddress = externalAddress
        self.error = error
    }
}

/// Maps TCP and UDP ports through the local NAT gateway using:
///  1. PCP (RFC 6887) -> NAT-PMP (RFC 6886) fallback to the default gateway on UDP 5351, and
///  2. UPnP IGD v1/v2 (SSDP + rootDesc.xml + SOAP) in parallel.
///
/// Whichever method succeeds first wins; active leases (1 h) are renewed at 50% of
/// the granted lifetime and deleted best-effort on `stop()`.
///
/// Threading: loop-confined (`@unchecked Sendable`); all public instance members must
/// be called on `loop.queue`. Never blocks the EventLoop.
public final class PortMapper: @unchecked Sendable {
    enum Method: Hashable, Sendable {
        case pcp
        case natpmp
        case upnp

        var displayName: String {
            switch self {
            case .pcp: return "PCP"
            case .natpmp: return "NAT-PMP"
            case .upnp: return "UPnP"
            }
        }
    }

    private enum GatewayMode {
        case idle
        case pcp
        case natpmp
        case done
    }

    private struct ActiveMapping {
        var method: Method
        var proto: PortProtocol
        var internalPort: UInt16
        var externalPort: UInt16
        var leaseDuration: UInt32
        var pcpNonce: Data?
        var upnpService: UPnPService?
        var upnpClientIP: String?
        var lastRenewalError: String?
        var renewTimer: LoopTimer?
    }

    // Configuration
    private let loop: EventLoop
    private let enabledMethods: Set<Method>
    private let requestedLease: UInt32
    private let gatewayOverride: IPAddress?
    private let gatewayPort: UInt16
    private let clientIPOverride: IPAddress?
    private let initialRetransmit: Double
    private let pcpMaxAttempts: Int
    private let natpmpMaxAttempts: Int
    private let ssdpRetryDelays: [Double]
    private let ssdpDiscoveryTimeout: Double
    private let ssdpTargetOverride: PeerAddress?

    // Lifecycle
    private var isRunning = false
    private var generation: UInt64 = 0
    private var mappedPort: UInt16 = 0
    private var resolvedGateway: IPAddress?
    private var resolvedClientIP: IPAddress?

    // Published state
    private var _statuses: [PortMappingStatus] = []
    private var _externalAddress: IPAddress?
    private var lastReportedExternalAddress: IPAddress?
    private var _onChange: (() -> Void)?

    public var onChange: (() -> Void)? {
        get {
            loop.assertInLoop()
            return _onChange
        }
        set {
            loop.assertInLoop()
            _onChange = newValue
        }
    }

    /// Optional internal hook invoked on `loop` after async `stop()` deletions finish (for tests).
    var onDeleteCompleted: (@Sendable () -> Void)?

    // Active mappings & per-backend failure state
    private var activeMappings: [PortProtocol: ActiveMapping] = [:]
    private var gatewayErrors: [PortProtocol: (method: String, error: String)] = [:]
    private var upnpErrors: [PortProtocol: String] = [:]
    private var gatewayDone = false
    private var upnpDone = false

    // PCP / NAT-PMP state
    private var gwSocket: UDPSocket?
    private var gwMode: GatewayMode = .idle
    private var gwTimer: LoopTimer?
    private var gwAttempt = 0
    private var gwDelay: Double = 0.25
    private var gwPendingProtos: Set<PortProtocol> = []
    private var gwNeedExternalIP = false
    private var pcpNonces: [PortProtocol: Data] = [:]
    private var gwLastEpoch: UInt32?
    private var gwLastEpochAt: Double?

    // UPnP state
    private var ssdpSocket: UDPSocket?
    private var ssdpTimer: LoopTimer?
    private var ssdpAttempt = 0
    private var ssdpTimedOut = false
    private var seenLocations: Set<String> = []
    private var pendingDescFetches = 0
    private var chosenUPnPService: UPnPService?
    private var upnpClientIP: String?
    private var upnpInFlightMaps: Set<PortProtocol> = []
    private var urlSession: URLSession?

    private var allowLoopbackUPnP: Bool { ssdpTargetOverride != nil }

    // MARK: - Public API

    public convenience init(loop: EventLoop) {
        self.init(
            loop: loop,
            methods: [.pcp, .natpmp, .upnp],
            leaseDuration: 3600,
            gatewayOverride: nil,
            gatewayPort: PCPWire.port,
            clientIPOverride: nil,
            initialRetransmit: 0.25,
            pcpMaxAttempts: 3,
            natpmpMaxAttempts: 5,
            ssdpRetryDelays: [0.5, 1.5],
            ssdpDiscoveryTimeout: 3.0,
            ssdpTargetOverride: nil
        )
    }

    init(
        loop: EventLoop,
        methods: Set<Method>,
        leaseDuration: UInt32 = 3600,
        gatewayOverride: IPAddress? = nil,
        gatewayPort: UInt16 = PCPWire.port,
        clientIPOverride: IPAddress? = nil,
        initialRetransmit: Double = 0.25,
        pcpMaxAttempts: Int = 3,
        natpmpMaxAttempts: Int = 5,
        ssdpRetryDelays: [Double] = [0.5, 1.5],
        ssdpDiscoveryTimeout: Double = 3.0,
        ssdpTargetOverride: PeerAddress? = nil
    ) {
        self.loop = loop
        self.enabledMethods = methods
        self.requestedLease = leaseDuration
        self.gatewayOverride = gatewayOverride
        self.gatewayPort = gatewayPort
        self.clientIPOverride = clientIPOverride
        self.initialRetransmit = initialRetransmit
        self.pcpMaxAttempts = max(1, pcpMaxAttempts)
        self.natpmpMaxAttempts = max(1, natpmpMaxAttempts)
        self.ssdpRetryDelays = ssdpRetryDelays
        self.ssdpDiscoveryTimeout = ssdpDiscoveryTimeout
        self.ssdpTargetOverride = ssdpTargetOverride
    }

    /// Map TCP and UDP for `port` and renew automatically before lease expiry.
    public func start(port: UInt16) {
        loop.assertInLoop()
        guard port > 0 else { return }
        if isRunning {
            // Avoid racing an async UPnP DeletePortMapping against a fresh AddPortMapping on the same port.
            teardown(skipDeletingPort: port, notifyDeleteHook: false)
        }

        generation &+= 1
        isRunning = true
        mappedPort = port
        activeMappings.removeAll()
        gatewayErrors.removeAll()
        upnpErrors.removeAll()
        _statuses = []
        _externalAddress = nil
        lastReportedExternalAddress = nil
        gwLastEpoch = nil
        gwLastEpochAt = nil
        pcpNonces = [.tcp: Data.random(12), .udp: Data.random(12)]

        resolvedGateway = gatewayOverride ?? Self.defaultGateway()
        if let gw = resolvedGateway {
            resolvedClientIP = clientIPOverride ?? LocalNetwork.localIPv4Address(for: gw)
        } else {
            resolvedClientIP = clientIPOverride
        }

        let wantGateway = enabledMethods.contains(.pcp) || enabledMethods.contains(.natpmp)
        let wantUPnP = enabledMethods.contains(.upnp)
        gatewayDone = !wantGateway
        upnpDone = !wantUPnP

        if wantGateway {
            startGatewayBackend()
        }
        if wantUPnP {
            startUPnPBackend()
        }
        recomputeStatuses()
    }

    /// Best-effort delete all active mappings, cancel timers, and close sockets.
    public func stop() {
        loop.assertInLoop()
        teardown(skipDeletingPort: nil, notifyDeleteHook: true)
    }

    private func teardown(skipDeletingPort: UInt16?, notifyDeleteHook: Bool) {
        generation &+= 1
        let wasRunning = isRunning
        isRunning = false

        gwTimer?.cancel()
        gwTimer = nil
        ssdpTimer?.cancel()
        ssdpTimer = nil

        let mappings = Array(activeMappings.values)
        for m in mappings {
            m.renewTimer?.cancel()
        }
        activeMappings.removeAll()
        gatewayErrors.removeAll()
        upnpErrors.removeAll()
        gwPendingProtos.removeAll()
        gwNeedExternalIP = false
        gwMode = .idle
        gatewayDone = false
        upnpDone = false
        seenLocations.removeAll()
        pendingDescFetches = 0
        chosenUPnPService = nil
        upnpClientIP = nil
        upnpInFlightMaps.removeAll()
        ssdpTimedOut = false

        let toDelete = mappings.filter { m in
            guard let skip = skipDeletingPort else { return true }
            return m.internalPort != skip && m.externalPort != skip
        }

        // Best-effort UDP deletions (PCP / NAT-PMP) before closing gwSocket.
        if wasRunning, let gw = resolvedGateway, let sock = gwSocket {
            let target = PeerAddress(ip: gw, port: gatewayPort)
            for m in toDelete {
                switch m.method {
                case .pcp:
                    if let clientIP = resolvedClientIP, let nonce = m.pcpNonce {
                        let pkt = PCPWire.encodeMapRequest(
                            clientIP: clientIP,
                            nonce: nonce,
                            proto: m.proto,
                            internalPort: m.internalPort,
                            suggestedExternalPort: 0,
                            suggestedExternalIP: nil,
                            lifetime: 0
                        )
                        sock.send(pkt, to: target)
                    }
                case .natpmp:
                    let pkt = NATPMPWire.encodeMapRequest(
                        proto: m.proto,
                        internalPort: m.internalPort,
                        suggestedExternalPort: 0,
                        lifetime: 0
                    )
                    sock.send(pkt, to: target)
                case .upnp:
                    break
                }
            }
        }

        gwSocket?.close()
        gwSocket = nil
        ssdpSocket?.close()
        ssdpSocket = nil
        urlSession?.invalidateAndCancel()
        urlSession = nil

        _statuses = []
        _externalAddress = nil
        lastReportedExternalAddress = nil

        // Best-effort async UPnP DeletePortMapping requests (never block the EventLoop).
        let upnpDeletes = toDelete.compactMap { m -> (UPnPService, UInt16, PortProtocol)? in
            guard m.method == .upnp, let svc = m.upnpService else { return nil }
            return (svc, m.externalPort, m.proto)
        }
        let completionHook = notifyDeleteHook ? onDeleteCompleted : nil
        if !upnpDeletes.isEmpty {
            sendUPnPDeletes(upnpDeletes, completion: completionHook)
        } else if let completionHook {
            loop.execute { completionHook() }
        }
    }

    public var statuses: [PortMappingStatus] {
        loop.assertInLoop()
        return _statuses
    }

    public var externalAddress: IPAddress? {
        loop.assertInLoop()
        return _externalAddress
    }

    /// Discover the IPv4 default gateway on a physical interface via the Darwin
    /// `sysctl(NET_RT_FLAGS, RTF_GATEWAY)` route table dump (skipping tunnel interfaces).
    public static func defaultGateway() -> IPAddress? {
        RouteDiscovery.defaultGateway()
    }

    deinit {
        // `deinit` may execute off `loop.queue` (e.g. when a URLSession callback releases the last ref).
        // `URLSession.invalidateAndCancel()` is thread-safe; timers and sockets must be closed on `loop.queue`.
        urlSession?.invalidateAndCancel()
        var timers: [LoopTimer] = []
        if let t = gwTimer { timers.append(t) }
        if let t = ssdpTimer { timers.append(t) }
        for m in activeMappings.values {
            if let t = m.renewTimer { timers.append(t) }
        }
        var sockets: [UDPSocket] = []
        if let s = gwSocket { sockets.append(s) }
        if let s = ssdpSocket { sockets.append(s) }
        if !timers.isEmpty || !sockets.isEmpty {
            let capturedTimers = timers
            let capturedSockets = sockets
            loop.run {
                for t in capturedTimers { t.cancel() }
                for s in capturedSockets { s.close() }
            }
        }
    }

    // MARK: - PCP / NAT-PMP Backend

    private func startGatewayBackend() {
        guard let gw = resolvedGateway, gw.isV4 else {
            let err = "no default IPv4 gateway found"
            for proto in PortProtocol.allCases {
                gatewayErrors[proto] = (enabledMethods.contains(.pcp) ? "PCP" : "NAT-PMP", err)
            }
            gwMode = .done
            gatewayDone = true
            return
        }

        let canRunPCP = enabledMethods.contains(.pcp) && resolvedClientIP != nil
        let canRunNATPMP = enabledMethods.contains(.natpmp)
        guard canRunPCP || canRunNATPMP else {
            for proto in PortProtocol.allCases {
                gatewayErrors[proto] = ("PCP", "unable to determine local LAN IPv4 address")
            }
            gwMode = .done
            gatewayDone = true
            return
        }

        do {
            let sock = try UDPSocket(port: 0, v6: false, loop: loop)
            sock.onDatagram = { [weak self] data, from in
                self?.handleGatewayDatagram(data, from: from)
            }
            sock.start()
            gwSocket = sock
        } catch {
            for proto in PortProtocol.allCases {
                gatewayErrors[proto] = (canRunPCP ? "PCP" : "NAT-PMP", "socket error: \(error)")
            }
            gwMode = .done
            gatewayDone = true
            return
        }

        gwPendingProtos = Set(PortProtocol.allCases)

        if canRunPCP {
            gwMode = .pcp
            gwAttempt = 0
            gwDelay = initialRetransmit
            sendPCPRequests()
        } else {
            startNATPMP(fallbackError: "NAT-PMP")
        }
    }

    private func sendPCPRequests() {
        guard isRunning, gwMode == .pcp, !gwPendingProtos.isEmpty,
              let gw = resolvedGateway, let clientIP = resolvedClientIP, let sock = gwSocket else {
            return
        }
        let target = PeerAddress(ip: gw, port: gatewayPort)
        for proto in PortProtocol.allCases where gwPendingProtos.contains(proto) {
            sendSinglePCPRequest(proto: proto, clientIP: clientIP, target: target, sock: sock)
        }

        gwTimer?.cancel()
        let delay = gwDelay
        gwTimer = loop.schedule(after: delay) { [weak self] in
            self?.onPCPTimeout()
        }
    }

    private func sendSinglePCPRequest(proto: PortProtocol, clientIP: IPAddress, target: PeerAddress, sock: UDPSocket) {
        let nonce = pcpNonces[proto] ?? Data.random(12)
        pcpNonces[proto] = nonce
        let suggestedPort = activeMappings[proto]?.externalPort ?? mappedPort
        let suggestedIP = _externalAddress
        let pkt = PCPWire.encodeMapRequest(
            clientIP: clientIP,
            nonce: nonce,
            proto: proto,
            internalPort: mappedPort,
            suggestedExternalPort: suggestedPort,
            suggestedExternalIP: suggestedIP,
            lifetime: requestedLease
        )
        sock.send(pkt, to: target)
    }

    private func onPCPTimeout() {
        guard isRunning, gwMode == .pcp, !gwPendingProtos.isEmpty else { return }
        gwAttempt += 1
        if gwAttempt >= pcpMaxAttempts {
            if enabledMethods.contains(.natpmp), activeMappings.values.allSatisfy({ $0.method != .pcp }) {
                startNATPMP(fallbackError: "timed out")
            } else {
                for proto in gwPendingProtos {
                    recordGatewayFailure(proto: proto, method: .pcp, error: "timed out")
                }
                gwPendingProtos.removeAll()
                gwTimer = nil
                finishGatewayIdleIfNoActiveMappings()
                recomputeStatuses()
            }
            return
        }
        gwDelay *= 2
        sendPCPRequests()
    }

    private func startNATPMP(fallbackError: String) {
        gwTimer?.cancel()
        gwTimer = nil
        guard isRunning, enabledMethods.contains(.natpmp) else {
            for proto in gwPendingProtos {
                recordGatewayFailure(proto: proto, method: .pcp, error: fallbackError)
            }
            gwPendingProtos.removeAll()
            finishGatewayIdleIfNoActiveMappings()
            recomputeStatuses()
            return
        }
        gwMode = .natpmp
        gwAttempt = 0
        gwDelay = initialRetransmit
        gwNeedExternalIP = (_externalAddress == nil)
        if gwPendingProtos.isEmpty {
            gwPendingProtos = Set(PortProtocol.allCases.filter { activeMappings[$0] == nil })
        }
        if gwPendingProtos.isEmpty && !gwNeedExternalIP {
            finishGatewayIdleIfNoActiveMappings()
            recomputeStatuses()
            return
        }
        sendNATPMPRequests()
    }

    private func sendNATPMPRequests() {
        guard isRunning, gwMode == .natpmp,
              let gw = resolvedGateway, let sock = gwSocket else {
            return
        }
        guard !gwPendingProtos.isEmpty || gwNeedExternalIP else { return }
        let target = PeerAddress(ip: gw, port: gatewayPort)

        if gwNeedExternalIP {
            sock.send(NATPMPWire.encodeExternalAddressRequest(), to: target)
        }
        for proto in PortProtocol.allCases where gwPendingProtos.contains(proto) {
            sendSingleNATPMPRequest(proto: proto, target: target, sock: sock)
        }

        gwTimer?.cancel()
        let delay = gwDelay
        gwTimer = loop.schedule(after: delay) { [weak self] in
            self?.onNATPMPTimeout()
        }
    }

    private func sendSingleNATPMPRequest(proto: PortProtocol, target: PeerAddress, sock: UDPSocket) {
        let suggestedPort = activeMappings[proto]?.externalPort ?? mappedPort
        let pkt = NATPMPWire.encodeMapRequest(
            proto: proto,
            internalPort: mappedPort,
            suggestedExternalPort: suggestedPort,
            lifetime: requestedLease
        )
        sock.send(pkt, to: target)
    }

    private func onNATPMPTimeout() {
        guard isRunning, gwMode == .natpmp else { return }
        guard !gwPendingProtos.isEmpty || gwNeedExternalIP else { return }
        gwAttempt += 1
        if gwAttempt >= natpmpMaxAttempts {
            for proto in gwPendingProtos {
                recordGatewayFailure(proto: proto, method: .natpmp, error: "timed out")
            }
            gwPendingProtos.removeAll()
            gwNeedExternalIP = false
            gwTimer = nil
            finishGatewayIdleIfNoActiveMappings()
            recomputeStatuses()
            return
        }
        gwDelay *= 2
        sendNATPMPRequests()
    }

    private func handleGatewayDatagram(_ data: Data, from: PeerAddress) {
        guard isRunning, let gw = resolvedGateway else { return }
        // RFC 6886 §3.2.1 / RFC 6887 §8.3: ignore packets not from the gateway on port 5351.
        guard from.ip == gw, from.port == gatewayPort else { return }

        switch gwMode {
        case .pcp:
            handlePCPResponse(data)
        case .natpmp:
            handleNATPMPResponse(data)
        case .idle, .done:
            break
        }
    }

    private func handlePCPResponse(_ data: Data) {
        guard let decoded = PCPWire.decodeResponse(data) else { return }
        switch decoded {
        case .natpmpUnsupportedVersion:
            guard activeMappings.values.allSatisfy({ $0.method != .pcp }) else { return }
            startNATPMP(fallbackError: "UNSUPP_VERSION")

        case .error(_, let code, _, let epoch, let nonce, let proto, let respInternalPort):
            // RFC 6887 §11.3: if a 60-byte error response carries a nonce/proto/port, it MUST match
            // our pending request; mismatched packets belong to another client or stale request -> ignore.
            if let nonce {
                guard let proto,
                      pcpNonces[proto] == nonce,
                      respInternalPort == nil || respInternalPort == mappedPort,
                      gwPendingProtos.contains(proto) else {
                    return
                }
            }

            let errText = PCPWire.describeResultCode(code)
            let shouldFallback = code == PCPResultCode.unsuppVersion.rawValue
                || code == PCPResultCode.unsuppOpcode.rawValue
                || code == PCPResultCode.malformedRequest.rawValue
            if shouldFallback, activeMappings.values.allSatisfy({ $0.method != .pcp }) {
                startNATPMP(fallbackError: errText)
                return
            }

            let rebooted = checkEpochReset(epoch)
            if let proto, nonce != nil {
                gwPendingProtos.remove(proto)
                recordGatewayFailure(proto: proto, method: .pcp, error: errText)
            } else {
                for p in gwPendingProtos {
                    recordGatewayFailure(proto: p, method: .pcp, error: errText)
                }
                gwPendingProtos.removeAll()
            }
            if gwPendingProtos.isEmpty {
                gwTimer?.cancel()
                gwTimer = nil
                finishGatewayIdleIfNoActiveMappings()
            }
            if rebooted {
                remapOtherGatewayMappings(excluding: proto)
            }
            recomputeStatuses()

        case .map(let resp):
            guard resp.internalPort == mappedPort,
                  pcpNonces[resp.proto] == resp.nonce,
                  gwPendingProtos.contains(resp.proto) else {
                return
            }
            // Do not overwrite a mapping already won by UPnP.
            if let existing = activeMappings[resp.proto], existing.method != .pcp {
                gwPendingProtos.remove(resp.proto)
                if gwPendingProtos.isEmpty {
                    gwTimer?.cancel()
                    gwTimer = nil
                    finishGatewayIdleIfNoActiveMappings()
                }
                return
            }

            let rebooted = checkEpochReset(resp.epoch)
            gwPendingProtos.remove(resp.proto)

            // RFC 6887 §11.1 / §15.1: lifetime == 0 or externalPort == 0 means no active mapping.
            guard resp.externalPort > 0, resp.lifetime > 0 else {
                let reason = resp.lifetime == 0 ? "server returned zero lifetime" : "server returned external port 0"
                recordGatewayFailure(proto: resp.proto, method: .pcp, error: reason)
                if gwPendingProtos.isEmpty {
                    gwTimer?.cancel()
                    gwTimer = nil
                    finishGatewayIdleIfNoActiveMappings()
                }
                recomputeStatuses()
                return
            }

            if !resp.externalAddress.isUnusable {
                _externalAddress = resp.externalAddress
            }
            gatewayErrors.removeValue(forKey: resp.proto)

            installMapping(
                method: .pcp,
                proto: resp.proto,
                externalPort: resp.externalPort,
                leaseDuration: resp.lifetime,
                pcpNonce: resp.nonce
            )

            if gwPendingProtos.isEmpty {
                gwTimer?.cancel()
                gwTimer = nil
                gatewayDone = true
            }
            if allProtocolsMapped {
                cancelPendingUPnP()
            }
            if rebooted {
                remapOtherGatewayMappings(excluding: resp.proto)
            }
            recomputeStatuses()
        }
    }

    private func handleNATPMPResponse(_ data: Data) {
        guard let decoded = NATPMPWire.decodeResponse(data) else { return }
        switch decoded {
        case .externalAddress(let ext):
            guard gwNeedExternalIP else { return }
            let rebooted = checkEpochReset(ext.epoch)
            gwNeedExternalIP = false
            if ext.resultCode == NATPMPResultCode.success.rawValue,
               let ip = ext.externalAddress, !ip.isUnusable {
                _externalAddress = ip
            }
            if gwPendingProtos.isEmpty && !gwNeedExternalIP {
                gwTimer?.cancel()
                gwTimer = nil
                finishGatewayIdleIfNoActiveMappings()
            }
            if rebooted {
                remapOtherGatewayMappings(excluding: nil)
            }
            recomputeStatuses()

        case .map(let resp):
            guard gwPendingProtos.contains(resp.proto) else { return }
            // Do not overwrite a mapping already won by UPnP.
            if let existing = activeMappings[resp.proto], existing.method != .natpmp {
                gwPendingProtos.remove(resp.proto)
                if gwPendingProtos.isEmpty && !gwNeedExternalIP {
                    gwTimer?.cancel()
                    gwTimer = nil
                    finishGatewayIdleIfNoActiveMappings()
                }
                return
            }

            if resp.resultCode == NATPMPResultCode.success.rawValue {
                guard resp.internalPort == mappedPort else { return }
                let rebooted = checkEpochReset(resp.epoch)
                gwPendingProtos.remove(resp.proto)

                // RFC 6886 §3.4: lifetime == 0 means deleted/no mapping.
                guard resp.externalPort > 0, resp.lifetime > 0 else {
                    let reason = resp.lifetime == 0 ? "server returned zero lifetime" : "server returned external port 0"
                    recordGatewayFailure(proto: resp.proto, method: .natpmp, error: reason)
                    if gwPendingProtos.isEmpty && !gwNeedExternalIP {
                        gwTimer?.cancel()
                        gwTimer = nil
                        finishGatewayIdleIfNoActiveMappings()
                    }
                    recomputeStatuses()
                    return
                }

                gatewayErrors.removeValue(forKey: resp.proto)
                installMapping(
                    method: .natpmp,
                    proto: resp.proto,
                    externalPort: resp.externalPort,
                    leaseDuration: resp.lifetime
                )
                if allProtocolsMapped {
                    cancelPendingUPnP()
                }
                if rebooted {
                    remapOtherGatewayMappings(excluding: resp.proto)
                }
            } else {
                guard resp.internalPort == mappedPort || resp.internalPort == 0 else { return }
                let rebooted = checkEpochReset(resp.epoch)
                gwPendingProtos.remove(resp.proto)
                recordGatewayFailure(
                    proto: resp.proto,
                    method: .natpmp,
                    error: NATPMPWire.describeResultCode(resp.resultCode)
                )
                if rebooted {
                    remapOtherGatewayMappings(excluding: resp.proto)
                }
            }
            if gwPendingProtos.isEmpty && !gwNeedExternalIP {
                gwTimer?.cancel()
                gwTimer = nil
                finishGatewayIdleIfNoActiveMappings()
            }
            recomputeStatuses()

        case .error(let opcode, let code, let epoch):
            // We only send NAT-PMP version 0 here; any trailing UNSUPPORTED_VERSION reply
            // belongs to the second in-flight PCP v2 probe sent before fallback -> ignore.
            if code == NATPMPResultCode.unsupportedVersion.rawValue {
                return
            }
            let errText = NATPMPWire.describeResultCode(code)
            let rebooted = checkEpochReset(epoch)
            if opcode == NATPMPWire.opcodeExternalAddress {
                gwNeedExternalIP = false
            } else if let proto = PortProtocol(natpmpOpcode: opcode) {
                guard gwPendingProtos.contains(proto) else { return }
                gwPendingProtos.remove(proto)
                recordGatewayFailure(proto: proto, method: .natpmp, error: errText)
            } else {
                for p in gwPendingProtos {
                    recordGatewayFailure(proto: p, method: .natpmp, error: errText)
                }
                gwPendingProtos.removeAll()
                gwNeedExternalIP = false
            }
            if gwPendingProtos.isEmpty && !gwNeedExternalIP {
                gwTimer?.cancel()
                gwTimer = nil
                finishGatewayIdleIfNoActiveMappings()
            }
            if rebooted {
                remapOtherGatewayMappings(excluding: nil)
            }
            recomputeStatuses()
        }
    }

    private func recordGatewayFailure(proto: PortProtocol, method: Method, error: String) {
        gatewayErrors[proto] = (method.displayName, error)
        if var active = activeMappings[proto], active.method == method {
            active.lastRenewalError = error
            activeMappings[proto] = active
            scheduleRenewalRetryIfActive(proto: proto, expectedMethod: method)
        }
    }

    private func finishGatewayIdleIfNoActiveMappings() {
        gatewayDone = true
        if activeMappings.values.allSatisfy({ $0.method != .pcp && $0.method != .natpmp }) {
            gwMode = .done
            gwSocket?.close()
            gwSocket = nil
        }
    }

    /// Pure RFC 6887 §8.5 / RFC 6886 §3.6 epoch discontinuity detector (64-bit safe, no UInt32 overflow).
    static func isEpochReset(prev: UInt32, current: UInt32, clientElapsed: Double) -> Bool {
        let serverDelta = Int64(current) - Int64(prev)
        if serverDelta < -1 {
            return true
        }
        let sd = Double(serverDelta)
        let cd = max(0.0, clientElapsed)
        // RFC 6887 §8.5: server clock diverged beyond 1/16 (6.25%) + small quantization slack.
        if cd + 3.0 < sd * (15.0 / 16.0) {
            return true
        }
        if sd + 3.0 < cd * (15.0 / 16.0) {
            return true
        }
        return false
    }

    /// Detect gateway reboot via epoch discontinuity (RFC 6886 §3.6 / RFC 6887 §8.5).
    @discardableResult
    private func checkEpochReset(_ epoch: UInt32) -> Bool {
        let now = monotonicNow()
        defer {
            gwLastEpoch = epoch
            gwLastEpochAt = now
        }
        guard let prev = gwLastEpoch, let prevAt = gwLastEpochAt else { return false }
        return Self.isEpochReset(prev: prev, current: epoch, clientElapsed: now - prevAt)
    }

    private func remapOtherGatewayMappings(excluding justMapped: PortProtocol?) {
        let toRemap = activeMappings.values.filter {
            ($0.method == .pcp || $0.method == .natpmp) && $0.proto != justMapped
        }
        guard !toRemap.isEmpty else { return }
        for m in toRemap {
            gwPendingProtos.insert(m.proto)
        }
        gwAttempt = 0
        gwDelay = initialRetransmit
        if gwMode == .pcp {
            sendPCPRequests()
        } else if gwMode == .natpmp {
            sendNATPMPRequests()
        }
    }

    private func cancelPendingGatewayProbes() {
        gwTimer?.cancel()
        gwTimer = nil
        gwPendingProtos.removeAll()
        gwNeedExternalIP = false
        finishGatewayIdleIfNoActiveMappings()
    }

    // MARK: - UPnP IGD Backend

    private func startUPnPBackend() {
        let cfg = URLSessionConfiguration.ephemeral
        cfg.timeoutIntervalForRequest = 5
        cfg.timeoutIntervalForResource = 10
        cfg.requestCachePolicy = .reloadIgnoringLocalCacheData
        urlSession = URLSession(configuration: cfg)

        ssdpAttempt = 0
        ssdpTimedOut = false
        seenLocations.removeAll()
        pendingDescFetches = 0
        chosenUPnPService = nil
        upnpClientIP = nil
        upnpInFlightMaps.removeAll()

        do {
            let sock = try UDPSocket(port: 0, v6: false, loop: loop)
            LocalNetwork.setMulticastTTLV4(fd: sock.fileDescriptor, ttl: 2)
            sock.onDatagram = { [weak self] data, from in
                self?.handleSSDPDatagram(data, from: from)
            }
            sock.start()
            ssdpSocket = sock
        } catch {
            for proto in PortProtocol.allCases {
                upnpErrors[proto] = "SSDP socket error: \(error)"
            }
            finishUPnPIdleIfNoActiveMappings()
            return
        }

        sendSSDPMSearch(includeFallbackTargets: false)
        scheduleNextSSDPStep()
    }

    private func sendSSDPMSearch(includeFallbackTargets: Bool) {
        guard isRunning, let sock = ssdpSocket else { return }
        let targets = includeFallbackTargets
            ? (SSDPWire.primarySearchTargets + SSDPWire.fallbackSearchTargets)
            : SSDPWire.primarySearchTargets
        let packets = targets.map { SSDPWire.encodeMSearch(st: $0) }

        if let override = ssdpTargetOverride {
            for pkt in packets { sock.send(pkt, to: override) }
            return
        }

        guard let mcastIP = IPAddress(SSDPWire.multicastIP) else { return }
        let dest = PeerAddress(ip: mcastIP, port: SSDPWire.multicastPort)
        let interfaces = LocalNetwork.physicalMulticastIPv4Interfaces()
        if interfaces.isEmpty {
            for pkt in packets { sock.send(pkt, to: dest) }
        } else {
            for iface in interfaces {
                LocalNetwork.setMulticastInterfaceV4(fd: sock.fileDescriptor, address: iface.address)
                for pkt in packets { sock.send(pkt, to: dest) }
            }
        }
    }

    private func scheduleNextSSDPStep() {
        ssdpTimer?.cancel()
        if ssdpAttempt < ssdpRetryDelays.count {
            let delay = ssdpRetryDelays[ssdpAttempt]
            ssdpAttempt += 1
            ssdpTimer = loop.schedule(after: delay) { [weak self] in
                guard let self, self.isRunning, self.chosenUPnPService == nil else { return }
                self.sendSSDPMSearch(includeFallbackTargets: true)
                self.scheduleNextSSDPStep()
            }
        } else {
            ssdpTimer = loop.schedule(after: ssdpDiscoveryTimeout) { [weak self] in
                self?.onSSDPDiscoveryTimeout()
            }
        }
    }

    private func onSSDPDiscoveryTimeout() {
        guard isRunning, chosenUPnPService == nil else { return }
        ssdpTimedOut = true
        ssdpTimer = nil
        ssdpSocket?.close()
        ssdpSocket = nil
        if pendingDescFetches == 0 {
            for proto in PortProtocol.allCases where activeMappings[proto] == nil {
                upnpErrors[proto] = "no UPnP IGD discovered"
            }
            finishUPnPIdleIfNoActiveMappings()
            recomputeStatuses()
        }
    }

    private func handleSSDPDatagram(_ data: Data, from: PeerAddress) {
        guard isRunning, chosenUPnPService == nil, !allProtocolsMapped else { return }
        guard let resp = SSDPWire.parseResponse(data) else { return }
        guard SSDPWire.isSafeLocationURL(resp.location, allowLoopback: allowLoopbackUPnP) else { return }
        let key = resp.location.absoluteString
        guard seenLocations.insert(key).inserted else { return }
        fetchRootDescription(from: resp.location)
    }

    private func fetchRootDescription(from location: URL) {
        guard let session = urlSession else { return }
        let gen = generation
        let allowLoopback = allowLoopbackUPnP
        pendingDescFetches += 1

        var req = URLRequest(url: location)
        req.httpMethod = "GET"
        req.timeoutInterval = 5

        session.dataTask(with: req) { [weak self] data, response, _ in
            let services: [UPnPService]
            if let data,
               let http = response as? HTTPURLResponse,
               (200..<300).contains(http.statusCode) {
                services = UPnPRootDescriptionParser.parse(data, locationURL: location, allowLoopback: allowLoopback)
            } else {
                services = []
            }
            guard let self else { return }
            self.loop.execute {
                self.handleRootDescriptionParsed(generation: gen, location: location, services: services)
            }
        }.resume()
    }

    private func handleRootDescriptionParsed(generation gen: UInt64, location: URL, services: [UPnPService]) {
        guard gen == generation, isRunning else { return }
        pendingDescFetches = max(0, pendingDescFetches - 1)

        if allProtocolsMapped {
            cancelPendingUPnP()
            return
        }
        guard chosenUPnPService == nil else { return }

        guard let service = services.first else {
            if ssdpTimedOut && pendingDescFetches == 0 {
                for proto in PortProtocol.allCases where activeMappings[proto] == nil {
                    upnpErrors[proto] = "no UPnP IGD connection service found"
                }
                finishUPnPIdleIfNoActiveMappings()
                recomputeStatuses()
            }
            return
        }

        // Select this IGD service and stop SSDP listening.
        chosenUPnPService = service
        ssdpTimer?.cancel()
        ssdpTimer = nil
        ssdpSocket?.close()
        ssdpSocket = nil

        let clientIP: IPAddress?
        if let override = clientIPOverride {
            clientIP = override
        } else if let host = location.host, let routerIP = IPAddress(host) {
            clientIP = LocalNetwork.localIPv4Address(for: routerIP) ?? resolvedClientIP
        } else {
            clientIP = resolvedClientIP
        }

        guard let clientIPStr = clientIP?.description else {
            for proto in PortProtocol.allCases where activeMappings[proto] == nil {
                upnpErrors[proto] = "unable to determine local LAN IPv4 address"
            }
            finishUPnPIdleIfNoActiveMappings()
            recomputeStatuses()
            return
        }
        upnpClientIP = clientIPStr

        // Query external IP in parallel with AddPortMapping.
        upnpGetExternalIP(service: service)

        let needed = PortProtocol.allCases.filter { activeMappings[$0] == nil }
        if needed.isEmpty {
            finishUPnPIdleIfNoActiveMappings()
            return
        }
        for proto in needed {
            upnpInFlightMaps.insert(proto)
            upnpAddPortMapping(
                service: service,
                proto: proto,
                externalPort: mappedPort,
                clientIP: clientIPStr,
                leaseDuration: requestedLease,
                allowPermanentFallback: true,
                allowAnyPortFallback: true
            )
        }
    }

    private func upnpGetExternalIP(service: UPnPService) {
        guard let session = urlSession else { return }
        let gen = generation
        let soap = UPnPSOAP.buildGetExternalIPAddress(serviceType: service.serviceType)
        let req = makeSOAPURLRequest(url: service.controlURL, soap: soap, timeout: 5)

        session.dataTask(with: req) { [weak self] data, response, _ in
            let status = (response as? HTTPURLResponse)?.statusCode ?? 0
            let parsed = UPnPSOAP.parseGetExternalIPAddressResponse(data ?? Data(), statusCode: status)
            guard let self else { return }
            self.loop.execute {
                guard gen == self.generation, self.isRunning else { return }
                if case .success(let ip) = parsed, !ip.isUnusable {
                    self._externalAddress = ip
                    self.recomputeStatuses()
                }
            }
        }.resume()
    }

    private func upnpAddPortMapping(
        service: UPnPService,
        proto: PortProtocol,
        externalPort: UInt16,
        clientIP: String,
        leaseDuration: UInt32,
        allowPermanentFallback: Bool,
        allowAnyPortFallback: Bool
    ) {
        guard let session = urlSession else { return }
        let gen = generation
        let soap = UPnPSOAP.buildAddPortMapping(
            serviceType: service.serviceType,
            externalPort: externalPort,
            proto: proto,
            internalPort: mappedPort,
            internalClient: clientIP,
            description: "Astor \(proto.name)",
            leaseDuration: leaseDuration
        )
        let req = makeSOAPURLRequest(url: service.controlURL, soap: soap, timeout: 5)

        session.dataTask(with: req) { [weak self] data, response, err in
            let status = (response as? HTTPURLResponse)?.statusCode ?? 0
            let result: Result<UInt16, UPnPSOAPError>
            if let err {
                result = .failure(.invalidResponse(err.localizedDescription))
            } else {
                switch UPnPSOAP.parseAddPortMappingResponse(data ?? Data(), statusCode: status) {
                case .success:
                    result = .success(externalPort)
                case .failure(let soapErr):
                    result = .failure(soapErr)
                }
            }
            guard let self else { return }
            self.loop.execute {
                self.handleUPnPMapResult(
                    generation: gen,
                    service: service,
                    proto: proto,
                    requestedExternalPort: externalPort,
                    clientIP: clientIP,
                    leaseDuration: leaseDuration,
                    viaAnyPort: false,
                    allowPermanentFallback: allowPermanentFallback,
                    allowAnyPortFallback: allowAnyPortFallback,
                    result: result
                )
            }
        }.resume()
    }

    private func upnpAddAnyPortMapping(
        service: UPnPService,
        proto: PortProtocol,
        externalPort: UInt16,
        clientIP: String,
        leaseDuration: UInt32,
        allowPermanentFallback: Bool
    ) {
        guard let session = urlSession else { return }
        let gen = generation
        let soap = UPnPSOAP.buildAddAnyPortMapping(
            serviceType: service.serviceType,
            externalPort: externalPort,
            proto: proto,
            internalPort: mappedPort,
            internalClient: clientIP,
            description: "Astor \(proto.name)",
            leaseDuration: leaseDuration
        )
        let req = makeSOAPURLRequest(url: service.controlURL, soap: soap, timeout: 5)

        session.dataTask(with: req) { [weak self] data, response, err in
            let status = (response as? HTTPURLResponse)?.statusCode ?? 0
            let result: Result<UInt16, UPnPSOAPError>
            if let err {
                result = .failure(.invalidResponse(err.localizedDescription))
            } else {
                result = UPnPSOAP.parseAddAnyPortMappingResponse(data ?? Data(), statusCode: status)
            }
            guard let self else { return }
            self.loop.execute {
                self.handleUPnPMapResult(
                    generation: gen,
                    service: service,
                    proto: proto,
                    requestedExternalPort: externalPort,
                    clientIP: clientIP,
                    leaseDuration: leaseDuration,
                    viaAnyPort: true,
                    allowPermanentFallback: allowPermanentFallback,
                    allowAnyPortFallback: false,
                    result: result
                )
            }
        }.resume()
    }

    private func handleUPnPMapResult(
        generation gen: UInt64,
        service: UPnPService,
        proto: PortProtocol,
        requestedExternalPort: UInt16,
        clientIP: String,
        leaseDuration: UInt32,
        viaAnyPort: Bool,
        allowPermanentFallback: Bool,
        allowAnyPortFallback: Bool,
        result: Result<UInt16, UPnPSOAPError>
    ) {
        guard gen == generation, isRunning, upnpInFlightMaps.contains(proto) else { return }

        // Handle parallel race: if PCP/NAT-PMP already mapped this protocol while our SOAP call was in flight.
        if let existing = activeMappings[proto], existing.method != .upnp {
            upnpInFlightMaps.remove(proto)
            if case .success(let assignedPort) = result {
                if assignedPort != existing.externalPort {
                    // Clean up the duplicate external port so nothing is orphaned on the router.
                    sendUPnPDeletes([(service, assignedPort, proto)], completion: nil)
                } else {
                    // Same external port: UPnP just refreshed/adopted the router's entry; track UPnP so stop() deletes it.
                    installMapping(
                        method: .upnp,
                        proto: proto,
                        externalPort: assignedPort,
                        leaseDuration: leaseDuration,
                        upnpService: service,
                        upnpClientIP: clientIP
                    )
                    recomputeStatuses()
                }
            }
            if upnpInFlightMaps.isEmpty {
                finishUPnPIdleIfNoActiveMappings()
            }
            return
        }

        switch result {
        case .success(let assignedPort):
            upnpInFlightMaps.remove(proto)
            upnpErrors.removeValue(forKey: proto)
            gwPendingProtos.remove(proto)
            installMapping(
                method: .upnp,
                proto: proto,
                externalPort: assignedPort,
                leaseDuration: leaseDuration,
                upnpService: service,
                upnpClientIP: clientIP
            )
            if upnpInFlightMaps.isEmpty {
                upnpDone = true
            }
            if allProtocolsMapped {
                cancelPendingGatewayProbes()
            } else if gwPendingProtos.isEmpty && !gwNeedExternalIP {
                gwTimer?.cancel()
                gwTimer = nil
                finishGatewayIdleIfNoActiveMappings()
            }
            recomputeStatuses()

        case .failure(let err):
            if case .fault(let code, _) = err {
                if code == UPnPSOAP.errorOnlyPermanentLeasesSupported, allowPermanentFallback, leaseDuration != 0 {
                    if viaAnyPort {
                        upnpAddAnyPortMapping(
                            service: service,
                            proto: proto,
                            externalPort: requestedExternalPort,
                            clientIP: clientIP,
                            leaseDuration: 0,
                            allowPermanentFallback: false
                        )
                    } else {
                        upnpAddPortMapping(
                            service: service,
                            proto: proto,
                            externalPort: requestedExternalPort,
                            clientIP: clientIP,
                            leaseDuration: 0,
                            allowPermanentFallback: false,
                            allowAnyPortFallback: allowAnyPortFallback
                        )
                    }
                    return
                }
                if code == UPnPSOAP.errorConflictInMappingEntry,
                   allowAnyPortFallback,
                   service.serviceType.hasSuffix(":2") {
                    upnpAddAnyPortMapping(
                        service: service,
                        proto: proto,
                        externalPort: requestedExternalPort,
                        clientIP: clientIP,
                        leaseDuration: leaseDuration,
                        allowPermanentFallback: allowPermanentFallback
                    )
                    return
                }
            }
            upnpInFlightMaps.remove(proto)
            upnpErrors[proto] = err.description
            if var active = activeMappings[proto], active.method == .upnp {
                active.lastRenewalError = err.description
                activeMappings[proto] = active
                scheduleRenewalRetryIfActive(proto: proto, expectedMethod: .upnp)
            }
            if upnpInFlightMaps.isEmpty {
                finishUPnPIdleIfNoActiveMappings()
            }
            recomputeStatuses()
        }
    }

    private func finishUPnPIdleIfNoActiveMappings() {
        upnpDone = true
        if activeMappings.values.allSatisfy({ $0.method != .upnp }) {
            ssdpTimer?.cancel()
            ssdpTimer = nil
            ssdpSocket?.close()
            ssdpSocket = nil
            urlSession?.invalidateAndCancel()
            urlSession = nil
        }
    }

    private func cancelPendingUPnP() {
        guard activeMappings.values.allSatisfy({ $0.method != .upnp }) else { return }
        upnpInFlightMaps.removeAll()
        finishUPnPIdleIfNoActiveMappings()
    }

    private func sendUPnPDeletes(
        _ deletes: [(UPnPService, UInt16, PortProtocol)],
        completion: (@Sendable () -> Void)?
    ) {
        let cfg = URLSessionConfiguration.ephemeral
        cfg.timeoutIntervalForRequest = 3
        cfg.timeoutIntervalForResource = 5
        let session = URLSession(configuration: cfg)
        let group = DispatchGroup()

        for (service, extPort, proto) in deletes {
            let soap = UPnPSOAP.buildDeletePortMapping(
                serviceType: service.serviceType,
                externalPort: extPort,
                proto: proto
            )
            let req = makeSOAPURLRequest(url: service.controlURL, soap: soap, timeout: 3)
            group.enter()
            session.dataTask(with: req) { _, _, _ in
                group.leave()
            }.resume()
        }
        session.finishTasksAndInvalidate()

        if let completion {
            let targetLoop = loop
            group.notify(queue: DispatchQueue.global(qos: .utility)) {
                targetLoop.execute { completion() }
            }
        }
    }

    private func makeSOAPURLRequest(url: URL, soap: UPnPSOAP.Request, timeout: TimeInterval) -> URLRequest {
        var req = URLRequest(url: url)
        req.httpMethod = "POST"
        req.timeoutInterval = timeout
        req.setValue("text/xml; charset=\"utf-8\"", forHTTPHeaderField: "Content-Type")
        req.setValue(soap.soapAction, forHTTPHeaderField: "SOAPACTION")
        req.httpBody = soap.body
        return req
    }

    // MARK: - Renewal & Status Management

    private var allProtocolsMapped: Bool {
        PortProtocol.allCases.allSatisfy { activeMappings[$0] != nil }
    }

    private func installMapping(
        method: Method,
        proto: PortProtocol,
        externalPort: UInt16,
        leaseDuration: UInt32,
        pcpNonce: Data? = nil,
        upnpService: UPnPService? = nil,
        upnpClientIP: String? = nil
    ) {
        activeMappings[proto]?.renewTimer?.cancel()

        var renewTimer: LoopTimer?
        if leaseDuration > 0 {
            let renewAfter = max(1.0, Double(leaseDuration) * 0.5)
            renewTimer = loop.schedule(after: renewAfter) { [weak self] in
                self?.renewMapping(proto: proto)
            }
        }

        activeMappings[proto] = ActiveMapping(
            method: method,
            proto: proto,
            internalPort: mappedPort,
            externalPort: externalPort,
            leaseDuration: leaseDuration,
            pcpNonce: pcpNonce,
            upnpService: upnpService,
            upnpClientIP: upnpClientIP,
            lastRenewalError: nil,
            renewTimer: renewTimer
        )
    }

    private func renewMapping(proto: PortProtocol) {
        guard isRunning, let mapping = activeMappings[proto] else { return }
        switch mapping.method {
        case .pcp:
            let alreadyInFlight = (gwMode == .pcp && gwTimer != nil)
            gwMode = .pcp
            gwPendingProtos.insert(proto)
            if alreadyInFlight, let gw = resolvedGateway, let clientIP = resolvedClientIP, let sock = gwSocket {
                // Coalesce into existing in-flight renewal without clobbering its backoff/timer.
                sendSinglePCPRequest(proto: proto, clientIP: clientIP, target: PeerAddress(ip: gw, port: gatewayPort), sock: sock)
            } else {
                gwAttempt = 0
                gwDelay = initialRetransmit
                sendPCPRequests()
            }

        case .natpmp:
            let alreadyInFlight = (gwMode == .natpmp && gwTimer != nil)
            gwMode = .natpmp
            gwPendingProtos.insert(proto)
            if alreadyInFlight, let gw = resolvedGateway, let sock = gwSocket {
                sendSingleNATPMPRequest(proto: proto, target: PeerAddress(ip: gw, port: gatewayPort), sock: sock)
            } else {
                gwNeedExternalIP = true
                gwAttempt = 0
                gwDelay = initialRetransmit
                sendNATPMPRequests()
            }

        case .upnp:
            guard let service = mapping.upnpService, let clientIP = mapping.upnpClientIP else { return }
            if urlSession == nil {
                let cfg = URLSessionConfiguration.ephemeral
                cfg.timeoutIntervalForRequest = 5
                cfg.timeoutIntervalForResource = 10
                cfg.requestCachePolicy = .reloadIgnoringLocalCacheData
                urlSession = URLSession(configuration: cfg)
            }
            upnpGetExternalIP(service: service)
            upnpInFlightMaps.insert(proto)
            upnpAddPortMapping(
                service: service,
                proto: proto,
                externalPort: mapping.externalPort,
                clientIP: clientIP,
                leaseDuration: requestedLease,
                allowPermanentFallback: true,
                allowAnyPortFallback: true
            )
        }
    }

    private func scheduleRenewalRetryIfActive(proto: PortProtocol, expectedMethod: Method) {
        guard isRunning, var mapping = activeMappings[proto],
              mapping.method == expectedMethod,
              mapping.leaseDuration > 0 else { return }
        mapping.renewTimer?.cancel()
        let retryAfter = max(0.5, min(60.0, Double(mapping.leaseDuration) * 0.25))
        mapping.renewTimer = loop.schedule(after: retryAfter) { [weak self] in
            self?.renewMapping(proto: proto)
        }
        activeMappings[proto] = mapping
    }

    private func recomputeStatuses() {
        var next: [PortMappingStatus] = []
        for proto in PortProtocol.allCases {
            if let active = activeMappings[proto] {
                next.append(PortMappingStatus(
                    method: active.method.displayName,
                    proto: proto.name,
                    internalPort: active.internalPort,
                    externalPort: active.externalPort,
                    externalAddress: _externalAddress,
                    error: active.lastRenewalError
                ))
            } else if gatewayDone && upnpDone {
                if let gwErr = gatewayErrors[proto], let upnpErr = upnpErrors[proto] {
                    next.append(PortMappingStatus(
                        method: gwErr.method,
                        proto: proto.name,
                        internalPort: mappedPort,
                        externalPort: nil,
                        externalAddress: _externalAddress,
                        error: "\(gwErr.method): \(gwErr.error); UPnP: \(upnpErr)"
                    ))
                } else if let gwErr = gatewayErrors[proto] {
                    next.append(PortMappingStatus(
                        method: gwErr.method,
                        proto: proto.name,
                        internalPort: mappedPort,
                        externalPort: nil,
                        externalAddress: _externalAddress,
                        error: gwErr.error
                    ))
                } else if let upnpErr = upnpErrors[proto] {
                    next.append(PortMappingStatus(
                        method: "UPnP",
                        proto: proto.name,
                        internalPort: mappedPort,
                        externalPort: nil,
                        externalAddress: _externalAddress,
                        error: upnpErr
                    ))
                }
            }
        }

        if next != _statuses || _externalAddress != lastReportedExternalAddress {
            _statuses = next
            lastReportedExternalAddress = _externalAddress
            _onChange?()
        }
    }
}
