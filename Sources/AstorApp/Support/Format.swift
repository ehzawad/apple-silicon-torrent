#if os(macOS)
import Foundation
import TorrentCore

/// Human-friendly formatting shared by every view (Finder-style decimal units,
/// like the rest of macOS, rather than the CLI's KiB/MiB).
enum Fmt {
    static func bytes(_ n: Int64) -> String {
        n.formatted(.byteCount(style: .file, spellsOutZero: false))
    }

    static func bytes(_ n: Double) -> String { bytes(Int64(max(0, n))) }

    /// "1.2 MB/s"; "0 KB/s" for idle so totals never look broken.
    static func rate(_ bytesPerSecond: Double) -> String {
        guard bytesPerSecond >= 1 else { return "0 KB/s" }
        return bytes(bytesPerSecond) + "/s"
    }

    /// Rates in table cells: empty when idle so busy rows stand out.
    static func cellRate(_ bytesPerSecond: Double) -> String {
        bytesPerSecond >= 512 ? rate(bytesPerSecond) : ""
    }

    static func percent(_ fraction: Double, digits: Int = 1) -> String {
        let clamped = min(max(fraction, 0), 1)
        return clamped.formatted(.percent.precision(.fractionLength(digits)))
    }

    /// "3d 4h", "2h 05m", "4m 10s", "12s".
    static func duration(_ seconds: Double?) -> String {
        guard let seconds, seconds.isFinite, seconds >= 0 else { return "∞" }
        let t = Int(seconds.rounded())
        if t >= 86_400 { return "\(t / 86_400)d \(t % 86_400 / 3_600)h" }
        if t >= 3_600 { return String(format: "%dh %02dm", t / 3_600, t % 3_600 / 60) }
        if t >= 60 { return String(format: "%dm %02ds", t / 60, t % 60) }
        return "\(t)s"
    }

    static func count(_ n: Int) -> String { n.formatted(.number) }

    static func ratio(uploaded: Int64, downloaded: Int64, size: Int64) -> String {
        let base = max(downloaded, size)
        guard base > 0 else { return "—" }
        return (Double(uploaded) / Double(base)).formatted(.number.precision(.fractionLength(2)))
    }

    static func version(_ v: TorrentVersion?) -> String {
        switch v {
        case .v1: "v1"
        case .v2: "v2"
        case .hybrid: "Hybrid (v1 + v2)"
        case nil: "—"
        }
    }

    static func source(_ s: PeerSource) -> String {
        switch s {
        case .tracker: "Trackers"
        case .dht: "DHT"
        case .pex: "Peer exchange"
        case .lsd: "Local network"
        case .incoming: "Incoming"
        case .magnet: "Magnet link"
        case .resume: "Saved peers"
        case .holepunch: "Hole punching"
        case .manual: "Added manually"
        }
    }

    /// Shortens a tracker URL to "host:port" for tables.
    static func trackerHost(_ url: String) -> String {
        guard let c = URLComponents(string: url), let host = c.host else { return url }
        if let port = c.port { return "\(host):\(port)" }
        return host
    }
}
#endif
