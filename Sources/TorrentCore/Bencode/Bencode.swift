import Foundation

/// A bencoded value (BEP 3). Dictionary keys are raw byte strings because
/// BitTorrent v2 uses binary keys (e.g. 32-byte "pieces root" keys in
/// "piece layers") and v2 file trees use arbitrary UTF-8 names.
public enum BValue: Hashable, Sendable {
    case int(Int64)
    case bytes(Data)
    case list([BValue])
    case dict([Data: BValue])

    // MARK: Convenience constructors

    public static func string(_ s: String) -> BValue { .bytes(Data(s.utf8)) }

    public static func dict(_ pairs: KeyValuePairs<String, BValue>) -> BValue {
        var d: [Data: BValue] = [:]
        for (k, v) in pairs { d[Data(k.utf8)] = v }
        return .dict(d)
    }

    // MARK: Accessors

    public var int: Int64? { if case .int(let v) = self { return v }; return nil }
    public var data: Data? { if case .bytes(let v) = self { return v }; return nil }
    public var list: [BValue]? { if case .list(let v) = self { return v }; return nil }
    public var dict: [Data: BValue]? { if case .dict(let v) = self { return v }; return nil }

    /// UTF-8 decoding of a byte string (lossy replacement of invalid sequences).
    public var string: String? {
        guard case .bytes(let d) = self else { return nil }
        return String(decoding: d, as: UTF8.self)
    }

    public subscript(key: String) -> BValue? {
        guard case .dict(let d) = self else { return nil }
        return d[Data(key.utf8)]
    }

    public subscript(key: Data) -> BValue? {
        guard case .dict(let d) = self else { return nil }
        return d[key]
    }

    // MARK: Encoding

    public var encoded: Data {
        var out = Data()
        encode(into: &out)
        return out
    }

    public func encode(into out: inout Data) {
        switch self {
        case .int(let v):
            out.append(UInt8(ascii: "i"))
            out.append(contentsOf: String(v).utf8)
            out.append(UInt8(ascii: "e"))
        case .bytes(let d):
            out.append(contentsOf: String(d.count).utf8)
            out.append(UInt8(ascii: ":"))
            out.append(d)
        case .list(let l):
            out.append(UInt8(ascii: "l"))
            for v in l { v.encode(into: &out) }
            out.append(UInt8(ascii: "e"))
        case .dict(let d):
            out.append(UInt8(ascii: "d"))
            // Keys must be sorted as raw byte strings.
            for k in d.keys.sorted(by: { $0.lexicographicallyPrecedes($1) }) {
                out.append(contentsOf: String(k.count).utf8)
                out.append(UInt8(ascii: ":"))
                out.append(k)
                d[k]!.encode(into: &out)
            }
            out.append(UInt8(ascii: "e"))
        }
    }
}

public struct BencodeError: Error, CustomStringConvertible, Sendable {
    public let message: String
    public let offset: Int
    public var description: String { "bencode: \(message) at offset \(offset)" }
}

/// Fast bencode decoder working directly on bytes.
public struct BDecoder {
    private let bytes: [UInt8]
    private var pos: Int = 0
    private let maxDepth = 128
    /// When set, the decoder records the byte range of the value stored under this
    /// key in the TOP-LEVEL dictionary (used to hash the raw "info" dictionary).
    private let captureKey: [UInt8]?
    public private(set) var capturedRange: Range<Int>?

    public init(_ data: Data, captureTopLevelKey: String? = nil) {
        self.bytes = [UInt8](data)
        self.captureKey = captureTopLevelKey.map { Array($0.utf8) }
    }

    public init(bytes: [UInt8], captureTopLevelKey: String? = nil) {
        self.bytes = bytes
        self.captureKey = captureTopLevelKey.map { Array($0.utf8) }
    }

    /// Decode exactly one value spanning the whole input.
    public static func decode(_ data: Data) throws -> BValue {
        var d = BDecoder(data)
        let v = try d.decodeValue(depth: 0)
        guard d.pos == d.bytes.count else { throw BencodeError(message: "trailing data", offset: d.pos) }
        return v
    }

    /// Decode one value from the start of `data`; returns it and the bytes consumed.
    /// Used for ut_metadata messages which carry raw payload after the dict.
    public static func decodePrefix(_ data: Data) throws -> (BValue, Int) {
        var d = BDecoder(data)
        let v = try d.decodeValue(depth: 0)
        return (v, d.pos)
    }

    /// Decode a whole document and also return the raw bytes of a top-level key's value.
    public static func decode(_ data: Data, capturing key: String) throws -> (BValue, Data?) {
        var d = BDecoder(data, captureTopLevelKey: key)
        let v = try d.decodeValue(depth: 0)
        guard d.pos == d.bytes.count else { throw BencodeError(message: "trailing data", offset: d.pos) }
        let raw = d.capturedRange.map { Data(d.bytes[$0]) }
        return (v, raw)
    }

    private func err(_ m: String) -> BencodeError { BencodeError(message: m, offset: pos) }

    mutating func decodeValue(depth: Int) throws -> BValue {
        guard depth < maxDepth else { throw err("nesting too deep") }
        guard pos < bytes.count else { throw err("unexpected end") }
        let c = bytes[pos]
        switch c {
        case UInt8(ascii: "i"):
            pos += 1
            return .int(try readInt(terminator: UInt8(ascii: "e")))
        case UInt8(ascii: "l"):
            pos += 1
            var items: [BValue] = []
            while true {
                guard pos < bytes.count else { throw err("unterminated list") }
                if bytes[pos] == UInt8(ascii: "e") { pos += 1; break }
                items.append(try decodeValue(depth: depth + 1))
            }
            return .list(items)
        case UInt8(ascii: "d"):
            pos += 1
            var dict: [Data: BValue] = [:]
            while true {
                guard pos < bytes.count else { throw err("unterminated dict") }
                if bytes[pos] == UInt8(ascii: "e") { pos += 1; break }
                guard bytes[pos] >= UInt8(ascii: "0") && bytes[pos] <= UInt8(ascii: "9") else {
                    throw err("dict key must be a string")
                }
                let keyRange = try readStringRange()
                let valueStart = pos
                let value = try decodeValue(depth: depth + 1)
                if depth == 0, let ck = captureKey, keyRange.count == ck.count,
                   bytes[keyRange].elementsEqual(ck) {
                    capturedRange = valueStart..<pos
                }
                dict[Data(bytes[keyRange])] = value
            }
            return .dict(dict)
        case UInt8(ascii: "0")...UInt8(ascii: "9"):
            let r = try readStringRange()
            return .bytes(Data(bytes[r]))
        default:
            throw err("invalid type byte \(c)")
        }
    }

    private mutating func readInt(terminator: UInt8) throws -> Int64 {
        var neg = false
        if pos < bytes.count, bytes[pos] == UInt8(ascii: "-") { neg = true; pos += 1 }
        var v: Int64 = 0
        var digits = 0
        while pos < bytes.count, bytes[pos] != terminator {
            let ch = bytes[pos]
            guard ch >= UInt8(ascii: "0") && ch <= UInt8(ascii: "9") else { throw err("bad digit") }
            let (m, o1) = v.multipliedReportingOverflow(by: 10)
            let (a, o2) = m.addingReportingOverflow(Int64(ch - UInt8(ascii: "0")))
            guard !o1 && !o2 else { throw err("integer overflow") }
            v = a
            digits += 1
            pos += 1
        }
        guard pos < bytes.count, digits > 0 else { throw err("unterminated integer") }
        pos += 1
        return neg ? -v : v
    }

    private mutating func readStringRange() throws -> Range<Int> {
        let len = try readInt(terminator: UInt8(ascii: ":"))
        guard len >= 0, len <= Int64(bytes.count - pos) else { throw err("string length out of range") }
        let start = pos
        pos += Int(len)
        return start..<pos
    }
}
