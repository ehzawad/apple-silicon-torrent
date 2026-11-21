#!/bin/bash
# Builds the AstorApp product in release mode and assembles build/Astor.app:
#   Contents/MacOS/Astor, Contents/Info.plist (from Resources/Info.plist),
#   Contents/Resources/AppIcon.icns (drawn programmatically), ad-hoc signed.
#
# Usage: scripts/make-app.sh [--icon]     (--icon forces the icon to be redrawn)
#
# Environment (all optional; scripts/package.sh uses these for release builds):
#   VERSION=0.1.0     CFBundleShortVersionString (default: ClientIdentity.version)
#   BUILD_NUMBER=1    CFBundleVersion            (default: git commit count)
#   ARCH=arm64        pass --arch to swift build (default: host architecture)
#   EMBED_CLI=1       also build the `astor` CLI into Contents/Helpers/astor
#   SIGN=none         skip signing (default: adhoc; package.sh signs with Developer ID)
#   REGISTER=0        don't register the bundle with Launch Services
set -euo pipefail

cd "$(dirname "$0")/.."
ROOT="$(pwd)"
APP="$ROOT/build/Astor.app"
ICON_DIR="$ROOT/build/icon"
ICNS="$ICON_DIR/AppIcon.icns"

[[ "${1:-}" == "--icon" ]] && rm -rf "$ICON_DIR"

SWIFT_FLAGS=(-c release)
[[ -n "${ARCH:-}" ]] && SWIFT_FLAGS+=(--arch "$ARCH")

echo "==> Building AstorApp (release${ARCH:+, $ARCH})"
swift build "${SWIFT_FLAGS[@]}" --product AstorApp
BIN_DIR="$(swift build "${SWIFT_FLAGS[@]}" --product AstorApp --show-bin-path)"
if [[ "${EMBED_CLI:-0}" == 1 ]]; then
    echo "==> Building astor CLI (release${ARCH:+, $ARCH})"
    swift build "${SWIFT_FLAGS[@]}" --product astor
fi

# ---------------------------------------------------------------------------
# App icon: a 1024 px squircle drawn with AppKit, then an .iconset → .icns.
# ---------------------------------------------------------------------------
make_icon() {
    mkdir -p "$ICON_DIR"
    cat > "$ICON_DIR/draw-icon.swift" <<'SWIFT'
import AppKit

let px = 1024
guard let rep = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: px, pixelsHigh: px,
                                 bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true, isPlanar: false,
                                 colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0),
      let gc = NSGraphicsContext(bitmapImageRep: rep) else { fatalError("no bitmap") }
NSGraphicsContext.saveGraphicsState()
NSGraphicsContext.current = gc
let ctx = gc.cgContext
let srgb = CGColorSpace(name: CGColorSpace.sRGB)!

// macOS icon grid: 824 pt body centred on a 1024 canvas.
let body = CGRect(x: 100, y: 100, width: 824, height: 824)
let shape = CGPath(roundedRect: body, cornerWidth: 186, cornerHeight: 186, transform: nil)

// Drop shadow
ctx.saveGState()
ctx.setShadow(offset: CGSize(width: 0, height: -10), blur: 24,
              color: CGColor(srgbRed: 0, green: 0, blue: 0, alpha: 0.30))
ctx.addPath(shape)
ctx.setFillColor(CGColor(srgbRed: 0.1, green: 0.2, blue: 0.5, alpha: 1))
ctx.fillPath()
ctx.restoreGState()

ctx.saveGState()
ctx.addPath(shape)
ctx.clip()

// Background gradient: sky blue → indigo
let bg = CGGradient(colorsSpace: srgb, colors: [
    CGColor(srgbRed: 0.27, green: 0.72, blue: 1.00, alpha: 1),
    CGColor(srgbRed: 0.20, green: 0.42, blue: 0.96, alpha: 1),
    CGColor(srgbRed: 0.27, green: 0.20, blue: 0.78, alpha: 1),
] as CFArray, locations: [0, 0.5, 1])!
ctx.drawLinearGradient(bg, start: CGPoint(x: 300, y: 924), end: CGPoint(x: 724, y: 100),
                       options: [.drawsBeforeStartLocation, .drawsAfterEndLocation])

// The swarm: peers on a ring, linked to the centre
let centre = CGPoint(x: 512, y: 512)
let ringRadius: CGFloat = 300
ctx.setLineWidth(6)
for i in 0..<10 {
    let a = CGFloat(i) / 10 * 2 * .pi + .pi / 10
    let p = CGPoint(x: centre.x + cos(a) * ringRadius, y: centre.y + sin(a) * ringRadius)
    ctx.setStrokeColor(CGColor(srgbRed: 1, green: 1, blue: 1, alpha: 0.16))
    ctx.move(to: centre); ctx.addLine(to: p); ctx.strokePath()
    let r: CGFloat = i % 3 == 0 ? 26 : 18
    ctx.setFillColor(CGColor(srgbRed: 1, green: 1, blue: 1, alpha: i % 3 == 0 ? 0.55 : 0.32))
    ctx.fillEllipse(in: CGRect(x: p.x - r, y: p.y - r, width: 2 * r, height: 2 * r))
}

// Soft glow disc behind the arrow
let glow = CGGradient(colorsSpace: srgb, colors: [
    CGColor(srgbRed: 1, green: 1, blue: 1, alpha: 0.28),
    CGColor(srgbRed: 1, green: 1, blue: 1, alpha: 0.0),
] as CFArray, locations: [0, 1])!
ctx.drawRadialGradient(glow, startCenter: centre, startRadius: 0, endCenter: centre, endRadius: 250, options: [])

// Download arrow (SF Symbol), white
let config = NSImage.SymbolConfiguration(pointSize: 380, weight: .heavy)
    .applying(NSImage.SymbolConfiguration(paletteColors: [.white]))
if let sym = NSImage(systemSymbolName: "arrow.down", accessibilityDescription: nil)?.withSymbolConfiguration(config) {
    let s = sym.size
    ctx.saveGState()
    ctx.setShadow(offset: CGSize(width: 0, height: -8), blur: 18,
                  color: CGColor(srgbRed: 0.05, green: 0.08, blue: 0.35, alpha: 0.45))
    sym.draw(in: CGRect(x: centre.x - s.width / 2, y: centre.y - s.height / 2, width: s.width, height: s.height))
    ctx.restoreGState()
}

// Top sheen
let sheen = CGGradient(colorsSpace: srgb, colors: [
    CGColor(srgbRed: 1, green: 1, blue: 1, alpha: 0.22),
    CGColor(srgbRed: 1, green: 1, blue: 1, alpha: 0.0),
] as CFArray, locations: [0, 1])!
ctx.drawLinearGradient(sheen, start: CGPoint(x: 512, y: 924), end: CGPoint(x: 512, y: 600), options: [])
ctx.restoreGState()

// Hairline edge
ctx.addPath(shape)
ctx.setStrokeColor(CGColor(srgbRed: 1, green: 1, blue: 1, alpha: 0.25))
ctx.setLineWidth(3)
ctx.strokePath()

NSGraphicsContext.restoreGraphicsState()
guard let png = rep.representation(using: .png, properties: [:]) else { fatalError("png") }
try png.write(to: URL(fileURLWithPath: CommandLine.arguments[1]))
SWIFT
    xcrun swiftc -O -o "$ICON_DIR/draw-icon" "$ICON_DIR/draw-icon.swift"
    "$ICON_DIR/draw-icon" "$ICON_DIR/icon-1024.png"
    local set="$ICON_DIR/AppIcon.iconset"
    rm -rf "$set"; mkdir -p "$set"
    for s in 16 32 128 256 512; do
        sips -z $s $s "$ICON_DIR/icon-1024.png" --out "$set/icon_${s}x${s}.png" >/dev/null
        d=$((s * 2))
        sips -z $d $d "$ICON_DIR/icon-1024.png" --out "$set/icon_${s}x${s}@2x.png" >/dev/null
    done
    iconutil -c icns "$set" -o "$ICNS"
}

if [[ ! -f "$ICNS" ]]; then
    echo "==> Drawing app icon"
    make_icon || echo "warning: icon generation failed; continuing without an icon" >&2
fi

# ---------------------------------------------------------------------------
# Assemble the bundle
# ---------------------------------------------------------------------------
echo "==> Assembling $APP"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp "$BIN_DIR/AstorApp" "$APP/Contents/MacOS/Astor"
if [[ "${EMBED_CLI:-0}" == 1 ]]; then
    mkdir -p "$APP/Contents/Helpers"
    cp "$BIN_DIR/astor" "$APP/Contents/Helpers/astor"
fi

: "${VERSION:=$(sed -n 's/.*static let version = "\(.*\)".*/\1/p' Sources/TorrentCore/Session/Config.swift | head -1)}"
: "${BUILD_NUMBER:=$(git rev-list --count HEAD 2>/dev/null || echo 1)}"
sed -e "s/__VERSION__/${VERSION:-0.1.0}/" -e "s/__BUILD__/${BUILD_NUMBER}/" Resources/Info.plist > "$APP/Contents/Info.plist"
plutil -lint -s "$APP/Contents/Info.plist"
printf 'APPL????' > "$APP/Contents/PkgInfo"
[[ -f "$ICNS" ]] && cp "$ICNS" "$APP/Contents/Resources/AppIcon.icns"

if [[ "${SIGN:-adhoc}" == adhoc ]]; then
    echo "==> Signing (ad-hoc)"
    codesign --force --deep -s - "$APP"
    codesign --verify --deep --strict "$APP"
fi

# Tell Launch Services about the new bundle (document & URL types).
if [[ "${REGISTER:-1}" == 1 ]]; then
    LSREGISTER=/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister
    [[ -x "$LSREGISTER" ]] && "$LSREGISTER" -f "$APP" >/dev/null 2>&1 || true
fi

echo "$APP"
