#!/bin/bash
# Release packaging for Astor (Apple Silicon, macOS 26+):
#
#   1. swift build -c release --arch arm64 (AstorApp + astor CLI)
#   2. build/Astor.app via make-app.sh, CLI embedded at Contents/Helpers/astor
#   3. Developer ID signature, hardened runtime, secure timestamp (helper first, then app)
#   4. dist/Astor-<VERSION>-arm64.dmg (compressed, Astor.app + Applications symlink), signed
#   5. optional notarization + stapling (see below)
#   6. Gatekeeper assessment (spctl) of the app and the DMG
#   7. smoke test: mount the DMG, launch the app from it with throwaway state, quit it
#   8. dist/Astor-<VERSION>-arm64.dmg.sha256
#
# Usage: scripts/package.sh
#
# Environment (all optional):
#   VERSION=0.1.0            CFBundleShortVersionString and file names
#   BUILD_NUMBER=1           CFBundleVersion
#   SIGN_IDENTITY=<sha1>     Developer ID Application identity, as the SHA-1 printed by
#                            `security find-identity -v -p codesigning`
#   NOTARY_PROFILE=<name>    notarize using a notarytool keychain profile, or
#   NOTARY_KEY=<AuthKey_XXXX.p8 path> NOTARY_KEY_ID=<key id> NOTARY_ISSUER=<issuer uuid>
#                            notarize using an App Store Connect API key
#   DMG_FORMAT=ULFO          hdiutil image format (ULFO = lzfse, UDZO = zlib)
#   SMOKE_TEST=0             skip the mount-and-launch smoke test
#   CODESIGN_TIMEOUT=180     seconds before a codesign call is considered stuck
#                            (usually a keychain access prompt waiting on screen)
#
# One-time notarization setup (stores the API key in the login keychain):
#   xcrun notarytool store-credentials astor-notary \
#       --key ~/.appstoreconnect/private_keys/AuthKey_<KEYID>.p8 --key-id <KEYID> --issuer <ISSUER-UUID>
#   NOTARY_PROFILE=astor-notary scripts/package.sh
set -euo pipefail

cd "$(dirname "$0")/.."
ROOT="$(pwd)"

VERSION="${VERSION:-0.1.0}"
BUILD_NUMBER="${BUILD_NUMBER:-1}"
ARCH=arm64
# Default: the first "Developer ID Application" identity in the keychain.
SIGN_IDENTITY="${SIGN_IDENTITY:-$(security find-identity -v -p codesigning | awk '/"Developer ID Application/ {print $2; exit}')}"
if [[ -z "$SIGN_IDENTITY" ]]; then
  echo "error: no 'Developer ID Application' signing identity found; set SIGN_IDENTITY" >&2
  exit 1
fi
DMG_FORMAT="${DMG_FORMAT:-ULFO}"
CODESIGN_TIMEOUT="${CODESIGN_TIMEOUT:-180}"

BUNDLE_ID="com.astor.torrent"
APP="$ROOT/build/Astor.app"
HELPER="$APP/Contents/Helpers/astor"
DIST="$ROOT/dist"
NAME="Astor-$VERSION-$ARCH"
DMG="$DIST/$NAME.dmg"
VOLNAME="Astor $VERSION"
# Hardened runtime needs no entitlements for this app (plain BSD sockets, not
# sandboxed). If one is ever needed, add Resources/Astor.entitlements and it is used.
ENTITLEMENTS="$ROOT/Resources/Astor.entitlements"

say()  { printf '\n==> %s\n' "$*"; }
die()  { printf '\nerror: %s\n' "$*" >&2; exit 1; }

WORK="$(cd "$(mktemp -d "${TMPDIR:-/tmp}/astor-package.XXXXXX")" && pwd -P)"
MNT=""
SMOKE_PID=""
cleanup() {
    if [[ -n "$SMOKE_PID" ]] && kill -0 "$SMOKE_PID" 2>/dev/null; then
        kill -TERM "$SMOKE_PID" 2>/dev/null || true
        sleep 3
        kill -KILL "$SMOKE_PID" 2>/dev/null || true
    fi
    if [[ -n "$MNT" ]] && mount | grep -qF " on $MNT "; then
        hdiutil detach "$MNT" -quiet 2>/dev/null || hdiutil detach "$MNT" -force -quiet 2>/dev/null || true
    fi
    rm -rf "$WORK"
}
trap cleanup EXIT

# codesign with a watchdog: a keychain access prompt blocks codesign until someone
# answers it, which would otherwise hang the script silently.
csign() {
    local rc=0
    perl -e 'alarm shift; exec @ARGV or die "exec: $!"' "$CODESIGN_TIMEOUT" codesign "$@" || rc=$?
    if (( rc == 142 )); then
        die "codesign got no answer within ${CODESIGN_TIMEOUT}s. It is probably waiting for a keychain prompt
       (\"codesign wants to access key ...\") on screen: enter the login password, click
       Always Allow, then run this script again."
    fi
    return $rc
}

# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------
say "Astor $VERSION ($BUILD_NUMBER), $ARCH"
security find-identity -v -p codesigning | grep -q "$SIGN_IDENTITY" \
    || die "signing identity $SIGN_IDENTITY not found (security find-identity -v -p codesigning)"
security find-identity -v -p codesigning | grep "$SIGN_IDENTITY" | grep -q '"Developer ID Application:' \
    || die "identity $SIGN_IDENTITY is not a \"Developer ID Application\" certificate"
for tool in swift codesign hdiutil spctl shasum ditto; do
    command -v "$tool" >/dev/null || die "$tool not found"
done

# ---------------------------------------------------------------------------
# 1-2. Build and assemble build/Astor.app (unsigned; signed below)
# ---------------------------------------------------------------------------
VERSION="$VERSION" BUILD_NUMBER="$BUILD_NUMBER" ARCH="$ARCH" EMBED_CLI=1 SIGN=none REGISTER=0 \
    "$ROOT/scripts/make-app.sh"

[[ -x "$APP/Contents/MacOS/Astor" && -x "$HELPER" ]] || die "bundle is incomplete"
for bin in "$APP/Contents/MacOS/Astor" "$HELPER"; do
    archs="$(lipo -archs "$bin")"
    [[ "$archs" == "$ARCH" ]] || die "$bin has architectures '$archs', expected '$ARCH'"
done
PLIST="$APP/Contents/Info.plist"
pb() { /usr/libexec/PlistBuddy -c "Print :$1" "$PLIST"; }
[[ "$(pb CFBundleShortVersionString)" == "$VERSION" ]] || die "CFBundleShortVersionString mismatch"
[[ "$(pb CFBundleVersion)" == "$BUILD_NUMBER" ]] || die "CFBundleVersion mismatch"
[[ "$(pb LSMinimumSystemVersion)" == "26.0" ]] || die "LSMinimumSystemVersion is not 26.0"
# Plain-http trackers/web seeds need the ATS exemption, and it only takes effect alone.
[[ "$(pb NSAppTransportSecurity:NSAllowsArbitraryLoads 2>/dev/null)" == "true" ]] \
    || die "Info.plist lacks NSAppTransportSecurity/NSAllowsArbitraryLoads (http:// trackers would fail)"
[[ "$(pb NSAppTransportSecurity 2>/dev/null | grep -c 'NSAllows')" == 1 ]] \
    || die "Info.plist has extra NSAllows* ATS keys, which make ATS ignore NSAllowsArbitraryLoads"
CLI_VERSION="$(sed -n 's/.*static let version = "\(.*\)".*/\1/p' Sources/TorrentCore/Session/Config.swift | head -1)"
[[ "$CLI_VERSION" == "$VERSION" ]] \
    || echo "warning: ClientIdentity.version is $CLI_VERSION but VERSION is $VERSION" >&2

# ---------------------------------------------------------------------------
# 3. Sign: nested code first, then the bundle. No --deep (it is for verifying only).
# ---------------------------------------------------------------------------
say "Signing with Developer ID ($SIGN_IDENTITY), hardened runtime, secure timestamp"
csign --force --options runtime --timestamp -s "$SIGN_IDENTITY" \
    --identifier "$BUNDLE_ID.cli" "$HELPER"
APP_SIGN_ARGS=(--force --options runtime --timestamp -s "$SIGN_IDENTITY")
if [[ -f "$ENTITLEMENTS" ]]; then
    plutil -lint -s "$ENTITLEMENTS"
    APP_SIGN_ARGS+=(--entitlements "$ENTITLEMENTS")
fi
csign "${APP_SIGN_ARGS[@]}" "$APP"

say "codesign --verify --deep --strict --verbose=2 build/Astor.app"
codesign --verify --deep --strict --verbose=2 "$APP"
say "codesign -dvv build/Astor.app"
codesign -dvv "$APP" 2>&1
say "codesign -dvv build/Astor.app/Contents/Helpers/astor"
codesign -dvv "$HELPER" 2>&1
say "Entitlements"
codesign -d --entitlements - "$APP" 2>&1 | sed -n '2,$p' | grep . || echo "(none)"

# ---------------------------------------------------------------------------
# 4. DMG: Astor.app + /Applications symlink, compressed, signed
# ---------------------------------------------------------------------------
say "Building $DMG"
STAGE="$WORK/dmg"
mkdir -p "$STAGE" "$DIST"
ditto "$APP" "$STAGE/Astor.app"
ln -s /Applications "$STAGE/Applications"
rm -f "$DMG" "$DMG.sha256"
hdiutil create -volname "$VOLNAME" -srcfolder "$STAGE" -fs HFS+ -format "$DMG_FORMAT" -ov "$DMG"
csign --force --timestamp -s "$SIGN_IDENTITY" --identifier "$BUNDLE_ID.dmg" "$DMG"
codesign --verify --strict --verbose=2 "$DMG"

# ---------------------------------------------------------------------------
# 5. Notarization (optional)
# ---------------------------------------------------------------------------
NOTARY_ARGS=()
if [[ -n "${NOTARY_PROFILE:-}" ]]; then
    NOTARY_ARGS=(--keychain-profile "$NOTARY_PROFILE")
    NOTARY_HOW="keychain profile \"$NOTARY_PROFILE\""
elif [[ -n "${NOTARY_KEY:-}" && -n "${NOTARY_KEY_ID:-}" && -n "${NOTARY_ISSUER:-}" ]]; then
    [[ -f "$NOTARY_KEY" ]] || die "NOTARY_KEY does not point to a file"
    NOTARY_ARGS=(--key "$NOTARY_KEY" --key-id "$NOTARY_KEY_ID" --issuer "$NOTARY_ISSUER")
    NOTARY_HOW="App Store Connect API key"
fi

NOTARIZED=0
if (( ${#NOTARY_ARGS[@]} )); then
    say "Notarizing with $NOTARY_HOW (usually a few minutes)"
    RESULT="$WORK/notary.json"
    xcrun notarytool submit "$DMG" "${NOTARY_ARGS[@]}" --wait --output-format json > "$RESULT" || true
    status="$(plutil -extract status raw -o - "$RESULT" 2>/dev/null || echo unknown)"
    sub_id="$(plutil -extract id raw -o - "$RESULT" 2>/dev/null || true)"
    echo "notarytool: status=$status id=${sub_id:-?}"
    if [[ "$status" != "Accepted" ]]; then
        [[ -n "$sub_id" ]] && xcrun notarytool log "$sub_id" "${NOTARY_ARGS[@]}" || true
        die "notarization did not succeed (status: $status)"
    fi
    say "Stapling"
    xcrun stapler staple "$DMG"
    xcrun stapler validate "$DMG"
    NOTARIZED=1
fi

# ---------------------------------------------------------------------------
# 6. Gatekeeper assessment (an un-notarized Developer ID build is rejected here;
#    that is expected until it is notarized)
# ---------------------------------------------------------------------------
say "spctl -a -vvv -t exec build/Astor.app"
spctl -a -vvv -t exec "$APP" 2>&1 || true
say "spctl -a -vvv -t open --context context:primary-signature dist/$NAME.dmg"
spctl -a -vvv -t open --context context:primary-signature "$DMG" 2>&1 || true

# ---------------------------------------------------------------------------
# 7. Smoke test: mount, inspect, launch from the image with throwaway state, quit
# ---------------------------------------------------------------------------
if [[ "${SMOKE_TEST:-1}" == 1 ]]; then
    say "Smoke test"
    hdiutil verify -quiet "$DMG"
    MNT="$WORK/mnt"
    mkdir -p "$MNT"
    hdiutil attach "$DMG" -nobrowse -readonly -noautoopen -mountpoint "$MNT" >/dev/null
    echo "mounted at $MNT:"
    ls -l "$MNT" | sed 's/^/  /'
    [[ -d "$MNT/Astor.app" ]] || die "Astor.app missing from the DMG"
    [[ -L "$MNT/Applications" && "$(readlink "$MNT/Applications")" == /Applications ]] \
        || die "Applications symlink missing from the DMG"
    codesign --verify --deep --strict "$MNT/Astor.app" || die "app on the DMG fails verification"
    echo "  Astor.app on the image verifies (deep, strict)"

    help_out="$("$MNT/Astor.app/Contents/Helpers/astor" --help 2>&1)" || true
    grep -q "astor — a BitTorrent client" <<<"$help_out" || die "Contents/Helpers/astor --help failed: $help_out"
    echo "  Contents/Helpers/astor --help:"
    head -n 3 <<<"$help_out" | sed 's/^/    /'

    STATE="$WORK/state"
    DOWNLOADS="$WORK/downloads"
    mkdir -p "$STATE" "$DOWNLOADS"
    EXE="$MNT/Astor.app/Contents/MacOS/Astor"
    # Isolated state/downloads; random port, no router port mapping or LAN discovery, so
    # an Astor the user already has running is unaffected.
    open -n "$MNT/Astor.app" --args -stateDirectory "$STATE" -downloadDirectory "$DOWNLOADS" \
        -listenPort 0 -enablePortMapping NO -enableLSD NO
    for _ in $(seq 1 40); do
        SMOKE_PID="$(pgrep -f "$EXE" | head -n 1 || true)"
        [[ -n "$SMOKE_PID" ]] && break
        sleep 0.25
    done
    [[ -n "$SMOKE_PID" ]] || die "Astor did not start from the DMG"
    sleep 5
    kill -0 "$SMOKE_PID" 2>/dev/null || die "Astor (pid $SMOKE_PID) exited within 5 s of launch"
    echo "  running from the image: pid $SMOKE_PID ($(ps -o command= -p "$SMOKE_PID" | cut -c1-120))"
    [[ -d "$STATE/resume" ]] && echo "  engine started (state directory initialised)" \
        || die "engine did not initialise $STATE"
    listening="$(lsof -nP -a -p "$SMOKE_PID" -iTCP -sTCP:LISTEN 2>/dev/null | awk 'NR>1 {print $9}' | sort -u | tr '\n' ' ')"
    [[ -n "$listening" ]] && echo "  listening (hardened runtime): $listening" \
        || die "Astor is not listening on any TCP port"

    LSREGISTER=/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister
    kill -TERM "$SMOKE_PID"           # same graceful path as Quit (resume data, tracker "stopped")
    for _ in $(seq 1 60); do kill -0 "$SMOKE_PID" 2>/dev/null || break; sleep 0.25; done
    if kill -0 "$SMOKE_PID" 2>/dev/null; then
        echo "  warning: pid $SMOKE_PID ignored SIGTERM for 15 s; killing it" >&2
        kill -KILL "$SMOKE_PID" 2>/dev/null || true
    else
        echo "  quit cleanly"
    fi
    SMOKE_PID=""
    [[ -x "$LSREGISTER" ]] && "$LSREGISTER" -u "$MNT/Astor.app" >/dev/null 2>&1 || true
    hdiutil detach "$MNT" -quiet || hdiutil detach "$MNT" -force -quiet
    MNT=""
    echo "  detached"
fi

# ---------------------------------------------------------------------------
# 8. Checksum (after stapling, which modifies the DMG) and summary
# ---------------------------------------------------------------------------
(cd "$DIST" && shasum -a 256 "$NAME.dmg" > "$NAME.dmg.sha256")
SIZE="$(stat -f %z "$DMG")"

say "Done"
echo "  $DMG ($(awk -v b="$SIZE" 'BEGIN { printf "%.1f MB", b / 1e6 }'), $SIZE bytes)"
echo "  $DMG.sha256: $(cut -d' ' -f1 "$DMG.sha256")"
if (( NOTARIZED )); then
    echo "  Developer ID signed, notarized and stapled."
else
    cat <<EOF

  NOTE: the DMG and app are Developer ID signed but NOT notarized, so Gatekeeper
  will block them on other Macs (they open there only via System Settings >
  Privacy & Security > Open Anyway). To notarize, store credentials once:

    xcrun notarytool store-credentials astor-notary \\
        --key ~/.appstoreconnect/private_keys/AuthKey_<KEYID>.p8 \\
        --key-id <KEYID> --issuer <ISSUER-UUID>

  then re-run:

    NOTARY_PROFILE=astor-notary scripts/package.sh
EOF
fi
