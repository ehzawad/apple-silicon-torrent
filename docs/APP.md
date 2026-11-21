# Astor for Mac (AstorApp)

A native SwiftUI front end for `TorrentCore`, targeting macOS 26+ with the
Liquid Glass system design (glass toolbar, sidebar and inspector come from the
system; content stays plain).

## Build & run

```sh
scripts/make-app.sh            # release build → build/Astor.app (ad-hoc signed)
open build/Astor.app
scripts/make-app.sh --icon     # also redraw the generated app icon
swift build -c release --product AstorApp   # binary only
```

`make-app.sh` copies `.build/release/AstorApp` to `Contents/MacOS/Astor`, fills
`Resources/Info.plist` (bundle id `com.astor.torrent`, LSMinimumSystemVersion
26.0, arm64 only, `.torrent` document type, `magnet:` URL scheme, and an App
Transport Security exemption so plain `http://` trackers and web seeds work),
draws `AppIcon.icns` with AppKit, signs with `codesign --force --deep -s -`,
and registers the bundle with Launch Services. Environment knobs (used by
`package.sh`): `VERSION`, `BUILD_NUMBER`, `ARCH`, `EMBED_CLI=1`, `SIGN=none`,
`REGISTER=0`.

> The ATS exemption must stay a lone `NSAllowsArbitraryLoads`: adding
> `NSAllowsLocalNetworking` (or any other `NSAllows*` key) next to it makes ATS
> ignore `NSAllowsArbitraryLoads`, and remote `http://` announces fail again.

## Release packaging

```sh
scripts/package.sh                                 # → dist/Astor-0.1.0-arm64.dmg (+ .sha256)
VERSION=0.2.0 BUILD_NUMBER=2 scripts/package.sh    # next release
NOTARY_PROFILE=astor-notary scripts/package.sh     # also notarize + staple
SMOKE_TEST=0 scripts/package.sh                    # skip the mount-and-launch test
```

`package.sh` builds `AstorApp` and `astor` for arm64 in release mode, assembles
`build/Astor.app` via `make-app.sh` with the CLI at `Contents/Helpers/astor`,
signs the helper and then the app with the Developer ID Application identity
(`SIGN_IDENTITY`, a SHA-1 from `security find-identity -v -p codesigning`),
hardened runtime and a secure timestamp. No entitlements are needed: the app is
not sandboxed and the hardened runtime doesn't restrict sockets. It then builds
a compressed DMG (volume "Astor 0.1.0", `Astor.app` + an `Applications` link),
signs it, notarizes and staples it if credentials are given, prints the
`spctl` assessments, and smoke-tests the image: it mounts the DMG, verifies the
app, runs `Contents/Helpers/astor --help`, launches the app from the image with
a throwaway state directory, random port and no port mapping, checks it is
listening, and quits that one process (an Astor you already have running is
left alone).

There is no Developer ID Installer certificate, so a DMG is shipped, not a `.pkg`.

### Notarization

Notarization is optional and driven by the environment: `NOTARY_PROFILE` (a
`notarytool` keychain profile) or `NOTARY_KEY` + `NOTARY_KEY_ID` +
`NOTARY_ISSUER` (an App Store Connect API key). Without either, the DMG is
Developer ID signed but not notarized, and Gatekeeper on other Macs rejects
it (`source=Unnotarized Developer ID`). To set it up once, create an App Store
Connect API key (Users and Access → Integrations → Team Keys, "Developer"
access), then:

```sh
xcrun notarytool store-credentials astor-notary \
    --key ~/.appstoreconnect/private_keys/AuthKey_<KEYID>.p8 \
    --key-id <KEYID> --issuer <ISSUER-UUID>
NOTARY_PROFILE=astor-notary scripts/package.sh
```

The DMG is submitted with `xcrun notarytool submit --wait` (Apple notarizes the
app inside it too), then `xcrun stapler staple` and `stapler validate`. On
rejection the script prints `notarytool log` for the submission.

## Install

1. Open `Astor-0.1.0-arm64.dmg` and drag **Astor** onto **Applications**.
   (Check the download first with `shasum -a 256 -c Astor-0.1.0-arm64.dmg.sha256`.)
2. Launch Astor from Applications. Until a build is notarized, macOS blocks the
   first launch: open System Settings → Privacy & Security and click
   **Open Anyway** next to the Astor message, then confirm.
3. Optional, the command-line client: the same `astor` CLI ships inside the app.
   To put it on your `PATH`:

   ```sh
   sudo mkdir -p /usr/local/bin      # not present on every Mac
   sudo ln -s /Applications/Astor.app/Contents/Helpers/astor /usr/local/bin/astor
   astor --help
   ```

Requirements: a Mac with Apple Silicon running macOS 26 or later. The app and
the CLI share `~/Library/Application Support/Astor`. To uninstall, quit Astor,
delete `/Applications/Astor.app` (and the `/usr/local/bin/astor` link if you
made one); remove that folder and `~/Library/Preferences/com.astor.torrent.plist`
to delete its state and settings too.

## What's in the window

- **Sidebar**: All / Downloading / Seeding / Completed / Paused (/ Errors), with counts.
- **Table**: name, progress, status, ↓/↑, peers (seeds), time left, size (+ optional ratio);
  sortable, multi-select, column visibility/width remembered, context menu
  (resume/pause, download in order, show in Finder, copy magnet link / info hash, remove).
  Double-click reveals the download in Finder; ⌫ removes (asks first; optionally
  moves files to the Trash).
- **Inspector** (⌃⌘I / toolbar): Overview (hashes, v1/v2/hybrid, pieces, save path,
  trackers & swarm summary, peer sources, encrypted/µTP/incoming counts, web seeds),
  Peers, Trackers, Files (choose which files to download).
- **Status bar**: total ↓/↑, DHT nodes, listen port, external IP, and reachability
  ("Reachable via UPnP/NAT-PMP" / "Not reachable" with a click-for-help explanation).
- **Adding**: toolbar, ⌘O (.torrent), ⌘U (magnet sheet), ⌘V in the list, drag and
  drop onto the window, and opening `.torrent` files / `magnet:` links from Finder or
  a browser (`.onOpenURL` on a single `Window` scene with `handlesExternalEvents`).
- **Create Torrent** (⌘N): file or folder, hybrid (default) / v1 / v2, trackers,
  private flag, web seeds, comment; hashing runs off the main thread with progress,
  then optionally starts seeding.
- **Settings** (⌘,): download folder, notifications, keep-awake (apply immediately);
  speed limits, DHT/PEX/LSD/extra trackers, port/port mapping/µTP/peer limits,
  encryption (apply after restart, with a one-click **Restart Astor**).

## Architecture

| File | Role |
|---|---|
| `Engine/Engine.swift` | Thread-safe facade over `Session`. Every call that hops onto the event loop (`torrentStatuses()`, `status()`, `allTorrents`, `loop.sync`) runs on a private serial queue and resumes via a continuation, never on the main actor. Loop-confined `Torrent` properties are only touched inside `loop.sync` / `withLoop`. |
| `Engine/Library.swift` | `<state>/app/library.json` + `<state>/app/torrents/*.torrent`. The engine keeps resume data but doesn't re-add torrents on start, so the app re-adds them (paused state, download-in-order and file choices included). |
| `Model/AppModel.swift` | `@MainActor @Observable` source of truth. Polls one snapshot per second, maps `TorrentStatus` → small `Equatable` rows off the main thread, and assigns only what changed (rows, filter counts, session info, selected torrent). Holds an App Nap opt-out while torrents are active. |
| `Views/*`, `Settings/*` | SwiftUI views (`NavigationSplitView` + `Table` + `.inspector`, `safeAreaBar` status bar, `Settings` scene). |
| `AppDelegate.swift` | Starts the engine; on quit returns `.terminateLater`, runs `Session.shutdown` (resume data + tracker "stopped"), then replies. SIGTERM takes the same path. |

State directory: `SessionConfig.defaultStateDirectory` (`~/Library/Application Support/Astor`),
shared with the CLI. Preferences live in the `com.astor.torrent` defaults domain.

### Developer options (launch arguments)

```sh
open build/Astor.app --args -stateDirectory /tmp/astor-test -downloadDirectory /tmp/astor-dl
open build/Astor.app --args -presentOnLaunch select,createTorrent   # also: addMagnet, settings
```

## Known limitations

- Engine settings need a restart (the `SessionConfig` is immutable once the session starts).
- The Peers tab shows the 12 fastest peers (`TorrentStatus.topPeers` is capped by the engine).
- The Files tab has no per-file progress (not in `TorrentStatus`).
- Until the NAT module replaces the stub `PortMapper`, the status bar says "Not reachable"
  unless incoming connections arrive.
- AppKit won't quit while a sheet is open (⌘Q is ignored until the sheet closes).
- Hashing in Create Torrent can't be cancelled midway; Cancel discards the result.
- Not sandboxed. `make-app.sh` builds are ad-hoc signed (for this Mac only); release
  DMGs from `package.sh` are Developer ID signed but need notarizing before
  Gatekeeper accepts them on other Macs (see Notarization).
