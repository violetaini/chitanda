# Chitanda downstream automation contract

Chitanda publishes a Mihomo-compatible core for downstream clients, but each
downstream has a different integration boundary. The downstream repositories
are independent private mirrors, not GitHub forks, so upstream code and
Chitanda overlays remain isolated.

## Release contract

`releases/mihomo/release-contract.json` is the single machine-readable
contract between the core producer and downstream builds.

Every Chitanda-integrated Mihomo release must provide:

- a versioned release whose tag equals the upstream Mihomo tag;
- `sha256sums.txt` for every versioned asset;
- a stable `chitanda-mihomo-latest` release containing `version.txt` and
  `manifest.json` that identify one fully-built versioned release;
- desktop assets for every platform enumerated by the contract; and
- an OpenClash-compatible `tar.gz` channel whose archive contains an
  executable named `clash`.

The stable channel must only advance after every required artifact has been
built and its checksum recorded. Consumers must obtain the version from the
stable channel, then download only the pinned versioned asset. They must not
follow GitHub's repository-wide `releases/latest` endpoint: Chitanda publishes
both Xray and Mihomo releases, so that endpoint does not identify a core type.

## Downstream boundaries

| Consumer | Integration boundary | Required validation |
| --- | --- | --- |
| OpenClash | Its OpenWrt core artifact channel | archive contains `clash`; `clash -v`; OpenWrt architecture mapping |
| Clash Verge Rev | build-time sidecar download and in-app core upgrader | checksum; staged `mihomo -v`; Tauri package smoke test |
| Clash Meta for Android | Mihomo source submodule before Android native build | overlay applies; four ABI builds; APK starts and accepts a Chitanda profile |

CMFA is intentionally source-overlay based. Repointing it at a desktop release
URL cannot work because its Android library is compiled from the Mihomo source
submodule.

## Synchronization policy

Each downstream workflow polls its upstream releases/tags. A newly detected
tag is applied to a candidate branch, receives the project-specific overlay,
and builds against a pinned Chitanda core manifest. A failed overlay, missing
asset, checksum mismatch, or smoke-test failure blocks publication. A candidate
must not replace the last working downstream release.

This repository is the core producer. The three consumer repositories keep the
project-specific synchronization code and never receive each other's build
toolchains.
