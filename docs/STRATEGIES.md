# Structured strategies

Strategies are configuration data, not shell scripts.

A strategy file currently describes:

- TCP and UDP port ranges;
- relative domain/IP list paths;
- a validated sequence of supported desynchronization stages.

Unknown TOML fields are rejected.

Current stage names are:

- `fake`
- `multi-split`
- `multi-disorder`
- `fake-split`
- `udp-length`
- `ip-fragment2`

The compiler translates validated data into arguments for the bundled `nfqws`
(Linux), `utunws` (macOS), or `winws2` (Windows). It does not accept arbitrary
engine command-line fragments. Windows profiles use the pinned engine's Lua
API; Unix profiles use the v1 desynchronization arguments.

## Bundled profiles

The desktop ships Standard (fake packets), Split (fake + multi-split), and
Disorder (fake + multi-disorder). The latter two split TCP payloads at positions
1 and 2. UDP uses the supported fake stage, not TCP splitting. Select a profile
in the app before starting; changing a profile requires restarting filtration.

The bundled list covers YouTube pages, video delivery, images and API hosts,
plus Discord pages, gateway, CDN, attachments and activities. Entries match
subdomains too. The supplemental API/CDN domains come from the default lists
of the macOS upstream pinned in `third_party/upstream.lock.toml`.

- HTTP/TLS: TCP 80, 443, 2053, 2083, 2087, 2096 and 8443, restricted by the
  configured domain/IP lists.
- QUIC: UDP 443, restricted by the same lists.
- Discord voice discovery and STUN: UDP 19294–19344 and 50000–50100,
  restricted by protocol detection instead of a hostname list. These packets
  do not carry the HTTP Host/TLS SNI required for hostname matching.

These UDP ranges follow the pinned macOS upstream configuration. They are not
a promise to cover every voice-server port: Discord assigns the endpoint at
connection time. macOS currently routes IPv4 traffic only.

## What the method can and cannot do

DPI desynchronization changes how a filtering middlebox interprets the initial
packets. It does not create a tunnel, change the destination IP, repair DNS, or
make an unreachable route reachable. A strict destination-IP allowlist can
therefore still prevent access. An encrypted or otherwise unrecognizable
hostname can also prevent a domain-list profile from matching.

Native CI checks that each bundled engine accepts all three profiles and can
start, stop and recover from an unexpected exit. Those checks do not establish
YouTube playback or Discord voice connectivity on a particular provider.
Check playback, seeking, attachments and a voice call in the target network;
try another bundled profile if needed and use the app's diagnostics on failure.

`examples/strategy.example.toml` remains a standalone example; the desktop uses
the staged profiles generated from `apps/desktop/resources/default/`.
