# vpnks — VPN killswitch + per-app VPN (Qt6)

For a NetworkManager-managed strongSwan (IKEv2) VPN, or WireGuard (split tunnel managed by vpnks,
see [WireGuard](#wireguard)). Two independent features:

- **Full-tunnel killswitch.** Arm once and the rules stay until you disarm, whatever the tunnel does.
  Backends: firewalld, iptables, nftables, ufw.
- **Per-app VPN.** Only apps started through vpnks use the VPN, by one of three methods (a single
  global switch, see [Per-app method](#per-app-method)): a network namespace (default), cgroup
  rules as a split tunnel, or cgroup rules as a per-app killswitch.

You pick the mode in the NetworkManager applet: connect your original profile for a full tunnel, or
the "(split)" copy that vpnks creates for split tunnelling.

## Build & install
Prerequisites are qt6, ninja and cmake:
```
pacman -S qt6-base qt6-wayland cmake ninja
```
To compile
```
mkdir build
cd build
cmake ..
make
```
optionally, can install system wide with `sudo make install` or otherwise.

The install step creates the system group `vpnks` (`groupadd -r vpnks`); the polkit rule grants
passwordless use to its members. Add your user to it and log out and back in or run `newgrp`:
```
sudo usermod -aG vpnks $USER
```

| Installed file | Purpose |
|---|---|
| `/usr/local/bin/vpnks` | the app |
| `/usr/lib/vpnks/vpnks-helper` | root helper: namespace setup/teardown, tunnel attach/detach, app launch |
| `/etc/NetworkManager/dispatcher.d/90-vpnks` | calls the helper on vpn-up / vpn-down |
| `/etc/vpnks/helper.conf` | names, host-only link addresses, fallback DNS, per-app method, cgroup mark/table |
| `/usr/lib/systemd/system/vpnks.slice` | persistent slice for the cgroup methods (enabled on first switch to one) |
| `/usr/share/polkit-1/actions/org.vpnks.helper.policy` | pkexec action for the helper |
| `/etc/polkit-1/rules.d/50-vpnks.rules` | no password prompts for members of group `vpnks` (helper, firewalld, and pkexec of iptables/ip6tables/nft/ufw — delete that last block if you only use firewalld) |

## Per-app VPN

1. **Create split profile…** → pick your VPN connection. vpnks runs
   `nmcli connection clone` and sets on the copy `connection.interface-name vpnks0`,
   `ipv4.never-default yes`, `ipv6.never-default yes`. The original is untouched.
2. Connect **"<name> (split)"** from the NetworkManager applet.
3. **Add…** an app (name + command), then **Launch** (or double-click, or the tray's *Launch in VPN*).
   **Add to app menu** creates an "<App> (VPN)" launcher (`vpnks --launch <id>`).

The table shows how many processes of each app are running under the current method.

### WireGuard

**Create split profile…** also lists NetworkManager WireGuard connections and a
*WireGuard .conf file…* entry (wg-quick format). Either is imported into
`/etc/vpnks/wg/<name>.conf` (root-only, mode 0600); a **WireGuard:** row then offers
**Connect** / **Disconnect** / **Remove**. Needs `wireguard-tools` (`wg`).

- vpnks, not NetworkManager, brings the tunnel up (`vpnks-helper wg-up <name>`), so it does not
  appear in the applet. NetworkManager owns the WireGuard interfaces it creates and would mark the
  connection failed once the interface left its namespace.
- The interface is created as `vpnks0` in the root namespace and then moved into the namespace:
  WireGuard keeps its UDP socket in the namespace it was created in, so the encrypted packets use
  the normal connection while the plaintext side serves only the namespace. All three per-app
  methods work unchanged on top of it.
- Only `PrivateKey`, `ListenPort`, `Address`, `DNS`, `MTU` and the peer keys are kept on import;
  `PostUp`/`PreDown`/`Table`/… are dropped and never run. Only IPv4 addresses and DNS servers are
  used. Endpoint host names are resolved when connecting.
- Importing from NetworkManager needs the private key stored in the connection (the default); a
  key held by a secret agent cannot be read, import the .conf file instead.
- Only one tunnel at a time: disconnect a connected "(split)" profile before connecting WireGuard,
  and vice versa. With the full-tunnel killswitch armed, add the WireGuard server to its endpoints.

### Per-app method

Chosen with **Method:** in the window; one global setting, stored in `/etc/vpnks/helper.conf`
(`MODE=`) and changed through the helper (`vpnks-helper set-mode …`).

| | Network namespace | cgroup — split tunnel | cgroup — killswitch only |
|---|---|---|---|
| Profile to connect | "(split)" | "(split)" | your normal one (full tunnel) |
| Apps run in | namespace `vpnks` | `vpnks.slice`, normal network stack | `vpnks.slice`, normal network stack |
| Kept out of the VPN by | routing (no other way out exists) | firewall rules + policy routing | firewall rules |
| If the rules are flushed | still confined | apps fall back to the normal connection | apps fall back to the normal connection |
| Host's localhost / LAN discovery | not reachable (host at 10.99.0.1) | reachable | reachable |
| Backends | any | firewalld, iptables, nftables | firewalld, iptables, nftables |

The namespace is the safer default: it fails closed by construction. Use a cgroup method when an app
needs the host's localhost services or LAN multicast (DLNA, Chromecast, mDNS).

Switching methods leaves apps alone where that is safe: apps already inside the namespace
stay there. Leaving a cgroup method while apps run in the slice requires stopping them (the window
asks), because their rules change.

### cgroup methods: how it works

- Apps are launched into `vpnks.slice/vpnks-<app>-<n>.scope` of the **system** manager
  (`systemd-run --scope`), then drop to your user exactly as in the namespace method (setpriv: no
  capabilities, no_new_privs). The helper refuses to start the app if it is not inside the slice.
- The firewall rules match the slice by cgroup path. The kernel resolves that path once, when a
  rule is inserted, and keeps that cgroup. The old per-app rules broke on exactly this (path missing
  before the first launch, stale after re-login). The slice therefore exists before firewalld loads
  its permanent rules (`WantedBy=slices.target`) and is never recreated (`RefuseManualStop=yes`).
  One slice is enough, because the match covers everything below it.
- **Killswitch only:** processes in the slice may use lo, local addresses, the LAN, the host-only
  link and the full tunnel (`nm-xfrm*`); everything else is rejected, IPv6 too.
- **Split tunnel:** additionally their IPv4 packets are marked (`0x766b`), and while the split profile
  is connected the helper adds

      ip rule pref 99  fwmark 0x766b lookup main suppress_prefixlength 0   # LAN/link routes still apply
      ip rule pref 100 fwmark 0x766b lookup 211                            # default via 10.99.0.2 dev vpnks-h

  Marked traffic goes over the host-only link into the namespace. The helper turns the namespace
  into a router there: it forwards only from `vpnks-ns` to `vpnks0` (plus replies), clamps the MSS
  and NATs to the VPN address. The host NATs marked traffic onto the link (10.99.0.1). Apps get the
  namespace's `resolv.conf`/`nsswitch.conf` in a private mount namespace, so DNS goes through the
  tunnel too.
  Without the split profile the routing rules are absent, so marked traffic follows normal routing:
  through a full tunnel if one is up (accepted), otherwise it is rejected.
- Rules are re-applied when the window starts, before every launch and on **Refresh**, if missing or
  built from different settings (the rule comment carries a fingerprint). iptables/nftables rules
  are runtime-only, so after a reboot they come back when vpnks starts; firewalld keeps them
  permanently. With apps still running under older rules, vpnks keeps those and asks you to quit
  the apps.

### Namespace method: how it works

- charon-nm names its XFRM interface after `connection.interface-name`, so the split profile's
  tunnel is always `vpnks0` (the full-tunnel profile keeps `nm-xfrm-<id>`).
- On vpn-up the dispatcher hook moves `vpnks0` into the namespace. An XFRM interface can live in a
  different namespace from its SAs: charon-nm and the SAs stay in the root namespace, only the
  plaintext side moves. The routes charon-nm had installed via `vpnks0` (table 210) vanish with the
  move, so the host goes back to its normal default route. No strongSwan configuration is changed.
- Inside the namespace: `lo`, `vpnks0` (virtual IP, default route), `vpnks-ns` (10.99.0.2/30,
  host-only). `resolv.conf` holds the VPN's DNS servers (fallback from helper.conf), and
  `nsswitch.conf` resolves hosts with plain DNS instead of the host's systemd-resolved.
- Fail-closed: on vpn-down the hook removes `vpnks0`, so namespaced apps have no route at all.
  Even if the hook never ran, an XFRM interface without SAs drops everything.
- Apps run as you, with all IDs dropped, no capabilities, an empty bounding set and
  `no_new_privs`: they cannot change routes, open raw sockets or leave the namespace, and setuid
  binaries don't elevate. The helper only accepts a whitelist of session variables
  (display, D-Bus, locale, …) from the caller.
- A dummy placeholder called `vpnks0` stays in the root namespace. After an IKE
  re-establishment charon-nm re-sends its IP config and NetworkManager looks the tunnel up again
  by name; without the placeholder it would mark the VPN failed. (`PLACEHOLDER=no` disables it.)

### Host-only link

From the desktop, services inside the namespace are at **10.99.0.2**, e.g. the Transmission web UI
at `http://10.99.0.2:9091` (add `10.99.0.1` to Transmission's `rpc-whitelist`). The namespace has
no route beyond this /30 and the host doesn't forward from it. When armed, the killswitch also
allows the /30, so the link keeps working.

### Caveats

- Only apps started through vpnks are inside. The normal menu entry still starts them outside.
- **Single-instance apps hand off** to a copy that is already running outside: launching Firefox
  or Transmission in the namespace while it runs outside just opens a window in the outside copy.
  Quit it first, or give the VPN copy its own profile (e.g. `firefox -P vpn --no-remote`). The other
  direction is fine: a magnet link opened elsewhere reaches the namespaced Transmission.
- Work delegated to desktop services that run outside (portals, KIO/gvfs daemons) does not go
  through the VPN.
- Apps that need a setuid or polkit helper for something (e.g. mounting) can't do that inside.
- If the virtual IP changes on an IKE re-establishment, the namespace keeps the old address and
  traffic is dropped (safe) until you reconnect. A static virtual IP is not affected.
- The full-tunnel killswitch and split mode don't mix: when armed, the host's own traffic is
  blocked. The namespace keeps working (its packets leave encrypted to the allowed endpoint), but
  disarm the killswitch when you use the split profile.
- cgroup methods rely on the firewall rules staying loaded while apps run. Flushing them (or
  `systemctl stop firewalld` with the firewalld backend) lets running apps out unconfined until
  vpnks re-applies them. The namespace method has no such dependency.
- cgroup — killswitch only: apps resolve through the host's resolver, which is not confined. With
  the tunnel down their connections are blocked, but DNS lookups can still leave outside it (arm the
  full-tunnel killswitch to stop that).

### Troubleshooting

    sudo /usr/lib/vpnks/vpnks-helper status     # interfaces, routes, processes, DNS inside
    journalctl -t vpnks-helper -f               # helper log (dispatcher + launches)
    journalctl --user -u 'vpnks-*'              # launched apps' stdout/stderr
    vpnks --status

- *"no vpnks0 interface"*: the split profile isn't connected, or lacks `connection.interface-name`.
- *"vpnks0 is a 'tun' device"*: charon-nm could not create the XFRM interface (typically a
  leftover device with that name after a crash) and fell back to a TUN device. Disconnect, run
  `sudo /usr/lib/vpnks/vpnks-helper detach`, reconnect.
- Teardown refuses while apps run inside; the GUI offers to stop them (`teardown --force`).
- cgroup methods: `vpnks --status` shows whether the rules are loaded and current;
  `systemctl status vpnks.slice` lists the running apps; `ip rule | grep 0x766b` shows the split
  routing; `sudo nft list table ip vpnks_router -n` (inside: `ip netns exec vpnks …`) shows the
  namespace router. *"not running inside vpnks.slice"*: the slice isn't installed or active — run
  `sudo cmake --install build`, then switch the method again.

## Full-tunnel killswitch

Policy installed by every backend (same semantics, backend-native syntax):

    accept -> loopback / local addresses
    accept -> LAN CIDRs (+ the namespace host-only link if the helper is installed)
    accept -> VPN servers, only on the uplink(s): the live peers of the full tunnel
              + configured endpoint IPs (hostnames resolved at arm time)
    accept -> optional DNS servers on :53
    accept -> anything leaving via the full tunnel (IPsec: nm-xfrm+ / "nm-xfrm*"; WireGuard: its interface)
    REJECT everything else          (IPv6: reject all unless "block IPv6" is off)

Rules are tagged `vpnks:global` so disarm removes exactly what was installed.

**Full-tunnel connection** (Settings): the NetworkManager connection that serves as full tunnel,
for the killswitch and for the per-app *killswitch only* method — an IPsec (strongSwan) or a
WireGuard connection. It sets the tunnel interface (IPsec: `nm-xfrm*`; WireGuard: the connection's
`interface-name`). While it is up, vpnks reads the VPN servers it is actually connected to
(`vpnks-helper peers`: `ip xfrm state` and `wg show all endpoints`) and allows them, re-arming when
they change (a reconnect, another server behind the same hostname). This matters for the per-app
rules too: the encrypted packets of an IPsec tunnel still carry the socket of the app that sent
the plaintext, so without the server allowed they hit the cgroup REJECT. Rules are replaced
without a gap (firewalld: add, then remove the stale ones; iptables: new chain, then swap;
nftables: one atomic transaction). vpnks has to run (the tray is enough) to follow a reconnect.

Setup: Settings… → backend (the one that actually manages your firewall), full-tunnel connection,
optionally fixed endpoints (or "Import from NM…" to pull `address=` from the strongSwan connection),
needed only to arm before the tunnel is up, LAN. Uplink interface(s):
leave empty to use every device with a default route (`ip route show default`, v4+v6, tunnel
excluded); vpnks re-arms automatically when that set changes. Autostart: `vpnks --hidden`.

### CLI

    vpnks --status
    vpnks --arm | --disarm
    vpnks --arm --dry-run        # print every command without executing
    vpnks --launch <app-id>      # start a configured app with the current per-app method

### Backend notes

- **firewalld**: `--direct` rules, runtime + `--permanent`. Survives reboot. cgroup rules at
  priorities 4–5 (between the killswitch's accepts and its REJECT), plus mangle/nat for split.
- **nftables**: own table `inet vpnks`: chain `global` (killswitch), `cg_filter`, `cg_mark`,
  `cg_nat` (cgroup methods). Runtime only; add `nft list table inet vpnks` output to
  /etc/nftables.conf if you want the killswitch at boot.
- **iptables**: chains `VPNKS_GLOBAL` and `VPNKS_CGROUP` (iptables + ip6tables), `VPNKS_CGMARK`
  (mangle), `VPNKS_CGNAT` (nat). Runtime only; `iptables-save > /etc/iptables/iptables.rules` +
  iptables.service for persistence.
- **ufw**: `default deny outgoing` + tagged allows. ufw can't wildcard interfaces, so the tunnel allow
  uses the concrete `nm-xfrm-NNN` name and vpnks re-adds it on reconnect (needs the app running).
  ufw cannot match cgroups: only the namespace method works with it.

All backends allow the host-only link (`vpnks-h`) while armed: it only leads into the namespace.

Do not run two backends, or raw iptables next to firewalld — they will fight.

### DNS

Leave "DNS servers" empty to fail closed: with the tunnel down nothing resolves. That also means
charon can't re-resolve a hostname endpoint — the resolved IP stays allowed, so reconnects work as
long as the server IP hasn't changed. Add your LAN router as a DNS server (already inside the LAN
allow) if you want resolution while down.

## X11 / Wayland

One binary; Qt picks `xcb` or `wayland` from the session (`qt6-wayland` must be installed on Arch for
the Wayland plugin — it is not part of `qt6-base`). Specifics handled:

- tray: XEmbed on X11, StatusNotifierItem (D-Bus) on Wayland/Plasma. If no tray host exists (GNOME
  without an AppIndicator extension, bare wlroots) vpnks polls for ~30 s, then runs as a plain window
  and close = quit.
- window icon: X11 gets it directly; Wayland resolves app_id `vpnks` → `vpnks.desktop` → `Icon=`,
  hence the installed icon + `StartupWMClass`.
- "Show window" from the tray toggles visibility rather than raise-only, because Wayland's
  focus-stealing prevention ignores raise()/activateWindow() on an already-mapped window.
- apps launched into the namespace get your `DISPLAY` / `WAYLAND_DISPLAY` / `XDG_RUNTIME_DIR` /
  D-Bus address, so they open on your desktop either way.

Force a platform for testing: `QT_QPA_PLATFORM=xcb vpnks` / `QT_QPA_PLATFORM=wayland vpnks`.

## Upgrading from earlier versions

- The old per-app cgroup rules (one slice per app under your user manager) are replaced by the
  cgroup methods above. Arm/disarm removes leftovers automatically. To clean firewalld's permanent
  config right away (keeps the new `vpnks:apps` rules):

      firewall-cmd --permanent --direct --get-all-rules | grep -- '-m cgroup' | grep -v 'vpnks:apps' |
        while read -r r; do firewall-cmd --permanent --direct --remove-rule $r; done
      firewall-cmd --reload

- Delete `/etc/NetworkManager/dispatcher.d/99-strongswan-killswitch` and run
  `firewall-cmd --reload`. The killswitch replaces it, and rules it left from a full-tunnel session
  would block the host once you switch to the split profile.
- `/etc/strongswan.d/charon-nm-split.conf` (`install_routes_xfrmi = no`) is not needed: moving the
  interface removes those routes. Delete it so the full-tunnel profile routes exactly as before.
- `50-vpnks-firewalld.rules` / `50-vpnks-pkexec.rules` in `/etc/polkit-1/rules.d/` are replaced by
  `50-vpnks.rules`; delete the old ones.

## Uninstall

Switch **Method** back to *Network namespace* first (removes the cgroup rules, including firewalld's
permanent ones), disarm, tear down the namespace, then remove the installed files listed above and
run `systemctl disable vpnks.slice`. Removing the slice while permanent rules still reference it
would make firewalld fail to load them at boot.
