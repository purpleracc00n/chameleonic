# chameleonic
Script to help with blending into a network environment.

chameleonic listens passively to the local network, fingerprints the hosts it hears, and takes on the identity of the most common kind of workstation: its MAC vendor, hostname pattern, DNS domain, DHCP fingerprint and TCP/IP stack behaviour. Nothing is sent from the machine until the new identity is in place.

The project has two scripts:

- **`chameleonic.sh`** is passive: it listens, analyses and changes the machine's identity.
- **`chameleonic-probe.sh`** is active: it probes the network and captures the replies, for when listening is too slow or too quiet. It changes nothing, and its capture can be analysed by chameleonic on the same machine or another one (see [Active probing](#active-probing-chameleonic-probesh)).

## How it works

1. **Goes silent.** Detaches the interface from NetworkManager and takes it down, then stops services that announce a Linux host (avahi, cups-browsed, nmbd, wsdd, lldpd, LLMNR/mDNS in systemd-resolved) and DHCP clients. The interface is down first, so the goodbye messages some services send when they stop (avahi's mDNS goodbye, IGMP leaves) are not heard. The stopped services are masked until the original identity is restored, so D-Bus or socket activation (a print dialog, network browsing) cannot start them again. systemd-networkd, if it manages the interface, is told to leave it alone, and VLANs on top of the interface, which would come back up with it and its MAC address, are taken down if the operator agrees (VLANs that were already down are kept down: the kernel would otherwise bring them up with the interface). It then removes the interface's IPv4 address, disables IPv6 on it and gives it a temporary random MAC address.
2. **Listens passively** (5 minutes by default) to broadcast and multicast traffic: ARP, DHCP, NetBIOS, browser announcements, LLMNR, mDNS and SSDP. The capture is saved as a pcapng file.
3. **Fingerprints every host** it heard and classifies it as `windows`, `macos`, `linux`, `mobile`, `printer` or `other`, or `unknown` when nothing it sent says what it is:

   | Signal | Example |
   |---|---|
   | DHCP vendor class | `MSFT 5.0` (Windows), `android-dhcp-*`, `dhcpcd-*` (a hint of Linux), `udhcp` |
   | DHCP parameter request list | Windows 10/11, macOS (which asks for LDAP and NetBIOS options), iOS and iPadOS (which do not: mobile) |
   | Device names, from DHCP, NetBIOS or mDNS | `Johns-iPhone`, `Galaxy-S23` (mobile), `Alices-MacBook-Pro` (macOS) |
   | NetBIOS registrations, browser announcements, LLMNR | Windows |
   | mDNS services and device models | `_ipp._tcp` (printer), `model=MacBookPro18,3`, `_workstation._tcp` (avahi) |
   | SSDP `SERVER` header | `Microsoft-Windows/10.0`, `Darwin`; `Linux/...` (routers, TVs and NAS boxes, not workstations) |
   | NetBIOS name tables | Windows (replies to chameleonic-probe.sh) |
   | WS-Discovery device types | `pub:Computer` (Windows), print and scan device types (printer) |
   | Open TCP ports | 135, 3389, 5985 (Windows), 548 (macOS), 631, 9100 (printer), 62078 (iPhone); 22 says nothing, as servers, NAS boxes and Macs open it alike |
   | Initial IP TTL | 128 (Windows), 64 (Unix-like), 255 (network devices) |

   The initial TTL overrules the other signals: a host answering with TTL 64 is never classed as Windows, and one answering with TTL 128 never as Linux, macOS or mobile. A Linux NAS running Samba answers NetBIOS and SMB like Windows does, but not with Windows' TTL. TTL 64 alone does not make a host a Linux workstation, since routers, NAS boxes and appliances use it too: that takes the DHCP option list of dhclient as Debian and Ubuntu ship it, or avahi's `_workstation._tcp` announcement (off by default in recent avahi). Linux desktops that show neither, like Macs that say little, count as `unknown`. Addresses and TTLs only count for the address a MAC address claims for itself (in ARP or DHCP): a router forwards packets from other hosts, such as DNS answers from a server behind it, with its own MAC address.

4. **Picks a persona**: the most common workstation type (`windows`, `macos` or `linux`). Phones, printers and IoT devices are not imitated: only evidence specific to a workstation makes a host one, so routers, NAS boxes and other Linux-based devices count as `unknown`. If two types are equally common, or no workstation could be fingerprinted, chameleonic asks (see [When the network gives no clear answer](#when-the-network-gives-no-clear-answer)).
5. **Builds the identity from the hosts of that persona**, so the MAC vendor and hostname tell the same story (no Polycom MAC with a laptop hostname):
   - **MAC address**: most common vendor prefix (OUI) among those hosts plus random bytes, never one already in use. Randomised (locally administered) MACs carry no vendor information and are ignored.
   - **Hostname**: finds the string shared by the most hostnames, takes the names that have it at the usual position and with the usual length (at least 3 of them), and compares them character by character: characters they all share are kept, the others become a digit (`#`), a letter (`@`) or either. A new name is generated from that pattern: `LON-WKS-0012`, `LON-WKS-1441`, `LON-WKS-2187` -> `LON-WKS-####` -> `LON-WKS-5820`. Letters that vary, such as site, department or user codes, keep one of the values seen, so a name never mentions a site or user that does not exist: `UK-LON-LT00012`, `UK-MAN-LT00417`, `UK-EDI-LT00533` -> `UK-@@@-LT00###`, with `@@@` one of `LON`, `MAN` or `EDI`. Digits that repeat across the network (`MANCHESTER-FLOOR3-DESK-0412`: the floor) do the same; those that differ on every host, like counters and asset numbers, are random but never one another host already has. A name made only of letters that vary, like user initials (`JSMITH-PC`), cannot be imitated without copying a host, so chameleonic asks. Names are compared in the case most of them use, since NetBIOS names are uppercase while DHCP keeps the case a host was given, and a name NetBIOS cut to 15 characters is replaced by the full name when another protocol gave it, or otherwise left out. The name is never one already seen on the network. `-H` sets the hostname yourself.
   - **DNS domain**: taken from the FQDN other clients send in DHCP (option 81), the domain the DHCP server hands out (option 15), or reverse DNS answers in a capture from chameleonic-probe.sh. The mDNS pseudo-domain `local` is ignored, real domains such as `corp.local` are kept. If none was seen, the domain from the DHCP lease is used.
   - **DHCP fingerprint**: copies the parameter request list, vendor class and FQDN behaviour of the persona's hosts on this network, so it matches whatever Windows/macOS build they run. If none of them requested an address during the capture, chameleonic offers a built-in profile (Windows 10/11, macOS 13+, Debian dhclient).
   - **TCP/IP stack**:

     | Persona | Changes |
     |---|---|
     | windows | TTL / hop limit 128, TCP timestamps off, TCP window scale 8, random IPv6 interface IDs with temporary addresses |
     | macos | TTL / hop limit 64, TCP timestamps on, TCP window scale 6, random IPv6 interface IDs with temporary addresses |
     | linux | unchanged; the IPv6 link-local address follows the new MAC address, or gets a new secret if stable-privacy addresses were configured |

     Each Windows or macOS identity gets a new random IPv6 secret, so its link-local address is new as well: two identities applied one after the other cannot be linked by it. Running chameleonic again with another persona first undoes the previous persona's settings.

     For every persona, only the interface that holds an address answers ARP for it (`arp_ignore=1`, `arp_announce=2`), as Windows and macOS do. Otherwise another interface of this machine on the same network answers for the new address with its own MAC address.

   - **Inbound firewall** (optional, `-f`): makes unsolicited inbound traffic get the persona's answer and hides your own listeners:

     | Persona | Unsolicited TCP, UDP and ping |
     |---|---|
     | windows | silently dropped, like Windows Defender Firewall: no TCP reset, no ICMP port unreachable, no ping reply |
     | macos, linux | every TCP and UDP port answers as closed (TCP reset, ICMP port unreachable), like a host with nothing listening; ping and other ICMP are answered by the stack |

     Ports you need (Responder, ntlmrelayx, reverse shells) stay reachable with `-a`. Replies to your own traffic, DHCP, IPv6 neighbour discovery and IGMP always get through. The rules live in their own nftables table (`inet chameleonic`), so they only add restrictions and never change an existing ruleset. Services are deliberately not emulated: a fake SMB or RDP service is easily spotted from its handshake, which gives the host away more than a closed port does.

6. **Applies it** and requests an address over DHCP with the persona's fingerprint, then sets the `127.0.1.1` line of `/etc/hosts` to the new FQDN and warns if the new hostname already resolves to another host. Each identity starts without a lease, so it never asks the DHCP server for a previous identity's address. The hostname is set until the next reboot only, like the MAC address: a reboot brings the machine back with its original identity, rather than the persona's name with the original MAC address. The firewall rules are loaded before the interface comes up, so the new identity is never reachable without them.

Everything that is changed is saved first, so `--restore` puts the machine back as it was: the MAC address, hostname, the `127.0.1.1` line of `/etc/hosts` (other entries added since are kept), `/etc/resolv.conf` (which dhclient rewrites with the network's DNS servers, through the link if it links to systemd-resolved's or resolvconf's file), the TCP/IP settings, the services, and whatever configured the interface. If anything cannot be put back, `-r` says what, keeps the saved state and can be run again. Only one run at a time can change the identity or restore it; a second one stops at once.

### When the network gives no clear answer

chameleonic never falls back to something the network did not point to without asking. It asks the operator, and moves on to the next alternative if the answer is no:

| Situation | Alternatives offered, in order |
|---|---|
| Two workstation types are equally common | each of them |
| More hosts could not be fingerprinted than the most common workstation type has | using that persona all the same |
| No workstation fingerprinted (only phones, printers, IoT) | the `linux` persona |
| Fewer than 3 hostnames of the persona, no pattern among them, or every name of the pattern is taken | the pattern of all hosts seen (shown with examples, and only if the persona's own hosts follow it), the persona's default naming scheme (`DESKTOP-XXXXXXX`, `MacBook-Pro-N`), a hostname typed in |
| The persona's hosts all use randomised MAC addresses | a randomised MAC address |
| No MAC address of the persona's hosts seen | the most common vendor among all hosts (naming the kind of hosts that use it), a random vendor |
| No host of the persona requested an address | the built-in DHCP fingerprint |
| The capture file is damaged part way through | the packets before the damage |
| The capture has no Ethernet headers (made on `any`, or on Wi-Fi), so only ARP and DHCP identify hosts | using what ARP and DHCP tell |
| The capture file does not exist, or is empty | listening and saving a new capture there |
| Listening stopped before its time without Ctrl-C (cable or adapter pulled, dumpcap failed) | the packets captured so far |
| The interface is a VLAN (or macvlan) whose parent interface still has addresses, so the parent keeps talking with the original MAC address | going on with the parent heard as before |
| VLANs run on top of the interface, and would come back up with it under the new MAC address | taking them down until the original identity is restored |
| dhcpcd serves the interface, and the options it was started with cannot be read back | stopping it, and starting `dhcpcd <interface>` when restoring |
| dhcpcd runs for all interfaces, so it would configure the interface again with the temporary MAC address | going on with dhcpcd running |
| systemd-networkd keeps managing the interface (another `.network` file for it comes first) | going on with it configuring the interface |
| A stopped service cannot be masked, so D-Bus could start it again | going on with it stopped but not masked |
| IPv6 cannot be disabled while listening, or some TCP/IP settings cannot be set | going on without them |
| The MAC address or inbound firewall cannot be set | the current MAC address; no firewall |
| No DHCP lease | asking again (twice), then keeping the identity without an IPv4 address |
| On `-r`, the interface no longer exists (USB adapter unplugged, VLAN deleted) | restoring everything else; otherwise the saved state is kept for when it is back |

Answering no to the last alternative stops chameleonic. If it had already taken over the interface, it offers to restore the original identity (except with `-y`, which never reconnects as the original host on its own), and otherwise leaves the interface as it is, with the capture saved so the next run can skip listening.

Without a terminal to ask on (cron, a pipe), chameleonic stops at the first question and prints it. `-y` accepts every alternative instead, and shows each question it answered. It never accepts going on in a way that exposes the original identity or this machine: keeping the original MAC address, running without the inbound firewall `-f` asked for, a TCP/IP stack only partly the persona's, a service that cannot be masked, IPv6 that cannot be disabled, or a VLAN parent, dhcpcd or systemd-networkd that would keep talking with the original identity. Those stop the run, as answering no would. Combine `-y` with `-p` and `-H` to decide the persona and hostname in advance.

## Usage

```
sudo ./chameleonic.sh [options] <interface> [capture_file]

  capture_file      pcap/pcapng from an earlier capture, passive or made with chameleonic-probe.sh.
                    If it does not exist, chameleonic listens passively and saves the capture there.
                    Default: ./chameleonic-<interface>-<date>.pcapng

Options:
  -t, --time SECONDS     how long to listen passively (default 300)
  -p, --persona NAME     force a persona: windows, macos or linux (default: most common on the network)
  -H, --hostname NAME    use this hostname instead of one following the network's naming pattern
  -f, --firewall         make inbound traffic look like the persona's: silently dropped for Windows,
                         answered as closed ports for macOS and Linux. Hides your own listeners.
  -a, --allow LIST       ports to keep reachable through the firewall, e.g. 445,8000-8100,53/udp,ping
                         (implies -f)
  -x, --exclude MACS     ignore these hosts in the capture, e.g. the machine that captured it
                         (aa:bb:cc:dd:ee:ff,...). Captures made by chameleonic and chameleonic-probe.sh
                         record it themselves.
  -n, --dry-run          analyse and show the plan without changing anything
  -y, --yes              accept every alternative chameleonic proposes when the network gives no clear
                         answer, but never one that exposes the original identity: those stop the run
                         (default: ask; without a terminal, stop)
  -r, --restore          restore the original identity
  -h, --help             show this help
```

Examples:

```
# Listen for 5 minutes, then become the most common workstation type
sudo ./chameleonic.sh eth0

# See what chameleonic would do with an existing capture, without changing anything
./chameleonic.sh -n eth0 office.pcapng

# Reuse a capture and force the Windows persona
sudo ./chameleonic.sh -p windows eth0 office.pcapng

# Also firewall inbound traffic like the persona, keeping a reverse shell listener on 4444 reachable
sudo ./chameleonic.sh -a 4444 eth0

# Unattended: decide the persona and hostname in advance, accept the remaining alternatives
sudo ./chameleonic.sh -y -p windows -H DESKTOP-4KQ7Z1M eth0 office.pcapng

# Put everything back
sudo ./chameleonic.sh -r
```

Press Ctrl-C while listening to stop early and continue with what was captured. A longer capture sees more hosts: DHCP requests and NetBIOS registrations mostly happen when machines boot or join the network, so the start of the working day gives the best results.

A dry run without a capture file listens with the machine's current identity and changes nothing.

When run with `sudo`, the capture file belongs to your user, so you can open it without root.

### Capturing for later

To collect traffic now and analyse it later, capture with the same filter chameleonic uses:

```
sudo dumpcap -i eth0 -f "broadcast or multicast or arp or udp port 67 or udp port 68" -a duration:1800 \
    --capture-comment "chameleonic-exclude=$(cat /sys/class/net/eth0/address)" -w /tmp/office.pcapng
sudo chown "$USER:" /tmp/office.pcapng
```

Then pass the file to a dry run, which needs neither root nor the network, nor an interface of that name on the machine that analyses it: `bash chameleonic.sh -n eth0 /tmp/office.pcapng`. Save the capture under `/tmp` (see [Troubleshooting](#troubleshooting)). The capture comment records the capturing machine's MAC address, so chameleonic ignores that machine's own traffic; for captures without it, use `-x`.

### Restoring

`sudo ./chameleonic.sh -r` restores the original MAC address, hostname, the `127.0.1.1` line of `/etc/hosts`, `/etc/resolv.conf`, TCP/IP settings, stopped services, and VLANs taken down with their addresses and routes, removes the firewall rules, and hands the interface back to what configured it: NetworkManager (reconnecting the connection that was active), systemd-networkd, the DHCP client exactly as it was started (with its own lease and pid files), or static IPv4 and IPv6 addresses and routes. An interface that was down stays down, unless NetworkManager or systemd-networkd manage it. The saved state lives in `/var/lib/chameleonic`, and is kept if something could not be restored. If the MAC address or the hostname cannot be put back, the interface stays down and the services stopped, so the original name is never heard with the persona's MAC address, or the other way round. Running chameleonic again before restoring keeps the original identity saved from the first run, and undoes the previous persona's settings before applying the new one.

## Active probing: chameleonic-probe.sh

chameleonic only listens, and on a quiet network listening can take a long time. `chameleonic-probe.sh` makes the hosts answer instead, and records their answers in a capture that chameleonic analyses like any other.

```
sudo ./chameleonic-probe.sh [options] <interface> [capture_file]

  capture_file          where to save the capture
                        Default: ./chameleonic-probe-<interface>-<date>.pcapng

Options:
  -r, --range CIDR      addresses to probe (default: the interface's subnet, at most 4096 addresses)
  -t, --time SECONDS    how long to keep listening after probing (default 30)
      --rate N          probes per second for the address sweep (default 100)
      --tcp             also connect to TCP ports 22,135,139,445,548,631,3389,5985,9100,62078 on every
                        host that answered (loudest)
  -h, --help            show this help
```

What it sends:

| Probe | What the answers give chameleonic |
|---|---|
| NetBIOS name table request to every address in the range | computer names of Windows and Samba hosts; the ARP requests it triggers reveal every live host |
| mDNS query for common services | host names, device models and services of Macs, phones, printers and Linux hosts |
| SSDP search | operating systems in the `SERVER` header |
| WS-Discovery probe | Windows PCs (`pub:Computer`) and printers |
| Reverse DNS lookup of every host that answered | host names and the DNS domain |
| TCP connections (`--tcp`) | open ports, and the TTL of hosts that ignore everything else |

Every reply also gives the host's initial TTL. The probes are sent from the interface's current address and MAC, so run it from a machine whose identity on the network does not matter, or before chameleonic disguises this one. It does not change the machine's identity: the only change is temporary routes that send the multicast queries out of the probed interface, and they are removed when the script exits, also when it is killed or the terminal hangs up. It asks before overwriting an existing capture file, and before reverse DNS lookups that would go to a DNS server through another interface (a VPN, a public resolver), which would tell that server every live address. It also asks when it cannot tell which way they would go: a local resolver such as dnsmasq or unbound, or systemd-resolved's fallback servers. It asks as well before probing a range beyond the interface's subnet (hosts behind a router answer with the router's MAC address, so chameleonic cannot tell them apart), and before leaving out mDNS, SSDP or WS-Discovery queries that a route of yours would send through another interface.

Example: probe from one machine, analyse and apply on another:

```
# On the probing machine
sudo ./chameleonic-probe.sh --tcp eth0 office-active.pcapng

# On the machine to disguise, after copying the file over
bash chameleonic.sh -n eth0 office-active.pcapng     # check the plan
sudo bash chameleonic.sh eth0 office-active.pcapng   # take on the identity
```

The capture records the probing machine's MAC address, so chameleonic ignores the probes themselves.

When the interface's subnet has more than 4096 addresses, it offers to probe the /20 around the machine's own address instead. If another interface of the machine has a more specific route to the range, the probes would leave through that one, with its MAC and address: it says so and asks before sending anything.

This is noisy by design. The NetBIOS sweep and the ARP requests it triggers reach every address in the range, and some replies arrive after the sending socket has closed, so the probing machine answers them with ICMP port unreachable, as with any UDP scanner. `--tcp` completes TCP connections, which host firewalls and EDR log. DHCP fingerprints still only come from listening: hosts do not request addresses because they were probed, so chameleonic offers the persona's built-in DHCP profile unless the capture also caught DHCP requests. Use `-t` to listen longer after probing.

## Requirements

### System

- Kali Linux, or another Debian-based distribution, with systemd
- Bash 4.3 or later (both scripts say so and stop under `sh` or an older bash)
- A wired network interface (Wi-Fi is not supported)
- Root privileges. The only exception is a dry run (`-n`) of chameleonic on an existing capture file.

### Packages

| Package | Command | Needed for | Required |
|---|---|---|---|
| `tshark` | `tshark` | parsing captures, MAC vendor names | always |
| `wireshark-common` (installed with `tshark`) | `dumpcap`, `capinfos` | capturing traffic while listening; reading which machine made a capture | `dumpcap` unless a capture file is given |
| `macchanger` | `macchanger` | setting the MAC address | yes, unless `-n` |
| `isc-dhcp-client` | `dhclient` | requesting an address with the persona's DHCP fingerprint | yes, unless `-n` |
| `iproute2` | `ip` | bringing the interface down and up, managing addresses | yes, unless `-n` (preinstalled) |
| `procps` | `sysctl`, `pgrep` | TCP/IP stack settings, finding DHCP clients | yes, unless `-n` (preinstalled) |
| `systemd` | `hostnamectl` | reading and restoring the saved hostname | yes, unless `-n` (preinstalled) |
| `libc-bin` | `getent` | checking whether the new hostname is already in DNS | yes, unless `-n` (preinstalled) |
| `nftables` | `nft` | the inbound firewall | only with `-f` or `-a` |
| `network-manager` | `nmcli` | detaching the interface and handing it back on restore | used if present |
| `systemd-resolved` | `resolvectl` | turning off LLMNR and mDNS on the interface | used if present |

chameleonic-probe.sh only needs `wireshark-common` (`dumpcap`, and `capinfos` for the packet count), `iproute2`, `libc-bin` (`getent`) and `coreutils` (`timeout`). It works on any Linux distribution and any Ethernet or Wi-Fi interface with an IPv4 address.

Install everything that is not already on Kali with:

```
sudo apt install tshark macchanger isc-dhcp-client nftables
```

chameleonic checks for each required command before changing anything and prints the package to install if one is missing.

`dhclient` is needed because it is the only common DHCP client that can send a custom parameter request list in a chosen order; NetworkManager's built-in client cannot. It is deprecated upstream but still packaged in Kali. Wireshark 4.2 or later gives the most complete vendor names; older versions fall back to macchanger's list.

## Tips

- The best time to run chameleonic is before the machine has talked to the network. NetworkManager connects as soon as a cable is plugged in, sending the real MAC address and hostname (`kali`) in its DHCP request. To avoid this, run `sudo nmcli device set eth0 managed no` before plugging in. chameleonic does not need the interface to be up or configured.
- Check the plan with `-n` on a saved capture before applying it. Applying draws the hostname's random characters and the MAC address's last bytes again; pass `-H` with the hostname from the plan to keep it.
- If you set the interface unmanaged as in the first tip, `-r` leaves it unmanaged, as it was when chameleonic started: `sudo nmcli device set eth0 managed yes` hands it back to NetworkManager.
- Running chameleonic again to switch persona asks whether to keep the previous run's inbound firewall when `-f` or `-a` is not given again; answering no removes it.

## Troubleshooting

**`tshark crashed (segmentation fault) on this system, so nothing was changed`**

chameleonic tests tshark before touching the interface. A crash on start-up means the Wireshark install is broken, not the script. On Kali rolling this is almost always a partial upgrade (tshark and its libraries from different versions) or a stale plugin.

1. Compare `tshark -v` and `sudo tshark -v`. If only the root one crashes, look for old plugins in `/root/.config/wireshark/plugins` and `/root/.local/lib/wireshark/plugins`.
2. Check the versions with `dpkg -l | grep -E 'tshark|wireshark|libwireshark|libwiretap|libwsutil'`. They should all match.
3. Upgrade the whole system: `sudo apt update && sudo apt full-upgrade`.
4. If it still crashes: `sudo apt install --reinstall tshark wireshark-common`.

**`dumpcap: The file to which the capture would be saved ... could not be opened: Permission denied`**

Only when you run `dumpcap` yourself. Running as root, `dumpcap` drops every privilege except capturing, so it cannot write to directories owned by other users, such as your home directory. Save the capture under `/tmp` instead. chameleonic handles this itself.

**`Stopped before the new identity was fully applied`**

Something failed after the interface was taken over, so it may have no address. Run `sudo bash chameleonic.sh -r` to restore the original identity, fix the cause shown above the message, then run chameleonic again.

## Limitations

- Wired interfaces only: on Wi-Fi, NetworkManager and wpa_supplicant control the MAC address and the association.
- On a VLAN interface (`eth0.100`) only the VLAN interface takes on the identity. Its parent keeps its own MAC address, and is heard as before if it has addresses: chameleonic asks before going on (see the table above).
- The TCP SYN matches the persona's TTL, window size, window scale and timestamps, but the Linux order of TCP options is kept (Windows sends MSS, NOP, WS, NOP, NOP, SACK; Linux sends MSS, NOP, NOP, SACK, NOP, WS). Matching it would need packet rewriting. Other stack traits, such as IP ID behaviour, are not changed either.
- dhclient sends DHCP options in its own order (53, 12, 81, 55, 60, 61), and the FQDN (option 81) in DHCPDISCOVER too, where Windows sends it only in DHCPREQUEST. The parameter request list, vendor class and FQDN themselves match the persona, and fingerprinting systems mostly rely on those. dhclient's own DNS updates are turned off, as Windows clients update Active Directory DNS themselves, securely.
- A capture on a trunk port mixes the hosts of every VLAN on it. Hosts heard only over IPv6 give little evidence: their hop limit and DHCPv6 options are not read.
- The identity does not survive a reboot: the machine comes back with its original MAC address, hostname and settings. Only the `127.0.1.1` line of `/etc/hosts` and `/etc/resolv.conf` keep the persona's values (the original name stays resolvable); run `-r` after a reboot to put them back.
- The firewall assumes the default behaviour of each persona. Networks whose workstations allow ping or file sharing by policy answer differently; use `-a ping` or `-a 445` to match them.
- ISC dhclient is deprecated upstream but still packaged in Kali.

