# chameleonic
Script to help with blending into a network environment.

chameleonic listens passively to the local network, fingerprints the hosts it hears, and takes on the identity of the most common kind of workstation: its MAC vendor, hostname pattern, DNS domain, DHCP fingerprint and TCP/IP stack behaviour. Nothing is sent from the machine until the new identity is in place.

The project has two scripts:

- **`chameleonic.sh`** is passive: it listens, analyses and changes the machine's identity.
- **`chameleonic-probe.sh`** is active: it probes the network and captures the replies, for when listening is too slow or too quiet. It changes nothing, and its capture can be analysed by chameleonic on the same machine or another one (see [Active probing](#active-probing-chameleonic-probesh)).

## How it works

1. **Goes silent.** Stops services that announce a Linux host (avahi, cups-browsed, nmbd, wsdd, lldpd, LLMNR/mDNS in systemd-resolved), detaches the interface from NetworkManager and DHCP clients, removes its IPv4 address, disables IPv6 on it and gives it a temporary random MAC address.
2. **Listens passively** (5 minutes by default) to broadcast and multicast traffic: ARP, DHCP, NetBIOS, browser announcements, LLMNR, mDNS and SSDP. The capture is saved as a pcapng file.
3. **Fingerprints every host** it heard and classifies it as `windows`, `macos`, `linux`, `mobile`, `printer` or `other`:

   | Signal | Example |
   |---|---|
   | DHCP vendor class | `MSFT 5.0` (Windows), `android-dhcp-*`, `dhcpcd-*`, `udhcp` |
   | DHCP parameter request list | Windows 10/11 and Apple lists |
   | NetBIOS registrations, browser announcements, LLMNR | Windows |
   | mDNS services and device models | `_ipp._tcp` (printer), `model=MacBookPro18,3`, `_workstation._tcp` (avahi) |
   | SSDP `SERVER` header | `Microsoft-Windows/10.0`, `Linux/...` |
   | NetBIOS name tables | Windows (replies to chameleonic-probe.sh) |
   | WS-Discovery device types | `pub:Computer` (Windows), print and scan device types (printer) |
   | Open TCP ports | 135, 3389, 5985 (Windows), 631, 9100 (printer), 62078 (iPhone), 22 (Linux) |
   | Initial IP TTL | 128 (Windows), 64 (Unix-like), 255 (network devices, printers) |

   The initial TTL overrules the other signals: a host answering with TTL 64 is never classed as Windows, and one answering with TTL 128 never as Linux, macOS or mobile. A Linux NAS running Samba answers NetBIOS and SMB like Windows does, but not with Windows' TTL.

4. **Picks a persona**: the most common workstation type (`windows`, `macos` or `linux`). Phones, printers and IoT devices are never imitated. If no workstation could be fingerprinted, the Linux stack is kept and only the MAC address and hostname are changed.
5. **Builds the identity from the hosts of that persona**, so the MAC vendor and hostname tell the same story (no Polycom MAC with a laptop hostname):
   - **MAC address**: most common vendor prefix (OUI) among those hosts plus random bytes, never one already in use. Randomised (locally administered) MACs carry no vendor information and are ignored.
   - **Hostname**: finds the longest string shared by the most hostnames, its usual position and the length of the names, and the type of characters around it, then generates a new name (e.g. `LON-WKS-0012`, `NYC-WKS-0441` -> `QRT-WKS-5820`). If there is no pattern, the persona's default naming is used (`DESKTOP-XXXXXXX`, `MacBook-Pro-N`), or `unknown` for Linux. The name is never one already seen on the network.
   - **DNS domain**: taken from the FQDN other clients send in DHCP (option 81), the domain the DHCP server hands out (option 15), or reverse DNS answers in a capture from chameleonic-probe.sh. The mDNS pseudo-domain `local` is ignored, real domains such as `corp.local` are kept. If none was seen, the domain from the DHCP lease is used.
   - **DHCP fingerprint**: copies the parameter request list, vendor class and FQDN behaviour of the persona's hosts on this network, so it matches whatever Windows/macOS build they run. If none of them requested an address during the capture, a built-in profile is used (Windows 10/11, macOS 13+, Debian dhclient).
   - **TCP/IP stack**:

     | Persona | Changes |
     |---|---|
     | windows | TTL / hop limit 128, TCP timestamps off, TCP window scale 8, random IPv6 interface IDs with temporary addresses |
     | macos | TTL / hop limit 64, TCP timestamps on, TCP window scale 6, random IPv6 interface IDs with temporary addresses |
     | linux | unchanged |

   - **Inbound firewall** (optional, `-f`): makes unsolicited inbound traffic get the persona's answer and hides your own listeners:

     | Persona | Unsolicited TCP, UDP and ping |
     |---|---|
     | windows | silently dropped, like Windows Defender Firewall: no TCP reset, no ICMP port unreachable, no ping reply |
     | macos, linux | every port answers as closed (TCP reset, ICMP port unreachable), ping is answered, like a host with nothing listening |

     Ports you need (Responder, ntlmrelayx, reverse shells) stay reachable with `-a`. Replies to your own traffic, DHCP, IPv6 neighbour discovery and IGMP always get through. The rules live in their own nftables table (`inet chameleonic`), so they only add restrictions and never change an existing ruleset. Services are deliberately not emulated: a fake SMB or RDP service is easily spotted from its handshake, which gives the host away more than a closed port does.

6. **Applies it** and requests an address over DHCP with the persona's fingerprint, then sets `/etc/hosts` to the new FQDN and warns if the new hostname already resolves to another host. The firewall rules are loaded before the interface comes up, so the new identity is never reachable without them.

Everything that is changed is saved first, so `--restore` puts the machine back exactly as it was.

## Usage

```
sudo ./chameleonic.sh [options] <interface> [capture_file]

  capture_file      pcap/pcapng from an earlier capture, passive or made with chameleonic-probe.sh.
                    If it does not exist, chameleonic listens passively and saves the capture there.
                    Default: ./chameleonic-<interface>-<date>.pcapng

Options:
  -t, --time SECONDS     how long to listen passively (default 300)
  -p, --persona NAME     force a persona: windows, macos or linux (default: most common on the network)
  -f, --firewall         make inbound traffic look like the persona's: silently dropped for Windows,
                         answered as closed ports for macOS and Linux. Hides your own listeners.
  -a, --allow LIST       ports to keep reachable through the firewall, e.g. 445,8000-8100,53/udp,ping
                         (implies -f)
  -x, --exclude MACS     ignore these hosts in the capture, e.g. the machine that captured it
                         (aa:bb:cc:dd:ee:ff,...). Captures made by chameleonic and chameleonic-probe.sh
                         record it themselves.
  -n, --dry-run          analyse and show the plan without changing anything
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
```

Then pass the file to a dry run, which needs neither root nor the network: `bash chameleonic.sh -n eth0 /tmp/office.pcapng`. Save the capture under `/tmp` (see [Troubleshooting](#troubleshooting)). The capture comment records the capturing machine's MAC address, so chameleonic ignores that machine's own traffic; for captures without it, use `-x`.

### Restoring

`sudo ./chameleonic.sh -r` restores the original MAC address, hostname, `/etc/hosts`, TCP/IP settings, stopped services, removes the firewall rules, and restores the way the interface got its address (NetworkManager, a DHCP client or static addresses). The saved state lives in `/var/lib/chameleonic`. Running chameleonic again before restoring keeps the original identity saved from the first run.

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

Every reply also gives the host's initial TTL. The probes are sent from the interface's current address and MAC, so run it from a machine whose identity on the network does not matter, or before chameleonic disguises this one. It does not change the machine's identity: the only change is a temporary route that sends multicast queries out of the probed interface, and it is removed when the script exits.

Example: probe from one machine, analyse and apply on another:

```
# On the probing machine
sudo ./chameleonic-probe.sh --tcp eth0 office-active.pcapng

# On the machine to disguise, after copying the file over
bash chameleonic.sh -n eth0 office-active.pcapng     # check the plan
sudo bash chameleonic.sh eth0 office-active.pcapng   # take on the identity
```

The capture records the probing machine's MAC address, so chameleonic ignores the probes themselves.

This is noisy by design. The NetBIOS sweep and the ARP requests it triggers reach every address in the range, and some replies arrive after the sending socket has closed, so the probing machine answers them with ICMP port unreachable, as with any UDP scanner. `--tcp` completes TCP connections, which host firewalls and EDR log. DHCP fingerprints still only come from listening: hosts do not request addresses because they were probed, so the persona's built-in DHCP profile is used unless the capture also caught DHCP requests. Use `-t` to listen longer after probing.

## Requirements

### System

- Kali Linux, or another Debian-based distribution, with systemd
- Bash 4.3 or later
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
| `systemd` | `hostnamectl` | setting the hostname | yes, unless `-n` (preinstalled) |
| `libc-bin` | `getent` | checking whether the new hostname is already in DNS | yes, unless `-n` (preinstalled) |
| `nftables` | `nft` | the inbound firewall | only with `-f` or `-a` |
| `network-manager` | `nmcli` | detaching the interface and handing it back on restore | used if present |
| `systemd-resolved` | `resolvectl` | turning off LLMNR and mDNS on the interface | used if present |

chameleonic-probe.sh only needs `wireshark-common` (`dumpcap`, and `capinfos` for the packet count), `iproute2`, `libc-bin` (`getent`) and `coreutils` (`timeout`). It works on any Linux distribution and any interface with an IPv4 address, Wi-Fi included.

Install everything that is not already on Kali with:

```
sudo apt install tshark macchanger isc-dhcp-client nftables
```

chameleonic checks for each required command before changing anything and prints the package to install if one is missing.

`dhclient` is needed because it is the only common DHCP client that can send a custom parameter request list in a chosen order; NetworkManager's built-in client cannot. It is deprecated upstream but still packaged in Kali. Wireshark 4.2 or later gives the most complete vendor names; older versions fall back to macchanger's list.

## Tips

- The best time to run chameleonic is before the machine has talked to the network. NetworkManager connects as soon as a cable is plugged in, sending the real MAC address and hostname (`kali`) in its DHCP request. To avoid this, run `sudo nmcli device set eth0 managed no` before plugging in. chameleonic does not need the interface to be up or configured.
- Check the plan with `-n` on a saved capture before applying it.

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
- The TCP SYN matches the persona's TTL, window size, window scale and timestamps, but the Linux order of TCP options is kept (Windows sends MSS, NOP, WS, NOP, NOP, SACK; Linux sends MSS, NOP, NOP, SACK, NOP, WS). Matching it would need packet rewriting. Other stack traits, such as IP ID behaviour, are not changed either.
- dhclient sends DHCP options in its own order (53, 12, 81, 55, 60, 61), while the parameter request list, vendor class and FQDN match the persona. Fingerprinting systems mostly rely on the latter.
- The MAC address, TCP/IP settings, firewall rules, NetworkManager detachment and DHCP client do not survive a reboot; the hostname and `/etc/hosts` do. Run `-r` after a reboot to restore the rest.
- The firewall assumes the default behaviour of each persona. Networks whose workstations allow ping or file sharing by policy answer differently; use `-a ping` or `-a 445` to match them.
- ISC dhclient is deprecated upstream but still packaged in Kali.
