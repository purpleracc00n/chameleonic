#!/bin/bash
# chameleonic-probe - actively probe the local network and capture the replies for chameleonic.
# Sends the discovery queries hosts answer (NetBIOS, mDNS, SSDP, WS-Discovery, reverse DNS and
# optionally TCP connections) and records everything with dumpcap. Nothing on this machine is changed:
# the capture is analysed by chameleonic, here or on another machine.

LISTEN_SECONDS=30
PROBE_RATE=100
MAX_HOSTS=4096
PARALLEL=32
TCP_PORTS="22,135,139,445,548,631,3389,5985,9100,62078"
# Replies to the probes, plus the broadcast and multicast traffic chameleonic uses when listening
CAPTURE_FILTER="arp or icmp or broadcast or multicast or udp port 53 or udp port 67 or udp port 68 or udp port 137 or udp port 138 or udp port 1900 or udp port 3702 or udp port 5353 or udp port 5355 or (tcp[tcpflags] & (tcp-syn|tcp-rst) != 0)"
MDNS_GROUP=224.0.0.251
# SSDP and WS-Discovery share this group
DISCOVERY_GROUP=239.255.255.250
# mDNS services that make workstations, Macs, phones and printers describe themselves
MDNS_SERVICES=(_services._dns-sd._udp.local _device-info._tcp.local _workstation._tcp.local _smb._tcp.local
	_companion-link._tcp.local _airplay._tcp.local _ipp._tcp.local _printer._tcp.local _googlecast._tcp.local)
SSDP_SEARCH=$'M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: "ssdp:discover"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n'

################################################# Helpers

show_help() {
	cat << EOF
Usage: sudo chameleonic-probe.sh [options] <interface> [capture_file]

Actively probes the network <interface> is on and captures the replies, so chameleonic can fingerprint
the hosts from them:
  sudo bash chameleonic.sh [-n] <interface> <capture_file>

Probes are sent from the interface's current address and MAC: run this from a machine whose identity
does not matter, or before chameleonic disguises this one. Nothing on this machine is changed.

  capture_file          where to save the capture
                        Default: ./chameleonic-probe-<interface>-<date>.pcapng

Options:
  -r, --range CIDR      addresses to probe (default: the interface's subnet, at most $MAX_HOSTS addresses)
  -t, --time SECONDS    how long to keep listening after probing (default $LISTEN_SECONDS)
      --rate N          probes per second for the address sweep (default $PROBE_RATE)
      --tcp             also connect to TCP ports $TCP_PORTS on every host that answered (loudest)
  -h, --help            show this help
EOF
}

die() {
	echo "[-] $*" >&2
	exit 1
}

warn() {
	echo "[-] $*" >&2
}

require_commands() {
	local entry
	for entry in "$@"; do
		command -v "${entry%%:*}" > /dev/null 2>&1 || die "Missing dependency: ${entry%%:*} (install with: apt install ${entry#*:})"
	done
}

# Describe how a command ended, naming the signal if it crashed
describe_status() {
	local status=$1
	if ((status == 139)); then
		echo "crashed (segmentation fault)"
	elif ((status > 128)); then
		echo "was killed by signal $((status - 128))"
	else
		echo "exited with status $status"
	fi
}

ip_to_int() {
	local IFS=. a b c d
	read -r a b c d <<< "$1"
	echo $(((a << 24) | (b << 16) | (c << 8) | d))
}

int_to_ip() {
	echo "$((($1 >> 24) & 255)).$((($1 >> 16) & 255)).$((($1 >> 8) & 255)).$(($1 & 255))"
}

# Background workers are tracked in "workers", so the capture running in the background is never
# waited for. Waits until fewer than PARALLEL workers are running.
throttle() {
	local pid running=()
	for pid in "${workers[@]}"; do
		kill -0 "$pid" 2> /dev/null && running+=("$pid")
	done
	workers=("${running[@]}")
	while ((${#workers[@]} >= PARALLEL)); do
		sleep 0.1
		throttle
	done
}

wait_for_workers() {
	((${#workers[@]})) && wait "${workers[@]}" 2> /dev/null
	workers=()
}

on_exit() {
	local status=$? route
	[[ -n $capture_pid ]] && kill -TERM "$capture_pid" 2> /dev/null
	for route in "${added_routes[@]}"; do
		ip route del "$route" dev "$interface" 2> /dev/null
	done
	[[ -n $workdir ]] && rm -rf "$workdir"
	exit "$status"
}

################################################# Probes
# Packets are built as printf escapes, so each one is written to its socket in a single datagram.

# DNS names as length-prefixed labels ending with a zero byte
dns_name() {
	local label out="" IFS=.
	for label in $1; do
		out+=$(printf '\\x%02x' "${#label}")$label
	done
	printf '%s\\x00' "$out"
}

# One mDNS query asking for every service in MDNS_SERVICES (PTR records)
mdns_query() {
	local service out
	out=$(printf '\\x00\\x00\\x00\\x00\\x00\\x%02x\\x00\\x00\\x00\\x00\\x00\\x00' "${#MDNS_SERVICES[@]}")
	for service in "${MDNS_SERVICES[@]}"; do
		out+="$(dns_name "$service")\\x00\\x0c\\x00\\x01"
	done
	printf '%s' "$out"
}

# NetBIOS node status request for the wildcard name "*": the host answers with its name table
nbstat_query() {
	printf '\\x%02x\\x%02x' $((RANDOM % 256)) $((RANDOM % 256))
	printf '%s' '\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00\x21\x00\x01'
}

# WS-Discovery probe without a type filter: every device answers with its types
wsd_probe() {
	printf '%s' '<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery"><soap:Header><wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To><wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</wsa:Action><wsa:MessageID>urn:uuid:'
	printf '%s' "$(cat /proc/sys/kernel/random/uuid)"
	printf '%s' '</wsa:MessageID></soap:Header><soap:Body><wsd:Probe/></soap:Body></soap:Envelope>'
}

# Multicast queries follow the routing table; make sure they leave through the probed interface
route_multicast() {
	local group dev
	for group in "$MDNS_GROUP" "$DISCOVERY_GROUP"; do
		dev=$(ip route get "$group" 2> /dev/null | sed -nE 's/.* dev ([^ ]+).*/\1/p')
		if [[ $dev != "$interface" ]] && ip route add "$group/32" dev "$interface" 2> /dev/null; then
			added_routes+=("$group/32")
		fi
	done
}

send_discovery_queries() {
	{
		printf "$(mdns_query)" > "/dev/udp/$MDNS_GROUP/5353"
		printf '%s' "$SSDP_SEARCH" > "/dev/udp/$DISCOVERY_GROUP/1900"
		printf '%s' "$(wsd_probe)" > "/dev/udp/$DISCOVERY_GROUP/3702"
	} 2> /dev/null || warn "Could not send some discovery queries"
}

# A NetBIOS request to every address: Windows and Samba hosts answer with their names, and the ARP
# requests the kernel sends first reveal every live host. Each socket stays open for the next 64
# probes, so most replies reach an open socket instead of triggering ICMP port unreachable.
sweep_netbios() {
	local address ip fd interval n=0 ring=()
	interval=$(awk -v rate="$probe_rate" 'BEGIN { printf "%.4f", 1 / rate }')
	echo "[*] Sending NetBIOS name table requests to $range_size addresses ($probe_rate per second)"
	for ((address = range_first; address <= range_last; address++)); do
		((interrupted)) && break
		ip=$(int_to_ip "$address")
		[[ $ip == "$own_ip" ]] && continue
		if { exec {fd}<> "/dev/udp/$ip/137"; } 2> /dev/null; then
			printf "$(nbstat_query)" >&"$fd" 2> /dev/null
			ring+=("$fd")
			if ((${#ring[@]} > 64)); then
				fd=${ring[0]}
				exec {fd}>&-
				ring=("${ring[@]:1}")
			fi
		fi
		((++n % 256 == 0)) && echo "[*] Probed $n / $range_size addresses"
		sleep "$interval"
	done
	sleep 2
	for fd in "${ring[@]}"; do
		exec {fd}>&-
	done
}

# Hosts that answered ARP during the sweep
find_live_hosts() {
	local ip address
	live_hosts=()
	while read -r ip; do
		address=$(ip_to_int "$ip")
		((address >= range_first && address <= range_last)) && live_hosts+=("$ip")
	done < <(ip -4 neigh show dev "$interface" | awk '/lladdr/ && !/FAILED|INCOMPLETE/ { print $1 }')
	echo "[+] ${#live_hosts[@]} hosts answered"
}

# PTR lookups through the system resolver: the answers give chameleonic hostnames and the DNS domain
reverse_lookups() {
	local ip
	((${#live_hosts[@]})) || return
	echo "[*] Looking up the reverse DNS names of ${#live_hosts[@]} hosts"
	: > "$workdir/names"
	for ip in "${live_hosts[@]}"; do
		((interrupted)) && break
		throttle
		timeout 3 getent hosts "$ip" >> "$workdir/names" 2> /dev/null &
		workers+=($!)
	done
	wait_for_workers
	echo "[+] $(wc -l < "$workdir/names") hosts have a reverse DNS name"
}

# Full TCP connections: open ports and the TTL of the answers identify the operating system
tcp_connects() {
	local ip
	((${#live_hosts[@]})) || return
	echo "[*] Connecting to TCP ports $TCP_PORTS on ${#live_hosts[@]} hosts"
	: > "$workdir/open"
	for ip in "${live_hosts[@]}"; do
		((interrupted)) && break
		throttle
		(
			for port in ${TCP_PORTS//,/ }; do
				timeout 1 bash -c 'exec 3<> "/dev/tcp/$0/$1"' "$ip" "$port" 2> /dev/null && echo "$ip $port"
			done
		) >> "$workdir/open" &
		workers+=($!)
	done
	wait_for_workers
	echo "[+] Found $(wc -l < "$workdir/open") open ports"
}

################################################# Capture

# dumpcap drops root's file permissions, so it writes into the private work directory.
# The capture comment tells chameleonic to ignore this machine.
start_capture() {
	capture_tmp=$workdir/capture.pcapng
	dumpcap -i "$interface" -f "$CAPTURE_FILTER" -q --capture-comment "chameleonic-exclude=$own_mac" \
		-w "$capture_tmp" > "$workdir/dumpcap.log" 2>&1 &
	capture_pid=$!
	local i
	for ((i = 0; i < 50; i++)); do
		[[ -s $capture_tmp ]] && break
		kill -0 "$capture_pid" 2> /dev/null || break
		sleep 0.1
	done
	[[ -s $capture_tmp ]] || die "Could not start capturing: $(grep -v '^$' "$workdir/dumpcap.log" | tail -n1)"
	sleep 1
	echo "[*] Capturing on $interface"
}

listen() {
	local elapsed
	((listen_seconds > 0)) || return
	echo "[*] Listening for late replies and passive traffic for ${listen_seconds}s (Ctrl-C stops early)"
	for ((elapsed = 1; elapsed <= listen_seconds; elapsed++)); do
		((interrupted)) && break
		sleep 1
		((elapsed % 10 == 0)) && echo "[*] Listening... ${elapsed}s / ${listen_seconds}s"
	done
}

stop_capture() {
	local status
	kill -TERM "$capture_pid" 2> /dev/null
	wait "$capture_pid"
	status=$?
	capture_pid=""
	[[ -s $capture_tmp ]] || die "Capture failed: dumpcap $(describe_status "$status") ($(grep -v '^$' "$workdir/dumpcap.log" | tail -n1))"
	mv -f "$capture_tmp" "$capture_file" || die "Could not save the capture to $capture_file"
	[[ -n $SUDO_UID && -n $SUDO_GID ]] && chown "$SUDO_UID:$SUDO_GID" "$capture_file"
	local packets
	packets=$(capinfos -c -M "$capture_file" 2> /dev/null | sed -nE 's/^Number of packets: *//p')
	echo "[+] Saved ${packets:+$packets packets to }$capture_file"
}

################################################# Main logic

parse_args() {
	local positional=()
	listen_seconds=$LISTEN_SECONDS
	probe_rate=$PROBE_RATE
	while (($#)); do
		case $1 in
			-r | --range) range=$2; shift 2 ;;
			-t | --time) listen_seconds=$2; shift 2 ;;
			--rate) probe_rate=$2; shift 2 ;;
			--tcp) tcp=1; shift ;;
			-h | --help) show_help; exit 0 ;;
			-*) show_help; die "Unknown option: $1" ;;
			*) positional+=("$1"); shift ;;
		esac
	done
	interface=${positional[0]}
	capture_file=${positional[1]}
	[[ $listen_seconds =~ ^[0-9]+$ ]] || die "Listening time must be a number of seconds"
	[[ $probe_rate =~ ^[1-9][0-9]*$ ]] || die "Rate must be a number of probes per second"
}

# The probed range: -r, or the interface's subnet without its network and broadcast addresses
choose_range() {
	local cidr=${range:-$interface_cidr} address prefix mask
	address=${cidr%/*}
	prefix=${cidr#*/}
	[[ $cidr == */* && $address =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ && $prefix =~ ^[0-9]+$ ]] && ((prefix >= 8 && prefix <= 32)) ||
		die "Invalid range $cidr: use an address and prefix such as 10.0.0.0/24"
	mask=$(((0xffffffff << (32 - prefix)) & 0xffffffff))
	range_first=$(($(ip_to_int "$address") & mask))
	range_last=$((range_first | (~mask & 0xffffffff)))
	echo "[*] Probing $(int_to_ip "$range_first")/$prefix from $own_ip ($own_mac)"
	if ((prefix <= 30)); then
		range_first=$((range_first + 1))
		range_last=$((range_last - 1))
	fi
	range_size=$((range_last - range_first + 1))
	((range_size <= MAX_HOSTS)) || die "$cidr has $range_size addresses, more than $MAX_HOSTS: probe a smaller range with -r"
}

main() {
	parse_args "$@"
	if [[ -z $interface ]]; then
		show_help
		die "No interface provided."
	fi
	[[ $(id -u) == 0 ]] || die "Run this as root!"
	[[ -e /sys/class/net/$interface ]] || die "This interface does not exist."
	require_commands dumpcap:wireshark-common ip:iproute2 getent:libc-bin timeout:coreutils
	interface_cidr=$(ip -4 -o addr show dev "$interface" | awk '{ print $4; exit }')
	[[ -n $interface_cidr ]] || die "$interface has no IPv4 address: probing needs one to send from and receive replies"
	own_ip=${interface_cidr%/*}
	own_mac=$(cat "/sys/class/net/$interface/address")
	capture_file=${capture_file:-./chameleonic-probe-$interface-$(date +%Y%m%d-%H%M%S).pcapng}
	choose_range

	# Make sure the capture can be saved before anything is sent
	local probe
	probe=$(mktemp -p "$(dirname -- "$capture_file")" .chameleonic.XXXXXX 2> /dev/null) || die "Cannot save the capture in $(dirname -- "$capture_file")"
	rm -f "$probe"

	workdir=$(mktemp -d)
	trap on_exit EXIT
	trap 'interrupted=1; echo; echo "[*] Stopping, saving what was captured..."' INT
	start_capture
	route_multicast

	echo "[*] Sending mDNS, SSDP and WS-Discovery queries"
	send_discovery_queries
	sweep_netbios
	((interrupted)) || find_live_hosts
	((interrupted)) || reverse_lookups
	((tcp && !interrupted)) && tcp_connects
	# Repeat the multicast queries for hosts that missed the first round
	((interrupted)) || send_discovery_queries
	listen
	stop_capture

	echo "[*] Analyse it with chameleonic (here or on another machine):"
	echo "      bash chameleonic.sh -n <interface> $capture_file        # show the plan, change nothing"
	echo "      sudo bash chameleonic.sh <interface> $capture_file      # take on the identity"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
	main "$@"
fi
