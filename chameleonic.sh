#!/bin/bash
# chameleonic - blend into a network by passively fingerprinting nearby hosts and taking on the identity
# of the most common kind of workstation: MAC vendor, hostname pattern, DNS domain, DHCP fingerprint and
# TCP/IP stack behaviour.

LISTEN_SECONDS=300
MAX_HOSTNAME_ATTEMPTS=20
STATE_DIR=/var/lib/chameleonic
STATE_FILE=$STATE_DIR/state
DHCLIENT_CONF=$STATE_DIR/dhclient.conf
DHCLIENT_LEASES=$STATE_DIR/dhclient.leases
DHCLIENT_PID=$STATE_DIR/dhclient.pid
# Broadcast and multicast traffic is what every port of a switched network sees
CAPTURE_FILTER="broadcast or multicast or arp or udp port 67 or udp port 68"
# Services that announce a Linux host: mDNS, printer browsing, NetBIOS, WS-Discovery, LLDP
CHATTY_SERVICES=(avahi-daemon.socket avahi-daemon.service cups-browsed.service nmbd.service wsdd.service wsdd2.service lldpd.service)
# Separator for multi-value tshark fields
AGG=$'\x1f'
# nftables table holding the persona's inbound firewall rules, separate from any existing ruleset
FIREWALL_TABLE="inet chameleonic"
# Works whether the script was started as ./chameleonic.sh or bash chameleonic.sh
RESTORE_COMMAND="sudo bash $0 -r"

# Built-in DHCP fingerprints, used when no host of the persona was seen requesting an address.
# Parameter request lists (option 55) are sent in exactly this order.
declare -A BUILTIN_PRL=(
	[windows]="1,3,6,15,31,33,43,44,46,47,119,121,249,252" # Windows 10/11
	[macos]="1,121,3,6,15,108,114,119,252,95,44,46"        # macOS 13+
	[linux]="1,28,2,3,15,6,119,12,44,47,26,121,42"         # Debian/Ubuntu dhclient
)
declare -A BUILTIN_VENDOR_CLASS=([windows]="MSFT 5.0" [macos]="" [linux]="")
declare -A BUILTIN_SENDS_FQDN=([windows]=1 [macos]=0 [linux]=0)
# Options dhclient-script reads by name, and DHCP protocol options, keep their standard ISC names.
# Any other requested code gets a generic definition.
declare -A DHCP_OPTION_NAMES=(
	[1]=subnet-mask [2]=time-offset [3]=routers [6]=domain-name-servers [12]=host-name [15]=domain-name
	[26]=interface-mtu [28]=broadcast-address [33]=static-routes [42]=ntp-servers [44]=netbios-name-servers
	[46]=netbios-node-type [47]=netbios-scope [119]=domain-search [121]=rfc3442-classless-static-routes
	[50]=dhcp-requested-address [51]=dhcp-lease-time [52]=dhcp-option-overload [53]=dhcp-message-type
	[54]=dhcp-server-identifier [55]=dhcp-parameter-request-list [56]=dhcp-message [57]=dhcp-max-message-size
	[58]=dhcp-renewal-time [59]=dhcp-rebinding-time [60]=vendor-class-identifier [61]=dhcp-client-identifier
	[81]=fqdn [82]=relay-agent-information
)

################################################# Helpers

show_help() {
	cat << EOF
Usage: sudo chameleonic.sh [options] <interface> [capture_file]

  capture_file      pcap/pcapng from an earlier capture, passive or made with chameleonic-probe.sh.
                    If it does not exist, chameleonic listens passively and saves the capture there.
                    Default: ./chameleonic-<interface>-<date>.pcapng

Options:
  -t, --time SECONDS     how long to listen passively (default $LISTEN_SECONDS)
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
EOF
}

die() {
	echo "[-] $*" >&2
	exit 1
}

warn() {
	echo "[-] $*" >&2
}

# Print the entry with the highest count from a "count value" list (output of uniq -c)
top_entry() {
	sort -nr | head -n1 | sed -E 's/^ *[0-9]+ //'
}

require_root() {
	[[ $(id -u) == 0 ]] || die "Run this as root!"
}

require_commands() {
	local entry
	for entry in "$@"; do
		command -v "${entry%%:*}" > /dev/null 2>&1 || die "Missing dependency: ${entry%%:*} (install with: apt install ${entry#*:})"
	done
}

has_systemd() {
	[[ -d /run/systemd/system ]] && command -v systemctl > /dev/null 2>&1
}

current_mac() {
	cat "/sys/class/net/$interface/address" 2> /dev/null
}

on_exit() {
	local status=$?
	if ((changing)); then
		warn "Stopped before the new identity was fully applied; $interface may have no address"
		ip link set dev "$interface" up 2> /dev/null
		warn "Run '$RESTORE_COMMAND' to restore the original identity"
	fi
	[[ -n $workdir ]] && rm -rf "$workdir"
	exit "$status"
}

################################################# Saved state
# The state file holds one "key=value" per line. Original values are recorded once, before the first
# change, so running chameleonic again never overwrites what --restore goes back to.

state_get() {
	[[ -f $STATE_FILE ]] || return
	awk -v key="$1" 'index($0, key "=") == 1 { print substr($0, length(key) + 2); exit }' "$STATE_FILE"
}

state_get_all() {
	[[ -f $STATE_FILE ]] || return
	awk -v key="$1" 'index($0, key "=") == 1 { print substr($0, length(key) + 2) }' "$STATE_FILE"
}

state_add() {
	printf '%s=%s\n' "$1" "$2" >> "$STATE_FILE"
}

# Record a value only if nothing was recorded for that key yet
state_record() {
	grep -q "^$1=" "$STATE_FILE" 2> /dev/null || state_add "$1" "$2"
}

set_sysctl() {
	local key=$1 value=$2
	state_record "sysctl:$key" "$(sysctl -n "$key" 2> /dev/null | tr '\t' ' ')"
	sysctl -qw "$key=$value" > /dev/null 2>&1 || warn "Could not set $key=$value"
}

# How the interface got its address before chameleonic took over: nm, dhclient, static or none
detect_network_mode() {
	if command -v nmcli > /dev/null 2>&1 && [[ $(nmcli -t -f RUNNING general 2> /dev/null) == running ]]; then
		local nm_state
		nm_state=$(nmcli -t -f DEVICE,STATE device status 2> /dev/null | awk -F: -v dev="$interface" '$1 == dev { print $2 }')
		if [[ -n $nm_state && $nm_state != unmanaged ]]; then
			echo nm
			return
		fi
	fi
	if [[ -n $(dhcp_client_pids) ]]; then
		echo dhclient
	elif [[ -n $(ip -4 -o addr show dev "$interface" 2> /dev/null) ]]; then
		echo static
	else
		echo none
	fi
}

init_state() {
	local saved_interface
	saved_interface=$(state_get interface)
	if [[ -n $saved_interface && $saved_interface != "$interface" ]]; then
		die "An identity is already applied to $saved_interface. Run '$RESTORE_COMMAND' first."
	fi
	if [[ -z $saved_interface ]]; then
		mkdir -p -m 700 "$STATE_DIR"
		: > "$STATE_FILE"
		state_add interface "$interface"
		state_add mac "$(current_mac)"
		state_add hostname "$(hostname)"
		local mode
		mode=$(detect_network_mode)
		state_add network "$mode"
		if [[ $mode == static ]]; then
			ip -4 -o addr show dev "$interface" | awk '{ print $4 }' | while read -r cidr; do state_add address "$cidr"; done
			state_add gateway "$(ip -4 route show default dev "$interface" | awk '{ print $3; exit }')"
		fi
		cp /etc/hosts "$STATE_DIR/hosts.bak"
		echo "[*] Saved original identity (MAC $(current_mac), hostname $(hostname)) to $STATE_DIR"
	else
		echo "[*] Re-running on $interface: keeping the original identity saved in $STATE_DIR"
	fi
}

################################################# Taking over the interface

dhcp_client_pids() {
	local pid args
	pgrep -a -x 'dhclient|dhcpcd' 2> /dev/null | while read -r pid args; do
		[[ " $args " == *" $interface "* ]] && echo "$pid"
	done
}

# Stop services that announce this host, before the interface comes up under a new identity
silence_chatter() {
	local service
	if has_systemd; then
		for service in "${CHATTY_SERVICES[@]}"; do
			if systemctl is-active --quiet "$service"; then
				systemctl stop "$service" && state_add service "$service"
				echo "[*] Stopped $service (it announces this host on the network)"
			fi
		done
		if systemctl is-active --quiet systemd-resolved && command -v resolvectl > /dev/null 2>&1; then
			resolvectl llmnr "$interface" no 2> /dev/null
			resolvectl mdns "$interface" no 2> /dev/null
			state_record resolved yes
			echo "[*] Disabled LLMNR and mDNS in systemd-resolved on $interface"
		fi
	fi
}

# Detach the interface from NetworkManager and DHCP clients so nothing is sent until the new identity
# is in place, and nothing resets the MAC address afterwards
take_over_interface() {
	((took_over)) && return
	init_state
	changing=1
	silence_chatter
	if [[ $(state_get network) == nm && $(nmcli -t -f DEVICE,STATE device status 2> /dev/null | awk -F: -v dev="$interface" '$1 == dev { print $2 }') != unmanaged ]]; then
		nmcli device set "$interface" managed no
		echo "[*] NetworkManager no longer manages $interface (so it cannot reset the MAC address or send DHCP requests)"
	fi
	local pids
	pids=$(dhcp_client_pids)
	if [[ -n $pids ]]; then
		kill $pids 2> /dev/null
		echo "[*] Stopped DHCP client on $interface"
	fi
	ip link set dev "$interface" down
	ip -4 addr flush dev "$interface"
	set_sysctl "net.ipv6.conf.$interface.disable_ipv6" 1
	echo "[*] $interface is silent: no IPv4 address, IPv6 disabled"
	took_over=1
}

################################################# Passive reconnaissance

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

# A broken Wireshark install (usually a partial Kali upgrade or a stale plugin) makes tshark crash
# on start-up. Find out before the interface is touched, by reading an empty capture.
check_tshark() {
	local empty=$workdir/empty.pcap status
	printf '\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x00\x00\x01\x00\x00\x00' > "$empty"
	tshark -n -r "$empty" > /dev/null 2>&1
	status=$?
	((status == 0)) && return
	die "tshark $(describe_status "$status") on this system, so nothing was changed. This is usually a partial Kali upgrade or a stale Wireshark plugin: run 'sudo apt update && sudo apt full-upgrade' and check that 'sudo tshark -v' works."
}

# Make sure the capture can be saved before the interface is touched
check_capture_path() {
	local dir probe
	dir=$(dirname -- "$capture_file")
	probe=$(mktemp -p "$dir" .chameleonic.XXXXXX 2> /dev/null) || die "Cannot save the capture in $dir: choose another capture_file path"
	rm -f "$probe"
}

# dumpcap is Wireshark's capture engine: it loads no dissectors or plugins. Running as root, it drops
# every capability except capturing, so it cannot write to directories owned by other users (such as
# your home directory). It writes into the private work directory and the file is moved afterwards.
listen_passively() {
	local capture_tmp=$workdir/capture.pcapng
	echo "[*] Listening passively on $interface for ${listen_seconds}s (Ctrl-C stops early and continues with what was captured)"
	echo "[*] Saving capture to $capture_file"
	# The comment lets a later analysis on another machine ignore this one
	dumpcap -i "$interface" -f "$CAPTURE_FILTER" -a "duration:$listen_seconds" -q \
		--capture-comment "chameleonic-exclude=$(current_mac)" -w "$capture_tmp" > "$workdir/dumpcap.log" 2>&1 &
	local capture_pid=$! elapsed=0 status
	trap 'kill -TERM "$capture_pid" 2> /dev/null' INT
	while kill -0 "$capture_pid" 2> /dev/null; do
		sleep 1
		((++elapsed % 30 == 0)) && echo "[*] Listening... ${elapsed}s / ${listen_seconds}s"
	done
	wait "$capture_pid"
	status=$?
	trap 'exit 130' INT
	if [[ ! -s $capture_tmp ]]; then
		local reason
		reason=$(grep -v '^$' "$workdir/dumpcap.log" | tail -n1)
		die "Capture failed: dumpcap $(describe_status "$status")${reason:+ ($reason)}"
	fi
	mv -f "$capture_tmp" "$capture_file" || die "Could not save the capture to $capture_file"
	# Hand the file to the user who ran sudo, so it can be opened without root
	[[ -n $SUDO_UID && -n $SUDO_GID ]] && chown "$SUDO_UID:$SUDO_GID" "$capture_file"
	echo "[+] Captured $(tshark -r "$capture_file" -T fields -e frame.number 2> /dev/null | wc -l) packets"
}

################################################# Capture parsing
# Every source is turned into "mac<TAB>key<TAB>value" events, then aggregated per host.

tshark_fields() {
	local filter=$1
	shift
	tshark -n -r "$capture_file" -Y "$filter" -T fields -E separator=/t -E occurrence=a -E "aggregator=$AGG" "$@" 2> /dev/null
}

pcap_events() {
	# Addresses
	tshark_fields "arp" -e arp.src.hw_mac -e arp.src.proto_ipv4 |
		awk -F'\t' '{ print $1 "\tip\t" $2 }'
	# Addresses and initial TTL. mDNS and LLMNR use fixed TTLs and dhclient sends DHCP with TTL 128,
	# so those packets are not used for the TTL.
	tshark_fields "ip && ip.src != 0.0.0.0" -e eth.src -e ip.src -e ip.ttl -e udp.srcport -e udp.dstport |
		awk -F'\t' -v agg="$AGG" '{
			split($2, src, agg); split($3, ttl, agg); split($4, sport, agg); split($5, dport, agg)
			print $1 "\tip\t" src[1]
			if (sport[1] !~ /^(67|68|5353|5355)$/ && dport[1] !~ /^(67|68|5353|5355)$/) print $1 "\tttl\t" ttl[1]
		}'
	# DHCP requests: hostname, FQDN, vendor class and parameter request list
	tshark_fields "!icmp && (dhcp.option.dhcp == 1 || dhcp.option.dhcp == 3 || dhcp.option.dhcp == 8)" \
		-e dhcp.hw.mac_addr -e dhcp.option.hostname -e dhcp.option.vendor_class_id -e dhcp.option.request_list_item \
		-e dhcp.fqdn.name -e dhcp.option.requested_ip_address |
		awk -F'\t' -v agg="$AGG" '{
			gsub(agg, ",", $4)
			if ($2 != "") print $1 "\tdhcp_host\t" $2
			if ($3 != "") print $1 "\tdhcp_vc\t" $3
			if ($4 != "") print $1 "\tdhcp_prl\t" $4
			if ($5 != "") print $1 "\tdhcp_fqdn\t" $5
			if ($6 != "") print $1 "\tip\t" $6
		}'
	# DHCP offers and acks: the domain name handed out by the server
	tshark_fields "!icmp && (dhcp.option.dhcp == 2 || dhcp.option.dhcp == 5)" -e eth.src -e dhcp.option.domain_name |
		awk -F'\t' '$2 != "" { print $1 "\tdomain_server\t" $2 }'
	# NetBIOS name service: queries, registrations and refreshes
	tshark_fields "nbns && !icmp && nbns.flags.response == 0" -e eth.src -e nbns.flags.opcode -e nbns.name -e nbns.nb_flags.group |
		awk -F'\t' -v agg="$AGG" '{ split($3, name, agg); split($4, group, agg); print $1 "\tnbns\t" $2 "|" name[1] "|" group[1] }'
	# Browser announcements carry the host name and Windows version
	tshark_fields "browser.server && !icmp" -e eth.src -e browser.server -e browser.os_major -e browser.os_minor |
		awk -F'\t' '{ print $1 "\tbrowser\t" $2 "|" $3 "." $4 }'
	tshark_fields "llmnr && !icmp && dns.flags.response == 0" -e eth.src |
		awk -F'\t' '{ print $1 "\tllmnr\t1" }'
	# mDNS answers: host names, advertised services and device models
	tshark_fields "mdns && !icmp && dns.flags.response == 1" -e eth.src -e dns.resp.name -e dns.resp.type -e dns.txt |
		awk -F'\t' -v agg="$AGG" '{
			n = split($2, names, agg); split($3, types, agg); t = split($4, txt, agg)
			for (i = 1; i <= n; i++) {
				if ((types[i] == 1 || types[i] == 28) && names[i] ~ /\.local\.?$/ && names[i] !~ /^_/) print $1 "\tmdns_name\t" names[i]
				if (match(names[i], /_[A-Za-z0-9-]+\._(tcp|udp)\.local\.?$/)) {
					service = substr(names[i], RSTART, RLENGTH)
					sub(/\.local\.?$/, "", service)
					print $1 "\tmdns_service\t" service
				}
			}
			for (i = 1; i <= t; i++) if (txt[i] ~ /^model=/) print $1 "\tmdns_model\t" substr(txt[i], 7)
		}'
	# SSDP announcements name the operating system in the SERVER header
	tshark_fields "ssdp && !icmp && (http.server || http.user_agent)" -e eth.src -e http.server -e http.user_agent |
		awk -F'\t' '{ print $1 "\tssdp\t" $2 " " $3 }'

	# The rest mostly comes from replies to chameleonic-probe.sh
	# NetBIOS name tables: the first unique name is the computer name
	tshark_fields "nbns && !icmp && nbns.flags.response == 1 && nbns.type == 33" -e eth.src -e nbns.netbios_name -e nbns.name_flags.group |
		awk -F'\t' -v agg="$AGG" '{
			n = split($2, names, agg); split($3, group, agg); name = ""
			for (i = 1; i <= n; i++) if (group[i] !~ /^(1|True|true)$/) { name = names[i]; break }
			print $1 "\tnbstat\t" name
		}'
	# WS-Discovery replies and announcements list the device types: ":Computer" for Windows PCs,
	# print and scan device types for printers. The payload is searched as hex.
	tshark_fields "udp.srcport == 3702 && !icmp" -e eth.src -e udp.payload |
		awk -F'\t' '{
			payload = tolower($2)
			if (index(payload, "3a436f6d7075746572")) print $1 "\twsd\tcomputer"
			else if (index(payload, "5072696e7444657669636554797065") || index(payload, "5363616e44657669636554797065")) print $1 "\twsd\tprinter"
		}'
	# Open TCP ports
	tshark_fields "tcp.flags.syn == 1 && tcp.flags.ack == 1 && !icmp" -e eth.src -e tcp.srcport |
		awk -F'\t' '{ print $1 "\ttcp_open\t" $2 }'
	# Reverse DNS answers name an address, not a MAC: they are matched to hosts by address later
	tshark_fields "dns && !mdns && !icmp && dns.flags.response == 1 && dns.ptr.domain_name" -e dns.qry.name -e dns.ptr.domain_name |
		awk -F'\t' -v agg="$AGG" '{
			split($1, query, agg); split($2, ptr, agg)
			if (query[1] ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\.in-addr\.arpa$/) {
				split(query[1], octet, ".")
				print "-\tptr\t" octet[4] "." octet[3] "." octet[2] "." octet[1] "|" ptr[1]
			}
		}'
}

# MACs of the machine that made the capture, recorded by chameleonic-probe.sh and chameleonic itself
# in the capture comment ("chameleonic-exclude=MAC,MAC")
capture_excludes() {
	command -v capinfos > /dev/null 2>&1 || return
	capinfos -k "$capture_file" 2> /dev/null | sed -nE 's/.*chameleonic-exclude=([0-9A-Fa-f:,]+).*/\1/p' | tr ',' ' '
}

# Aggregate events into one line per host (mac, ip, name, class, evidence, dhcp_prl, dhcp_vendor_class,
# sends_fqdn) and count the DNS domains seen. Each piece of evidence scores a class once per host;
# a host needs a score of 2 or more to be classified.
aggregate_events() {
	awk -F'\t' -v OFS='\t' -v own="$own_macs" -v win_prl="${BUILTIN_PRL[windows]}" -v agg="$AGG" \
		-v hosts_file="$workdir/hosts" -v domains_file="$workdir/domains" '
		function note(mac, tag, class, weight) {
			if ((mac, tag) in noted) return
			noted[mac, tag] = 1
			score[mac, class] += weight
			evidence[mac] = evidence[mac] (evidence[mac] == "" ? "" : ", ") tag
		}
		function name_candidate(mac, priority, name) {
			sub(/\.+$/, "", name)
			if (name !~ /^[A-Za-z0-9-]+$/ || length(name) > 63) return
			if (!(mac in name_priority) || priority < name_priority[mac]) {
				name_priority[mac] = priority
				host_name[mac] = name
			}
		}
		# "local" on its own is the mDNS pseudo-domain; real domains such as corp.local are kept
		function domain_candidate(mac, domain) {
			domain = tolower(domain)
			sub(/\.+$/, "", domain)
			if (domain == "local" || length(domain) > 253) return
			if (domain !~ /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$/) return
			if ((mac, domain) in domain_seen) return
			domain_seen[mac, domain] = 1
			domain_count[domain]++
		}
		function fqdn(mac, priority, value,   dot) {
			dot = index(value, ".")
			if (dot) {
				name_candidate(mac, priority, substr(value, 1, dot - 1))
				domain_candidate(mac, substr(value, dot + 1))
			} else {
				name_candidate(mac, priority, value)
			}
		}
		function initial_ttl(ttl) {
			return ttl <= 32 ? 32 : ttl <= 64 ? 64 : ttl <= 128 ? 128 : 255
		}
		BEGIN {
			split(own, own_list, " ")
			for (i in own_list) own_mac[tolower(own_list[i])] = 1
			n_classes = split("windows macos linux mobile printer other", classes, " ")
		}
		{
			# Fields tshark reports more than once (the client MAC is also in the DHCP client identifier)
			# keep their first value
			split($1, first_mac, agg); split($3, first_value, agg)
			mac = tolower(first_mac[1]); key = $2; value = (key == "dhcp_prl" ? $3 : first_value[1])
			if (key == "ptr") {
				split(value, ptr, "|")
				ptr_name[ptr[1]] = ptr[2]
				next
			}
			if (mac !~ /^([0-9a-f][0-9a-f]:){5}[0-9a-f][0-9a-f]$/ || mac == "00:00:00:00:00:00" || mac == "ff:ff:ff:ff:ff:ff" || (mac in own_mac)) next
			hosts[mac] = 1
			if (key == "ip") {
				if (value ~ /^[0-9.]+$/ && value != "0.0.0.0" && !(mac in ip)) ip[mac] = value
			} else if (key == "ttl") {
				if (value + 0 >= 32) ttl_count[mac, initial_ttl(value + 0)]++
			} else if (key == "dhcp_host") {
				name_candidate(mac, 1, value)
			} else if (key == "dhcp_fqdn") {
				sends_fqdn[mac] = 1
				fqdn(mac, 2, value)
			} else if (key == "domain_server") {
				domain_candidate(mac, value)
			} else if (key == "dhcp_vc") {
				vendor_class[mac] = value
				if (value ~ /^MSFT/) note(mac, "dhcp:" value, "windows", 3)
				else if (value ~ /^android-dhcp/) note(mac, "dhcp:android", "mobile", 3)
				else if (value ~ /^dhcpcd/) note(mac, "dhcp:dhcpcd", "linux", 2)
				else if (value ~ /^udhcp/) note(mac, "dhcp:udhcp", "other", 2)
			} else if (key == "dhcp_prl") {
				prl[mac] = value
				if (value == win_prl) note(mac, "dhcp:windows-options", "windows", 3)
				else if (value ~ /^1,121,3,6,15,/) note(mac, "dhcp:apple-options", "macos", 3)
			} else if (key == "nbns") {
				split(value, nbns, "|")
				note(mac, "netbios", "windows", 1)
				if ((nbns[1] == 5 || nbns[1] == 8) && nbns[2] ~ /<00>$/ && nbns[3] !~ /^(1|True|true)$/) {
					note(mac, "netbios-register", "windows", 2)
					name = nbns[2]
					sub(/ *<00>$/, "", name)
					name_candidate(mac, 3, name)
				}
			} else if (key == "nbstat") {
				note(mac, "netbios-status", "windows", 2)
				name = value
				sub(/ *<00>$/, "", name)
				name_candidate(mac, 3, name)
			} else if (key == "wsd") {
				if (value == "computer") note(mac, "wsd:computer", "windows", 3)
				else if (value == "printer") note(mac, "wsd:printer", "printer", 4)
			} else if (key == "tcp_open") {
				# Samba also offers 139 and 445, so they weigh less than Windows-only services
				if (value ~ /^(135|3389|5985)$/) note(mac, "tcp:" value, "windows", 2)
				else if (value ~ /^(139|445)$/) note(mac, "tcp:" value, "windows", 1)
				else if (value == 22) note(mac, "tcp:22", "linux", 1)
				else if (value == 548) note(mac, "tcp:548", "macos", 2)
				else if (value ~ /^(515|631|9100)$/) note(mac, "tcp:" value, "printer", 3)
				else if (value == 62078) note(mac, "tcp:62078", "mobile", 4)
			} else if (key == "browser") {
				split(value, browser, "|")
				note(mac, "browser:" browser[2], "windows", 2)
				name_candidate(mac, 4, browser[1])
			} else if (key == "llmnr") {
				note(mac, "llmnr", "windows", 1)
			} else if (key == "mdns_name") {
				name = value
				sub(/\.local\.?$/, "", name)
				name_candidate(mac, 5, name)
				if (name ~ /iPhone|iPad|iPod|Apple-Watch/) note(mac, "mdns:" name, "mobile", 4)
				else if (name ~ /[Aa]ndroid|Galaxy|Pixel/) note(mac, "mdns:" name, "mobile", 3)
				else if (name ~ /MacBook|iMac|Mac-mini|Mac-Pro|Mac-Studio|-MBP|-MBA/) note(mac, "mdns:" name, "macos", 2)
			} else if (key == "mdns_service") {
				if (value ~ /^_(ipp|ipps|printer|pdl-datastream|scanner|uscan|uscans)\._tcp$/) note(mac, "mdns:printer", "printer", 4)
				else if (value == "_workstation._tcp") note(mac, "mdns:workstation", "linux", 2)
				else if (value ~ /^_(googlecast|hap|amzn-wplay|spotify-connect|sonos)\._tcp$/) note(mac, "mdns:" value, "other", 3)
				else if (value ~ /^_(companion-link|airplay|raop)\._tcp$/) note(mac, "mdns:apple", "macos", 1)
			} else if (key == "mdns_model") {
				if (value ~ /^(MacBook|iMac|Macmini|MacPro|MacStudio|Mac[0-9])/) note(mac, "model:" value, "macos", 4)
				else if (value ~ /^(iPhone|iPad|iPod|Watch)/) note(mac, "model:" value, "mobile", 4)
				else if (value ~ /^(AppleTV|AudioAccessory)/) note(mac, "model:" value, "other", 3)
			} else if (key == "ssdp") {
				if (value ~ /Windows/) note(mac, "ssdp:windows", "windows", 2)
				else if (value ~ /Darwin|Mac OS/) note(mac, "ssdp:macos", "macos", 2)
				else if (value ~ /Linux/) note(mac, "ssdp:linux", "linux", 1)
			}
		}
		END {
			for (mac in hosts) {
				if ((mac in ip) && (ip[mac] in ptr_name)) fqdn(mac, 6, ptr_name[ip[mac]])
				best_ttl = ""; best_ttl_count = 0
				split("32 64 128 255", ttls, " ")
				for (i = 1; i <= 4; i++) if (ttl_count[mac, ttls[i]] > best_ttl_count) { best_ttl = ttls[i]; best_ttl_count = ttl_count[mac, ttls[i]] }
				# The initial TTL overrules protocol hints: Windows uses 128, Unix-like systems 64
				# (a Linux NAS running Samba answers NetBIOS and SMB like Windows does)
				if (best_ttl == 128) {
					note(mac, "ttl:128", "windows", 2)
					score[mac, "linux"] = score[mac, "macos"] = score[mac, "mobile"] = 0
				} else if (best_ttl == 64 || best_ttl == 255) {
					note(mac, "ttl:" best_ttl, (best_ttl == 64 ? "linux" : "other"), 1)
					score[mac, "windows"] = 0
				}
				class = "unknown"; best_score = 1
				for (c = 1; c <= n_classes; c++) if (score[mac, classes[c]] > best_score) { class = classes[c]; best_score = score[mac, classes[c]] }
				print mac, ip[mac], host_name[mac], class, evidence[mac], prl[mac], vendor_class[mac], sends_fqdn[mac] + 0 > hosts_file
			}
			for (domain in domain_count) print domain_count[domain], domain > domains_file
		}' "$workdir/events"
	touch "$workdir/hosts" "$workdir/domains"
}

analyse_capture() {
	local magic
	magic=$(od -An -tx1 -N4 "$capture_file" | tr -d ' \n')
	case $magic in
		0a0d0d0a | d4c3b2a1 | a1b2c3d4 | 4d3cb2a1 | a1b23c4d) ;;
		*) die "$capture_file is not a packet capture (pcap or pcapng)" ;;
	esac
	local excluded
	excluded=$(capture_excludes)
	if [[ -n $excluded ]]; then
		echo "[*] Ignoring the machine that made the capture: $excluded"
		own_macs+=" $excluded"
	fi
	echo "[*] Fingerprinting hosts in capture $capture_file..."
	pcap_events > "$workdir/events"
	aggregate_events
}

print_hosts() {
	local count
	count=$(wc -l < "$workdir/hosts")
	echo "[+] Found $count hosts:"
	sort -t$'\t' -k4,4 -k3,3 "$workdir/hosts" | head -n 50 |
		awk -F'\t' '{ printf "    %-15s  %-17s  %-20s  %-8s  %s\n", ($2 == "" ? "-" : $2), $1, ($3 == "" ? "-" : $3), $4, $5 }'
	((count > 50)) && echo "    ... and $((count - 50)) more"
}

################################################# Persona

# Picks the persona: the most common workstation OS on the network, unless forced with -p
choose_persona() {
	local breakdown
	breakdown=$(awk -F'\t' '{ count[$4]++ } END { for (c in count) printf "%d %s\n", count[c], c }' "$workdir/hosts" | sort -nr | awk '{ printf "%s%d %s", (NR > 1 ? ", " : ""), $1, $2 }')
	echo "[*] Fingerprints: ${breakdown:-none}"
	persona_count=0
	persona_generic=0
	if [[ -n $forced_persona ]]; then
		persona=$forced_persona
		persona_count=$(awk -F'\t' -v p="$persona" '$4 == p' "$workdir/hosts" | wc -l)
		echo "[*] Persona forced with -p: $persona ($persona_count matching hosts seen)"
		return
	fi
	local best
	best=$(awk -F'\t' '$4 == "windows" || $4 == "macos" || $4 == "linux" { print $4 }' "$workdir/hosts" | sort | uniq -c | sort -nr | head -n1)
	if [[ -z $best ]]; then
		persona=linux
		persona_generic=1
		echo "[-] No workstation could be fingerprinted: keeping the Linux network stack (force a persona with -p)"
		return
	fi
	persona=${best##* }
	persona_count=${best% *}
	persona_count=${persona_count// /}
	echo "[+] Persona: $persona (most common workstation type, $persona_count hosts)"
}

# Hosts the identity is modelled on: those of the persona, or every host if none matched
persona_filter() {
	if ((persona_generic || persona_count == 0)); then
		cat "$workdir/hosts"
	else
		awk -F'\t' -v p="$persona" '$4 == p' "$workdir/hosts"
	fi
}

choose_domain() {
	domain=$(sort -nr "$workdir/domains" | head -n1 | awk '{ print $2 }')
	if [[ -n $domain ]]; then
		echo "[+] DNS domain: $domain (seen from $(sort -nr "$workdir/domains" | head -n1 | awk '{ print $1 }') hosts)"
	else
		echo "[*] No DNS domain seen yet; will use the one handed out by DHCP, if any"
	fi
}

# Copy the most common DHCP fingerprint of the persona's hosts, or fall back to the built-in one
choose_dhcp_fingerprint() {
	local learned=""
	if ((!persona_generic && persona_count > 0)); then
		learned=$(persona_filter | awk -F'\t' '$6 != "" { print $6 "\x1f" $7 "\x1f" $8 }' | sort | uniq -c | top_entry)
	fi
	if [[ -n $learned ]]; then
		IFS=$'\x1f' read -r dhcp_prl dhcp_vendor_class dhcp_sends_fqdn <<< "$learned"
		dhcp_source="copied from $persona hosts on this network"
	else
		dhcp_prl=${BUILTIN_PRL[$persona]}
		dhcp_vendor_class=${BUILTIN_VENDOR_CLASS[$persona]}
		dhcp_sends_fqdn=${BUILTIN_SENDS_FQDN[$persona]}
		dhcp_source="built-in $persona profile"
	fi
	# Keep only valid option codes and printable vendor classes, since both come from the network
	dhcp_prl=$(tr ',' '\n' <<< "$dhcp_prl" | grep -E '^[0-9]+$' | awk '$1 >= 1 && $1 <= 254 && !seen[$1]++' | paste -sd, -)
	dhcp_vendor_class=$(tr -cd '[:alnum:] .:_/-' <<< "$dhcp_vendor_class")
}

# TCP/IP settings that make the stack answer like the persona (TTL, TCP options, IPv6 addressing)
persona_sysctls() {
	local rmem
	rmem=$(sysctl -n net.ipv4.tcp_rmem 2> /dev/null | awk '{ print $1, $2 }')
	case $persona in
		windows)
			# TTL 128, no TCP timestamps, window scale 8, random IPv6 interface IDs with temporary addresses
			echo "net.ipv4.ip_default_ttl=128"
			echo "net.ipv6.conf.$interface.hop_limit=128"
			echo "net.ipv4.tcp_timestamps=0"
			echo "net.ipv4.tcp_rmem=$rmem 12582912"
			echo "net.ipv6.conf.$interface.addr_gen_mode=3"
			echo "net.ipv6.conf.$interface.use_tempaddr=2"
			;;
		macos)
			# TTL 64, TCP timestamps, window scale 6, random IPv6 interface IDs with temporary addresses
			echo "net.ipv4.ip_default_ttl=64"
			echo "net.ipv6.conf.$interface.hop_limit=64"
			echo "net.ipv4.tcp_timestamps=1"
			echo "net.ipv4.tcp_rmem=$rmem 3145728"
			echo "net.ipv6.conf.$interface.addr_gen_mode=3"
			echo "net.ipv6.conf.$interface.use_tempaddr=2"
			;;
	esac
}

describe_stack() {
	case $persona in
		windows) echo "TTL 128, TCP timestamps off, TCP window scale 8, random IPv6 addresses" ;;
		macos) echo "TTL 64, TCP timestamps on, TCP window scale 6, random IPv6 addresses" ;;
		*) echo "unchanged (Linux)" ;;
	esac
}

################################################# Hostname

# Find the substring (3+ chars) shared by the most hostnames, preferring the longest on ties
find_largest_common() {
	local -n arr=$1
	local -A occurrences seen
	local str substr i j count largest_common="" max_count=0

	for str in "${arr[@]}"; do
		# Count each substring once per hostname
		seen=()
		for ((i = 0; i < ${#str}; i++)); do
			for ((j = i + 3; j <= ${#str}; j++)); do
				seen[${str:i:j-i}]=1
			done
		done
		for substr in "${!seen[@]}"; do
			occurrences[$substr]=$((${occurrences[$substr]:-0} + 1))
		done
	done

	for substr in "${!occurrences[@]}"; do
		count=${occurrences[$substr]}
		if ((count >= 3 && (count > max_count || (count == max_count && ${#substr} > ${#largest_common})))); then
			max_count=$count
			largest_common=$substr
		fi
	done

	echo "$largest_common"
}

# Classify the characters used in a string
classify_chars() {
	local str="$1"
	if [[ "$str" =~ ^[0-9]+$ ]]; then
		echo "Digits only"
	elif [[ "$str" =~ ^[A-Z]+$ ]]; then
		echo "Uppercase letters only"
	elif [[ "$str" =~ ^[a-z]+$ ]]; then
		echo "Lowercase letters only"
	elif [[ "$str" =~ ^[A-Za-z]+$ ]]; then
		echo "Alphanumeric (letters only, both cases)"
	elif [[ "$str" =~ ^[0-9A-Z]+$ ]]; then
		echo "Alphanumeric (digits + uppercase)"
	elif [[ "$str" =~ ^[0-9a-z]+$ ]]; then
		echo "Alphanumeric (digits + lowercase)"
	elif [[ "$str" =~ ^[0-9A-Za-z]+$ ]]; then
		echo "Alphanumeric (digits + both cases)"
	else
		echo "Mixed characters"
	fi
}

# Most common character type among the given strings (empty strings are skipped)
most_common_char_type() {
	local part
	for part in "$@"; do
		[[ -n $part ]] && classify_chars "$part"
	done | sort | uniq -c | top_entry
}

# Generate random characters of a given type
generate_random_chars() {
	local length="$1" type="$2" chars
	case "$type" in
		"Digits only") chars="0123456789" ;;
		"Uppercase letters only") chars="ABCDEFGHIJKLMNOPQRSTUVWXYZ" ;;
		"Lowercase letters only") chars="abcdefghijklmnopqrstuvwxyz" ;;
		"Alphanumeric (letters only, both cases)") chars="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz" ;;
		"Alphanumeric (digits + uppercase)") chars="ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" ;;
		"Alphanumeric (digits + lowercase)") chars="abcdefghijklmnopqrstuvwxyz0123456789" ;;
		"Alphanumeric (digits + both cases)") chars="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" ;;
		*) chars="ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz" ;; # Fallback for mixed characters
	esac
	((length > 0)) && LC_ALL=C tr -dc "$chars" < /dev/urandom | head -c "$length"
}

# Default names of a freshly installed machine, used when the network shows no naming pattern
fallback_pattern() {
	pattern_before_len=0
	pattern_after_len=0
	case $persona in
		windows)
			pattern_common="DESKTOP-"
			pattern_after_len=7
			pattern_after_type="Alphanumeric (digits + uppercase)"
			echo "[*] Using the Windows default naming scheme (DESKTOP-XXXXXXX)"
			;;
		macos)
			pattern_common="MacBook-Pro-"
			pattern_after_len=1
			pattern_after_type="Digits only"
			echo "[*] Using the macOS default naming scheme (MacBook-Pro-N)"
			;;
		*)
			pattern_common=""
			;;
	esac
}

# Work out the hostname pattern once. Sets pattern_common, pattern_before_len/type and
# pattern_after_len/type, or leaves pattern_common empty if no pattern was found.
analyse_hostnames() {
	pattern_common=""
	if ((${#names_array[@]} < 3)); then
		echo "[-] Not enough hostnames identified to find a naming pattern"
		fallback_pattern
		return
	fi
	echo "[*] Analysing ${#names_array[@]} hostnames..."

	local common
	common=$(find_largest_common names_array)
	if [[ -z $common ]]; then
		echo "[-] Could not find a reliable hostname pattern"
		fallback_pattern
		return
	fi
	echo "[*] Largest most common string: $common"

	# Most common full length, then most common position of the shared string within names of that length
	local -a matching=()
	local str prefix
	for str in "${names_array[@]}"; do
		[[ $str == *"$common"* ]] && matching+=("$str")
	done
	local full_length offset
	full_length=$(for str in "${matching[@]}"; do echo "${#str}"; done | sort | uniq -c | top_entry)
	echo "[*] Most common length of hostnames containing $common is $full_length"
	offset=$(for str in "${matching[@]}"; do
		((${#str} == full_length)) || continue
		prefix=${str%%"$common"*}
		echo "${#prefix}"
	done | sort | uniq -c | top_entry)

	# Split those hostnames into the parts before and after the shared string
	local -a before_parts=() after_parts=()
	for str in "${matching[@]}"; do
		prefix=${str%%"$common"*}
		((${#str} == full_length && ${#prefix} == offset)) || continue
		before_parts+=("$prefix")
		after_parts+=("${str:offset+${#common}}")
	done

	pattern_common=$common
	pattern_before_len=$offset
	pattern_after_len=$((full_length - offset - ${#common}))
	pattern_before_type=$(most_common_char_type "${before_parts[@]}")
	pattern_after_type=$(most_common_char_type "${after_parts[@]}")
	((pattern_before_len > 0)) && echo "[*] Pattern: $pattern_before_len chars ($pattern_before_type) before $common"
	((pattern_after_len > 0)) && echo "[*] Pattern: $pattern_after_len chars ($pattern_after_type) after $common"
}

generate_new_hostname() {
	hostname_new="$(generate_random_chars "$pattern_before_len" "$pattern_before_type")$pattern_common$(generate_random_chars "$pattern_after_len" "$pattern_after_type")"
}

# The interface has no address yet, so uniqueness is checked against every name seen on the network.
# DNS is checked once an address has been obtained.
is_hostname_unique() {
	local hostname="$1" name
	for name in "${all_names[@]}"; do
		[[ ${name,,} == "${hostname,,}" ]] && return 1
	done
	return 0
}

choose_hostname() {
	mapfile -t all_names < <(cut -f3 "$workdir/hosts" | grep -v '^$' | sort -uf)
	local -a persona_names
	mapfile -t persona_names < <(persona_filter | cut -f3 | grep -v '^$' | sort -uf)
	names_array=("${persona_names[@]}")
	local widened=0 name
	if ((!persona_generic && persona_count > 0 && ${#names_array[@]} < 3)); then
		echo "[*] Fewer than 3 $persona hostnames seen, looking for a pattern across all hosts"
		names_array=("${all_names[@]}")
		widened=1
	fi
	analyse_hostnames
	# A network-wide pattern only fits if the persona's own hosts follow it
	if ((widened && ${#persona_names[@]} > 0)) && [[ -n $pattern_common ]]; then
		for name in "${persona_names[@]}"; do
			[[ $name == *"$pattern_common"* ]] && break
		done
		if [[ $name != *"$pattern_common"* ]]; then
			echo "[*] The $persona hosts seen (${persona_names[*]}) do not follow that pattern"
			fallback_pattern
		fi
	fi
	if [[ -z $pattern_common ]]; then
		echo "[-] Will assign hostname 'unknown'"
		hostname_new="unknown"
		return
	fi
	local attempt
	for ((attempt = 1; attempt <= MAX_HOSTNAME_ATTEMPTS; attempt++)); do
		generate_new_hostname
		if is_hostname_unique "$hostname_new"; then
			echo "[+] Hostname: $hostname_new (not used by any host seen)"
			return
		fi
		echo "[*] Hostname '$hostname_new' is already in use, generating a new one..."
	done
	echo "[-] Could not generate an unused hostname after $MAX_HOSTNAME_ATTEMPTS attempts... will assign hostname 'unknown'"
	hostname_new="unknown"
}

################################################# MAC address

# Vendor names come from Wireshark's OUI database, or macchanger's older list on Wireshark < 4.2
vendor_of() {
	local oui=${1,,}
	if [[ ! -s $workdir/vendors ]]; then
		tshark -G manuf 2> /dev/null | awk -F'\t' '$1 ~ /^[0-9A-Fa-f:]+ *$/ { sub(/ +$/, "", $1); print $1 "\t" $3 }' > "$workdir/vendors"
		[[ -s $workdir/vendors ]] || macchanger -l 2> /dev/null | sed -nE 's/^[0-9]+ - ([0-9a-fA-F:]{8}) - (.*)$/\1\t\2/p' > "$workdir/vendors"
	fi
	local vendor
	vendor=$(awk -F'\t' -v oui="$oui" 'tolower($1) == oui { print $2; exit }' "$workdir/vendors")
	echo "${vendor:-unknown vendor}"
}

# Use the most common vendor prefix (OUI) of the persona's hosts. Locally administered MACs
# (randomised phones, VMs) carry no vendor information and are ignored.
choose_mac() {
	local source="$persona hosts"
	((persona_generic || persona_count == 0)) && source="all hosts"
	mac_oui=$(persona_filter | awk -F'\t' 'tolower(substr($1, 2, 1)) !~ /[26ae]/ { print substr($1, 1, 8) }' | sort | uniq -c | top_entry)
	if [[ -z $mac_oui ]]; then
		source="all hosts"
		mac_oui=$(awk -F'\t' 'tolower(substr($1, 2, 1)) !~ /[26ae]/ { print substr($1, 1, 8) }' "$workdir/hosts" | sort | uniq -c | top_entry)
	fi
	if [[ -z $mac_oui ]]; then
		mac_new=""
		echo "[-] No vendor information identified... will assign a random MAC address"
		return
	fi
	mac_vendor=$(vendor_of "$mac_oui")
	local attempt
	for ((attempt = 1; attempt <= MAX_HOSTNAME_ATTEMPTS; attempt++)); do
		mac_new="$mac_oui:$(printf "%02x:%02x:%02x" $((RANDOM % 256)) $((RANDOM % 256)) $((RANDOM % 256)))"
		grep -q "^$mac_new"$'\t' "$workdir/hosts" || break
	done
	echo "[+] MAC address: $mac_new ($mac_vendor, most common vendor among $source)"
}

################################################# Inbound firewall

# nftables rules that make unsolicited inbound traffic on the interface get the persona's answer:
# Windows Defender Firewall drops it silently, a Mac or Linux host with nothing listening answers
# with closed ports. Replies to our own traffic, DHCP, IPv6 neighbour discovery, IGMP and the allowed
# ports always get through.
firewall_rules() {
	local entry tcp=() udp=() ping=0
	for entry in ${allow_list//,/ }; do
		case $entry in
			ping) ping=1 ;;
			*/udp) udp+=("${entry%/udp}") ;;
			*) tcp+=("${entry%/tcp}") ;;
		esac
	done
	[[ $persona == windows ]] || ping=1
	cat << EOF
table $FIREWALL_TABLE {
	chain input {
		type filter hook input priority -10; policy accept;
		iifname != "$interface" accept
		ct state established,related accept
		meta l4proto igmp accept
		udp dport { 68, 546 } accept
		icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-advert, nd-redirect, mld-listener-query } accept
EOF
	if ((ping)); then
		echo "		icmp type echo-request accept"
		echo "		icmpv6 type echo-request accept"
	fi
	((${#tcp[@]})) && echo "		tcp dport { $(IFS=,; echo "${tcp[*]}") } accept"
	((${#udp[@]})) && echo "		udp dport { $(IFS=,; echo "${udp[*]}") } accept"
	if [[ $persona == windows ]]; then
		echo "		drop"
	else
		echo "		meta l4proto tcp reject with tcp reset"
		echo "		reject"
	fi
	echo "	}"
	echo "}"
}

describe_firewall() {
	if ((!firewall)); then
		echo "unchanged"
	elif [[ $persona == windows ]]; then
		echo "unsolicited traffic silently dropped, like Windows Defender Firewall (allowed: ${allow_list:-nothing})"
	else
		echo "all ports answer as closed, hiding local listeners (allowed: ${allow_list:-nothing})"
	fi
}

# Applied before the interface comes up, so the new identity is never reachable without it.
# A run without -f removes the rules of a previous run.
apply_firewall() {
	command -v nft > /dev/null 2>&1 || return
	if nft list table $FIREWALL_TABLE > /dev/null 2>&1; then
		nft delete table $FIREWALL_TABLE
		((firewall)) || echo "[*] Removed the inbound firewall rules of the previous run"
	fi
	((firewall)) || return
	if firewall_rules | nft -f /dev/stdin; then
		echo "[*] Inbound firewall: $(describe_firewall)"
	else
		warn "Failed to load the inbound firewall rules"
	fi
}

################################################# Applying the identity

write_dhclient_conf() {
	local code names=() fqdn=$hostname_new
	[[ -n $domain ]] && fqdn="$hostname_new.$domain"
	{
		echo "# Generated by chameleonic: $persona persona, DHCP fingerprint $dhcp_source"
		echo "timeout 60;"
		echo "option rfc3442-classless-static-routes code 121 = array of unsigned integer 8;"
		IFS=, read -ra codes <<< "$dhcp_prl"
		for code in "${codes[@]}"; do
			if [[ -n ${DHCP_OPTION_NAMES[$code]} ]]; then
				names+=("${DHCP_OPTION_NAMES[$code]}")
			else
				echo "option chameleonic-$code code $code = string;"
				names+=("chameleonic-$code")
			fi
		done
		echo "send host-name \"$hostname_new\";"
		echo "send dhcp-client-identifier = hardware;"
		[[ -n $dhcp_vendor_class ]] && echo "send vendor-class-identifier \"$dhcp_vendor_class\";"
		if ((dhcp_sends_fqdn)); then
			echo "send fqdn.fqdn \"$fqdn\";"
			echo "send fqdn.encoded off;"
			echo "send fqdn.server-update off;"
		fi
		if [[ $persona == macos && $dhcp_source == built-in* ]]; then
			echo "send dhcp-lease-time 7776000;"
			echo "send dhcp-max-message-size 1500;"
		fi
		(IFS=,; echo "request ${names[*]};") | sed 's/,/, /g'
	} > "$DHCLIENT_CONF"
}

set_hosts_entry() {
	local entry="$hostname_new"
	[[ -n $domain ]] && entry="$hostname_new.$domain"$'\t'"$hostname_new"
	# Rewrite in place, so ownership, permissions and bind mounts of /etc/hosts are kept
	{
		grep -v '^127\.0\.1\.1[[:space:]]' "$STATE_DIR/hosts.bak"
		printf "127.0.1.1\t%s\n" "$entry"
	} > "$workdir/hosts.new" && cat "$workdir/hosts.new" > /etc/hosts
}

apply_identity() {
	ip link set dev "$interface" down

	# MAC address
	if [[ -n $mac_new ]]; then
		macchanger -m "$mac_new" "$interface" > /dev/null 2>&1 || warn "Failed to set MAC address $mac_new on $interface"
	else
		macchanger -A "$interface" > /dev/null 2>&1 || warn "Failed to set a random MAC address on $interface"
	fi
	echo "[*] MAC address of $interface is now $(current_mac)"

	# Hostname
	hostnamectl set-hostname "$hostname_new" || warn "Failed to set hostname $hostname_new"
	set_hosts_entry
	echo "[*] Hostname is now $(hostname) (original /etc/hosts saved in $STATE_DIR)"

	# TCP/IP stack
	local setting
	while read -r setting; do
		[[ -n $setting ]] && set_sysctl "${setting%%=*}" "${setting#*=}"
	done < <(persona_sysctls)
	echo "[*] TCP/IP stack: $(describe_stack)"
	apply_firewall
	sysctl -qw "net.ipv6.conf.$interface.disable_ipv6=$(state_get "sysctl:net.ipv6.conf.$interface.disable_ipv6")" > /dev/null 2>&1

	# DHCP
	ip link set dev "$interface" up
	write_dhclient_conf
	echo "[*] Requesting an address with the $persona DHCP fingerprint ($dhcp_source)..."
	if dhclient -4 -1 -v -cf "$DHCLIENT_CONF" -lf "$DHCLIENT_LEASES" -pf "$DHCLIENT_PID" "$interface" > "$workdir/dhclient.log" 2>&1; then
		ip_new=$(ip -4 -o addr show dev "$interface" | awk '{ print $4; exit }')
		echo "[+] Got address $ip_new"
	else
		warn "No DHCP lease obtained ($(tail -n1 "$workdir/dhclient.log")); the new identity is applied without an IPv4 address"
	fi
	changing=0

	# The DHCP server is the most reliable source for the domain when none was seen in the capture
	if [[ -z $domain && -n $ip_new ]]; then
		domain=$(sed -nE 's/^ *option domain-name "([^" ]+)".*/\1/p' "$DHCLIENT_LEASES" | tail -n1 | tr 'A-Z' 'a-z')
		if [[ -n $domain ]]; then
			set_hosts_entry
			echo "[+] DNS domain from DHCP: $domain"
		fi
	fi
	if [[ -n $ip_new ]]; then
		local others
		others=$(getent ahostsv4 "$hostname_new" 2> /dev/null | awk '{ print $1 }' | sort -u | grep -v -e "^${ip_new%/*}$" -e '^127\.' | paste -sd' ' -)
		if [[ -n $others ]]; then
			warn "Hostname $hostname_new already resolves to $others: another host may be using it. Restore and run again to pick a new name."
		fi
	fi
}

print_plan() {
	local fqdn=$hostname_new
	[[ -n $domain ]] && fqdn="$hostname_new.$domain"
	local services=() service
	if has_systemd; then
		for service in "${CHATTY_SERVICES[@]}"; do
			systemctl is-active --quiet "$service" && services+=("$service")
		done
	fi
	echo "[*] Plan for $interface:"
	echo "    Persona:          $persona"
	echo "    MAC address:      ${mac_new:-random} ${mac_vendor:+($mac_vendor)}"
	echo "    Hostname:         $fqdn"
	echo "    DHCP fingerprint: ${dhcp_vendor_class:+vendor class \"$dhcp_vendor_class\", }options $dhcp_prl ($dhcp_source)"
	echo "    TCP/IP stack:     $(describe_stack)"
	echo "    Inbound firewall: $(describe_firewall)"
	echo "    Services stopped: ${services[*]:-none running}"
}

################################################# Restore

restore_identity() {
	[[ -f $STATE_FILE ]] || die "Nothing to restore: no saved identity in $STATE_DIR"
	interface=$(state_get interface)
	echo "[*] Restoring the original identity of $interface"

	if [[ -f $DHCLIENT_PID ]]; then
		dhclient -x -cf "$DHCLIENT_CONF" -lf "$DHCLIENT_LEASES" -pf "$DHCLIENT_PID" "$interface" > /dev/null 2>&1
		echo "[*] Stopped chameleonic's DHCP client"
	fi
	local pids
	pids=$(dhcp_client_pids)
	[[ -n $pids ]] && kill $pids 2> /dev/null
	ip link set dev "$interface" down
	ip -4 addr flush dev "$interface"

	local mac_old
	mac_old=$(state_get mac)
	macchanger -m "$mac_old" "$interface" > /dev/null 2>&1 || warn "Failed to restore MAC address $mac_old"
	echo "[*] MAC address of $interface is now $(current_mac)"

	local setting
	while IFS= read -r setting; do
		[[ -n $setting ]] || continue
		sysctl -qw "${setting%%=*}=${setting#*=}" > /dev/null 2>&1 || warn "Could not restore ${setting%%=*}"
	done < <(awk 'index($0, "sysctl:") == 1 { print substr($0, 8) }' "$STATE_FILE")
	echo "[*] Restored TCP/IP stack settings"

	hostnamectl set-hostname "$(state_get hostname)" || warn "Failed to restore hostname"
	cp "$STATE_DIR/hosts.bak" /etc/hosts
	echo "[*] Hostname is now $(hostname), /etc/hosts restored"

	if command -v nft > /dev/null 2>&1 && nft list table $FIREWALL_TABLE > /dev/null 2>&1; then
		nft delete table $FIREWALL_TABLE && echo "[*] Removed chameleonic's inbound firewall rules"
	fi

	if [[ $(state_get resolved) == yes ]] && command -v resolvectl > /dev/null 2>&1; then
		resolvectl revert "$interface" 2> /dev/null
	fi
	local service
	while read -r service; do
		[[ -n $service ]] && systemctl start "$service" && echo "[*] Started $service"
	done < <(state_get_all service)

	ip link set dev "$interface" up
	case $(state_get network) in
		nm)
			nmcli device set "$interface" managed yes
			echo "[*] NetworkManager manages $interface again"
			;;
		dhclient)
			dhclient -4 -nw "$interface" > /dev/null 2>&1
			echo "[*] Started DHCP client on $interface"
			;;
		static)
			local cidr gateway
			while read -r cidr; do
				[[ -n $cidr ]] && ip addr add "$cidr" dev "$interface"
			done < <(state_get_all address)
			gateway=$(state_get gateway)
			[[ -n $gateway ]] && ip route add default via "$gateway" dev "$interface" 2> /dev/null
			echo "[*] Restored static addresses on $interface"
			;;
	esac
	rm -rf "$STATE_DIR"
	echo "[+] Original identity restored"
}

################################################# Main logic

parse_args() {
	local positional=()
	listen_seconds=$LISTEN_SECONDS
	while (($#)); do
		case $1 in
			-t | --time) listen_seconds=$2; shift 2 ;;
			-p | --persona) forced_persona=$2; shift 2 ;;
			-f | --firewall) firewall=1; shift ;;
			-a | --allow) allow_list=$2; firewall=1; shift 2 ;;
			-x | --exclude) exclude_list=$2; shift 2 ;;
			-n | --dry-run) dry_run=1; shift ;;
			-r | --restore) restore=1; shift ;;
			-h | --help) show_help; exit 0 ;;
			-*) show_help; die "Unknown option: $1" ;;
			*) positional+=("$1"); shift ;;
		esac
	done
	interface=${positional[0]}
	capture_file=${positional[1]}
	[[ $listen_seconds =~ ^[1-9][0-9]*$ ]] || die "Listening time must be a number of seconds"
	[[ -z $forced_persona || $forced_persona =~ ^(windows|macos|linux)$ ]] || die "Persona must be windows, macos or linux"
	local entry port
	for entry in ${exclude_list//,/ }; do
		[[ $entry =~ ^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$ ]] || die "Invalid MAC address '$entry' in --exclude"
	done
	for entry in ${allow_list//,/ }; do
		[[ $entry == ping || $entry =~ ^[0-9]+(-[0-9]+)?(/(tcp|udp))?$ ]] || die "Invalid --allow entry '$entry': use PORT, PORT-PORT, PORT/udp or ping"
		for port in ${entry//[^0-9]/ }; do
			((port >= 1 && port <= 65535)) || die "Invalid port $port in --allow"
		done
	done
}

main() {
	parse_args "$@"
	if ((restore)); then
		require_root
		restore_identity
		return
	fi
	if [[ -z $interface ]]; then
		show_help
		die "No interface provided."
	fi
	[[ -e /sys/class/net/$interface ]] || die "This interface does not exist."
	if [[ -d /sys/class/net/$interface/wireless || -e /sys/class/net/$interface/phy80211 ]]; then
		die "$interface is a wireless interface: chameleonic needs a wired interface, since NetworkManager and wpa_supplicant control the MAC address and association on Wi-Fi"
	fi
	capture_file=${capture_file:-./chameleonic-$interface-$(date +%Y%m%d-%H%M%S).pcapng}
	local have_capture=0
	[[ -s $capture_file ]] && have_capture=1

	if ((dry_run && have_capture)); then
		require_commands tshark:tshark
	else
		require_root
		require_commands tshark:tshark
		((have_capture)) || require_commands dumpcap:wireshark-common
		((dry_run)) || require_commands ip:iproute2 macchanger:macchanger hostnamectl:systemd getent:libc-bin \
			dhclient:isc-dhcp-client sysctl:procps pgrep:procps
		((dry_run || !firewall)) || require_commands nft:nftables
	fi

	workdir=$(mktemp -d)
	trap on_exit EXIT
	trap 'exit 130' INT TERM
	check_tshark
	((have_capture)) || check_capture_path
	own_macs="$(current_mac) $(state_get mac) ${exclude_list//,/ }"

	if ((!have_capture)); then
		if ((dry_run)); then
			echo "[*] Dry run: listening with the current identity of $interface, nothing is changed"
		else
			take_over_interface
			macchanger -A "$interface" > /dev/null 2>&1 || warn "Failed to set a temporary random MAC address"
			echo "[*] Temporary random MAC address for listening: $(current_mac)"
			own_macs+=" $(current_mac)"
			ip link set dev "$interface" up
		fi
		listen_passively
	fi

	analyse_capture
	[[ -s $workdir/hosts ]] || warn "No hosts found in the capture; applying a generic identity (listen longer with -t for better results)"
	print_hosts
	choose_persona
	choose_domain
	choose_hostname
	choose_mac
	choose_dhcp_fingerprint
	print_plan

	if ((dry_run)); then
		echo "[*] Dry run: nothing was changed"
		return
	fi
	take_over_interface
	apply_identity
	echo "[+] Done: $interface is now $(hostname)${domain:+.$domain} ($persona) with MAC $(current_mac)${ip_new:+ and address $ip_new}"
	echo "[*] Restore the original identity with: $RESTORE_COMMAND"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
	main "$@"
fi
