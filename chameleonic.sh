#!/bin/bash
# chameleonic - blend into a network by passively fingerprinting nearby hosts and taking on the identity
# of the most common kind of workstation: MAC vendor, hostname pattern, DNS domain, DHCP fingerprint and
# TCP/IP stack behaviour.

# Under sh or an older bash, say so before reaching anything bash-specific
case $BASH_VERSION in
	'' | [0-3].* | 4.[0-2].*)
		echo "This script needs bash 4.3 or later: run it with 'bash $0'" >&2
		exit 1
		;;
esac

LISTEN_SECONDS=300
MAX_HOSTNAME_ATTEMPTS=20
STATE_DIR=/var/lib/chameleonic
STATE_FILE=$STATE_DIR/state
# Where Debian's AppArmor profile for dhclient lets it read its configuration and keep its lease and pid:
# elsewhere, an enforced profile would make it fall back to its own defaults, and a Linux fingerprint
DHCLIENT_CONF=/etc/dhcp/dhclient-chameleonic.conf
DHCLIENT_LEASES=/var/lib/dhcp/dhclient-chameleonic.leases
DHCLIENT_PID=/run/dhclient-chameleonic.pid
LOCK_FILE=/run/chameleonic.lock
# Broadcast and multicast traffic is what every port of a switched network sees
CAPTURE_FILTER="broadcast or multicast or arp or udp port 67 or udp port 68"
# Services that announce a Linux host: mDNS, printer browsing, NetBIOS, WS-Discovery, LLDP
CHATTY_SERVICES=(avahi-daemon.socket avahi-daemon.service cups-browsed.service nmbd.service wsdd.service wsdd2.service lldpd.service)
# Separator for multi-value tshark fields
AGG=$'\x1f'
# nftables table holding the persona's inbound firewall rules, separate from any existing ruleset
FIREWALL_TABLE="inet chameleonic"
# Works whether the script was started as ./chameleonic.sh or bash chameleonic.sh
printf -v RESTORE_COMMAND 'sudo bash %q -r' "$0"

# Built-in DHCP fingerprints, used when no host of the persona was seen requesting an address.
# Parameter request lists (option 55) are sent in exactly this order.
declare -A BUILTIN_PRL=(
	[windows]="1,3,6,15,31,33,43,44,46,47,119,121,249,252" # Windows 10/11
	[macos]="1,121,3,6,15,108,114,119,252,95,44,46"        # macOS 13+
	[linux]="1,28,2,3,15,6,119,12,44,47,26,121,42"         # Debian/Ubuntu dhclient
)
declare -A BUILTIN_VENDOR_CLASS=([windows]="MSFT 5.0" [macos]="" [linux]="")
declare -A BUILTIN_SENDS_FQDN=([windows]=1 [macos]=0 [linux]=0)
declare -A BUILTIN_DESCRIPTION=([windows]="Windows 10/11" [macos]="macOS 13+" [linux]="Debian dhclient, as this machine sends")
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
EOF
}

die() {
	echo "[-] $*" >&2
	exit 1
}

warn() {
	echo "[-] $*" >&2
}

# Ask the operator a question on the terminal and print the answer. Without a terminal to ask on,
# chameleonic stops rather than guess (-y answers yes to every question instead).
ask() {
	local question=$1 answer
	if ! { exec {tty_fd}<> /dev/tty; } 2> /dev/null; then
		die "No terminal to ask on: \"$question\". Run chameleonic from a terminal, or pass -y to accept every alternative it proposes."
	fi
	printf '[?] %s ' "$question" >&"$tty_fd"
	read -r answer <&"$tty_fd" || answer=""
	exec {tty_fd}>&-
	echo "$answer"
}

# Ask before doing something the network did not clearly point to. Returns 0 if the operator agrees.
confirm() {
	local answer
	if ((assume_yes)); then
		echo "[?] $1 [y/N] y (-y)"
		return 0
	fi
	answer=$(ask "$1 [y/N]") || exit 1
	[[ ${answer,,} == y || ${answer,,} == yes ]]
}

# Where more traffic would help: listening longer, unless the capture came from a file, which -t does
# not lengthen
more_traffic() {
	if ((have_capture)); then
		echo "listen again for longer (without the capture file, or with a new path, and -t)"
	else
		echo "listen longer with -t"
	fi
}

# Ask before going on in a way that exposes the original identity or this machine (the original MAC
# address, a DHCP request with the real hostname, no firewall). -y does not accept these: an unattended
# run stops instead.
confirm_exposure() {
	if ((assume_yes)); then
		echo "[?] $1 [y/N] n (-y never accepts this)"
		return 1
	fi
	confirm "$1"
}

# The operator declined an alternative: stop. If the interface was already taken over, offer to put it
# back, since restoring reconnects it with the original MAC address and hostname.
stop_here() {
	warn "Stopped: $*"
	if ((took_over)); then
		changing=0
		# Once only: a restore that stops here too must not offer itself again
		took_over=0
		[[ -s $capture_file ]] && echo "[*] The capture is saved in $capture_file: run again with it to skip listening"
		# Never restored without asking: -y accepts alternatives, not reconnecting as the original host
		if ((!assume_yes)) && { : <> /dev/tty; } 2> /dev/null &&
			confirm "Restore the original identity of $interface now? It reconnects with the original MAC address and hostname"; then
			restore_identity
		else
			echo "[*] $interface stays as it is now, without an address. Restore it later with '$RESTORE_COMMAND'"
		fi
	fi
	exit 1
}

# Print the entry with the highest count from a "count value" list (output of uniq -c)
top_entry() {
	sort -nr | head -n1 | sed -E 's/^ *[0-9]+ //'
}

require_root() {
	[[ $(id -u) == 0 ]] || die "Run this as root!"
}

# Two runs changing the interface at the same time would mix their identities and the saved state.
# Daemons started here (dhclient) must not inherit the lock, or it would outlive the run: they are
# started with {lock_fd}>&-.
lock_run() {
	exec {lock_fd}> "$LOCK_FILE"
	command -v flock > /dev/null 2>&1 || return
	flock -n "$lock_fd" || die "Another chameleonic run is changing the network identity: wait for it to finish"
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
	# Killed or hung up while listening: the capture must not go on without chameleonic
	[[ -n $capture_pid ]] && kill -TERM "$capture_pid" 2> /dev/null
	if ((changing)); then
		# The interface is left as it is: bringing it up would let it talk with a half-applied identity
		warn "Stopped before the new identity was fully applied; $interface may be down or have no address"
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

# A change whose original value cannot be saved is not made: -r could not undo it (a full disk)
state_add() {
	printf '%s=%s\n' "$1" "$2" >> "$STATE_FILE" 2> /dev/null ||
		stop_here "could not write to $STATE_FILE, so -r could not undo the next change"
}

state_has() {
	grep -q "^$1=" "$STATE_FILE" 2> /dev/null
}

# Record a value only if nothing was recorded for that key yet
state_record() {
	grep -q "^$1=" "$STATE_FILE" 2> /dev/null || state_add "$1" "$2"
}

set_sysctl() {
	local key=$1 value=$2
	state_record "sysctl:$key" "$(sysctl -n "$key" 2> /dev/null | tr '\t' ' ')"
	sysctl -qw "$key=$value" > /dev/null 2>&1 && return
	warn "Could not set $key=$value"
	return 1
}

# Put back the original value of every sysctl changed so far, except those matching the patterns given.
# Those that cannot be set are listed in sysctl_failed.
restore_sysctls() {
	local setting pattern key
	sysctl_failed=()
	while IFS= read -r setting; do
		# Empty if it could not be read before, like an IPv6 stable_secret that was never set
		[[ -n ${setting#*=} ]] || continue
		key=${setting%%=*}
		for pattern in "$@"; do
			# shellcheck disable=SC2053 # the patterns are globs
			[[ $key == $pattern ]] && continue 2
		done
		# Saved by earlier versions as net.ipv6.conf.eth0.100.hop_limit, which sysctl reads as eth0/100
		if [[ $interface == *.* && $key == net.ipv[46].conf."$interface".* ]]; then
			key="net/${key:4:4}/conf/$interface/${key#net.ipv?.conf."$interface".}"
		fi
		sysctl -qw "$key=${setting#*=}" > /dev/null 2>&1 || { warn "Could not restore $key"; sysctl_failed+=("$key"); }
		# Setting an IPv6 stable_secret switches addr_gen_mode to stable privacy, so secrets go first
	done < <(awk 'index($0, "sysctl:") == 1 {
			setting = substr($0, 8)
			if (setting ~ /[.\/]stable_secret=/) print setting
			else rest[++n] = setting
		}
		END { for (i = 1; i <= n; i++) print rest[i] }' "$STATE_FILE")
}

# A random IPv6 address, used as the secret IPv6 link-local addresses are derived from
random_ipv6() {
	od -An -tx2 -N16 /dev/urandom | awk '{ $1 = $1; gsub(/ /, ":"); print }'
}

nm_device_state() {
	nmcli -t -f DEVICE,STATE device status 2> /dev/null | awk -F: -v dev="$1" '$1 == dev { print $2 }'
}

networkd_manages() {
	systemctl is-active --quiet systemd-networkd 2> /dev/null || return 1
	local setup
	setup=$(networkctl list --no-legend --no-pager 2> /dev/null | awk -v dev="$interface" '$2 == dev { print $5 }')
	[[ -n $setup && $setup != unmanaged ]]
}

# Booted with ipv6.disable=1, the kernel has no IPv6 at all: nothing to disable, and nothing to set
ipv6_present() {
	[[ -d /proc/sys/net/ipv6/conf/$interface ]]
}

link_is_up() {
	(($(cat "/sys/class/net/$1/flags" 2> /dev/null || echo 0) & 1))
}

# What configured the interface before chameleonic took over, so restoring can hand it back: nm,
# networkd, dhclient (a DHCP client started for this interface), static or none
detect_network_mode() {
	if command -v nmcli > /dev/null 2>&1 && [[ $(nmcli -t -f RUNNING general 2> /dev/null) == running ]]; then
		local nm_state
		nm_state=$(nm_device_state "$interface")
		# "connected (externally)": configured by hand or another tool, which NetworkManager only watches
		if [[ -n $nm_state && $nm_state != unmanaged && $nm_state != "connected (externally)" ]]; then
			echo nm
			return
		fi
	fi
	if networkd_manages; then
		echo networkd
	elif [[ -n $(dhcp_client_pids) ]]; then
		echo dhclient
	elif [[ -n $(ip -o addr show dev "$interface" scope global 2> /dev/null) ]]; then
		echo static
	else
		echo none
	fi
}

# Route lines of a device (the interface by default) as "ip route show" prints them, without the flags
# "ip route replace" does not take
route_lines() {
	ip "$1" route show dev "${2:-$interface}" 2> /dev/null |
		grep -vE 'proto (kernel|ra|dhcp)|^(fe80::|ff00::|multicast )' |
		sed -E 's/ (linkdown|dead|offload|trap|rt_offload|rt_trap|rt_offload_failed)\b//g'
}

init_state() {
	local saved_interface
	saved_interface=$(state_get interface)
	if [[ -n $saved_interface && $saved_interface != "$interface" ]]; then
		die "An identity is already applied to $saved_interface. Run '$RESTORE_COMMAND' first."
	fi
	if [[ -n $saved_interface ]]; then
		echo "[*] Re-running on $interface: keeping the original identity saved in $STATE_DIR"
		# Saved by an earlier version, which made the persona's name the saved hostname: the original
		# goes back there, so a reboot does not bring the persona's name up with the original MAC address
		if ! state_has hostname_static; then
			state_add hostname_static "$(state_get hostname)"
			hostnamectl set-hostname --static "$(state_get hostname)" 2> /dev/null ||
				warn "Could not set the saved hostname back to $(state_get hostname)"
		fi
		return
	fi

	# Saved in a new directory that is moved into place at once: a save cut short (Ctrl-C, a full disk)
	# must not leave a partial identity that later runs and -r would trust
	local new_dir=$STATE_DIR.new saved_file=$STATE_FILE
	rm -rf "$new_dir"
	mkdir -p -m 700 "$new_dir" || die "Cannot save the original identity in $new_dir: nothing was changed"
	STATE_FILE=$new_dir/state
	: > "$STATE_FILE"
	state_add interface "$interface"
	state_add mac "$(current_mac)"
	state_add hostname "$(hostname)"
	state_add hostname_static "$(hostnamectl --static 2> /dev/null || cat /etc/hostname 2> /dev/null)"
	link_is_up "$interface" && state_add link up || state_add link down
	local mode pid args
	mode=$(detect_network_mode)
	state_add network "$mode"
	[[ $(nm_device_state "$interface") == "connected (externally)" ]] && state_add nm_external yes
	case $mode in
		nm)
			state_add nm_connection "$(nmcli -t -f UUID,DEVICE connection show --active 2> /dev/null | awk -F: -v dev="$interface" '$2 == dev { print $1; exit }')"
			;;
		dhclient)
			# Started again exactly as it was, with its own lease and pid files. dhcpcd 9 and later
			# rename their processes, so their options cannot be read back (see check_dhcpcd).
			for pid in $(dhcp_client_pids); do
				args=$(tr '\0' ' ' < "/proc/$pid/cmdline" | sed 's/ *$//')
				[[ $args == dhcpcd:* ]] && args="dhcpcd $interface"
				state_add dhcp_command "$args"
			done
			;;
		static)
			# IPv6 addresses and routes too: disabling IPv6 on the interface removes them
			while read -r cidr; do state_add address "$cidr"; done < <(ip -o addr show dev "$interface" scope global | awk '$0 !~ / dynamic / { print $4 }')
			while read -r route; do state_add route4 "$route"; done < <(route_lines -4)
			while read -r route; do state_add route6 "$route"; done < <(route_lines -6)
			;;
	esac
	local saved=1
	cp /etc/hosts "$new_dir/hosts.bak" || saved=0
	# dhclient-script rewrites /etc/resolv.conf with the network's DNS servers, through the link if
	# it is one (to systemd-resolved's or resolvconf's file)
	[[ -L /etc/resolv.conf ]] && state_add resolv_link "$(readlink /etc/resolv.conf)"
	if [[ -f /etc/resolv.conf ]]; then
		cp -L /etc/resolv.conf "$new_dir/resolv.conf.bak" || saved=0
	fi
	STATE_FILE=$saved_file
	[[ -n $(STATE_FILE=$new_dir/state state_get mac) && -n $(STATE_FILE=$new_dir/state state_get network) ]] || saved=0
	# A directory left without a state file holds nothing to restore
	((saved)) && rm -rf "$STATE_DIR" && mv "$new_dir" "$STATE_DIR" || {
		rm -rf "$new_dir"
		die "Could not save the original identity in $STATE_DIR: nothing was changed"
	}
	echo "[*] Saved original identity (MAC $(current_mac), hostname $(hostname)) to $STATE_DIR"
}

################################################# Taking over the interface

# Stop processes and wait until they are gone: a DHCP client finishing a hook script would otherwise send
# one more packet once the interface is up again, with the MAC address it started with
stop_processes() {
	local pid tries alive
	(($#)) || return 0
	kill "$@" 2> /dev/null
	for ((tries = 0; tries < 30; tries++)); do
		alive=0
		for pid in "$@"; do
			kill -0 "$pid" 2> /dev/null && alive=1
		done
		((alive)) || return 0
		sleep 0.1
	done
	kill -KILL "$@" 2> /dev/null
}

# chameleonic's dhclient, if it still runs: after a power cut its pid file is stale, and the number may
# belong to another process by now
own_dhclient_pid() {
	local pid
	pid=$(cat "$DHCLIENT_PID" 2> /dev/null) || return 1
	[[ $pid =~ ^[0-9]+$ ]] && tr '\0' ' ' < "/proc/$pid/cmdline" 2> /dev/null | grep -qF -- "$DHCLIENT_CONF" && echo "$pid"
}

dhcp_client_pids() {
	local pid args
	pgrep -a -x 'dhclient|dhcpcd' 2> /dev/null | while read -r pid args; do
		if [[ $args == dhcpcd:* ]]; then
			# dhcpcd 9 and later rename their processes: "dhcpcd: eth0 [ip4] [ip6]" serves eth0 alone,
			# "dhcpcd: [manager] ..." every interface (see check_dhcpcd); the others are their helpers
			[[ $args == "dhcpcd: $interface "* ]] && echo "$pid"
		elif [[ " $args " == *" $interface "* ]]; then
			echo "$pid"
		fi
	done
}

# Stop services that announce this host. The interface is already down, so the goodbye messages some
# of them send when stopping (avahi's mDNS goodbye, IGMP leaves) cannot be heard on the network.
silence_chatter() {
	local service active=()
	if has_systemd; then
		# Stopping a socket unit also stops its service: note everything running first, so restoring
		# starts both again
		for service in "${CHATTY_SERVICES[@]}"; do
			systemctl is-active --quiet "$service" && active+=("$service")
		done
		for service in "${active[@]}"; do
			state_add service "$service"
			systemctl stop "$service" 2> /dev/null
			# Masked until restored: D-Bus or socket activation (a print dialog, network browsing) would
			# start it again, announcing a Linux host under the new identity
			if systemctl mask --runtime "$service" > /dev/null 2>&1; then
				state_add masked "$service"
			else
				warn "Could not mask $service, so it can be started again while the new identity is applied"
				confirm_exposure "Continue with $service stopped but not masked?" || stop_here "$service could not be masked"
			fi
			echo "[*] Stopped $service (it announces this host on the network)"
		done
		if systemctl is-active --quiet systemd-resolved && command -v resolvectl > /dev/null 2>&1; then
			resolvectl llmnr "$interface" no 2> /dev/null
			resolvectl mdns "$interface" no 2> /dev/null
			state_record resolved yes
			echo "[*] Disabled LLMNR and mDNS in systemd-resolved on $interface"
		fi
	fi
}

# A VLAN or macvlan interface shares the network card of its parent. chameleonic only changes the
# interface it is given, so a parent with addresses keeps talking with the original MAC address.
check_parent_interface() {
	local lower parent addresses talks
	for lower in "/sys/class/net/$interface"/lower_*; do
		[[ -e $lower ]] || continue
		parent=${lower##*/lower_}
		talks=""
		addresses=$(ip -4 -o addr show dev "$parent" 2> /dev/null | awk '{ print $4 }' | paste -sd' ' -)
		[[ -n $addresses ]] && talks="IPv4 $addresses"
		[[ $(sysctl -n "net/ipv6/conf/$parent/disable_ipv6" 2> /dev/null) == 0 ]] && talks+="${talks:+, }IPv6 enabled"
		[[ -n $talks ]] || continue
		warn "$interface runs on $parent, which chameleonic does not change: it keeps the MAC address $(cat "/sys/class/net/$parent/address") and talks on the network ($talks)"
		((dry_run)) && continue
		confirm_exposure "Continue, with $parent heard on the network as before?" ||
			stop_here "silence $parent first: remove its IPv4 addresses and disable IPv6 (sysctl -w net/ipv6/conf/$parent/disable_ipv6=1)"
	done
}

# VLAN or macvlan interfaces on top of this one go down and up with it and take on its MAC address:
# while chameleonic listens and afterwards, they would be heard again with their own addresses and
# names. Sets stacked to those that are up, if the operator agrees to take them down.
check_stacked_interfaces() {
	local upper name
	stacked=()
	for upper in "/sys/class/net/$interface"/upper_*; do
		[[ -e $upper ]] || continue
		name=${upper##*/upper_}
		link_is_up "$name" && stacked+=("$name")
	done
	((${#stacked[@]})) || return 0
	warn "${stacked[*]} run on $interface: they go down and up with it and take on its MAC address, so they would be heard with their own addresses and names under the new identity"
	((dry_run)) && return 0
	confirm "Take ${stacked[*]} down until the original identity is restored?" ||
		stop_here "take ${stacked[*]} down yourself, or remove them"
}

# dhcpcd 9 and later rename their processes, so the options a dhcpcd serving only this interface was
# started with cannot be read back. dhcpcd in manager mode serves every interface and configures this
# one again as soon as it comes up, whatever it is told: chameleonic cannot make it let go.
check_dhcpcd() {
	local pid args word named own=0 manager=0
	while read -r pid args; do
		if [[ $args == "dhcpcd: $interface "* ]]; then
			own=1
		elif [[ $args == *"[manager]"* ]]; then
			manager=1
		elif [[ $args != dhcpcd:* ]]; then
			named=0
			for word in $args; do
				[[ -e /sys/class/net/$word ]] && named=1
			done
			((named)) || manager=1
		fi
	done < <(pgrep -a -x dhcpcd 2> /dev/null)
	if ((own)); then
		warn "dhcpcd serves $interface, and the options it was started with cannot be read back"
		((dry_run)) || confirm "Stop it while the new identity is applied, and start 'dhcpcd $interface' when restoring?" ||
			stop_here "stop dhcpcd on $interface yourself (dhcpcd -x $interface), then run chameleonic again"
	fi
	if ((manager)); then
		warn "dhcpcd runs for all interfaces, so it would configure $interface again as soon as chameleonic brings it up, with the temporary MAC address and this machine's hostname"
		((dry_run)) || confirm_exposure "Continue with dhcpcd running?" ||
			stop_here "make dhcpcd ignore $interface (denyinterfaces $interface in /etc/dhcpcd.conf) and restart it, or stop it"
	fi
}

# The interface can disappear while chameleonic runs (a USB adapter unplugged, a VLAN deleted)
require_interface() {
	[[ -e /sys/class/net/$interface ]] && return
	stop_here "$interface no longer exists"
}

# Detach the interface from NetworkManager, systemd-networkd and DHCP clients so nothing is sent until
# the new identity is in place, and nothing resets the MAC address afterwards
take_over_interface() {
	((took_over)) && return
	require_interface
	init_state
	changing=1
	took_over=1
	# VLANs on top lose their routes and IPv6 addresses when the interface goes down: saved first
	local name cidr route
	for name in "${stacked[@]}"; do
		# Already saved by an earlier run
		state_get_all stacked | grep -qxF -- "$name" && continue
		state_add stacked "$name"
		while read -r cidr; do
			[[ -n $cidr ]] && state_add stacked_address "$name $cidr"
		done < <(ip -o addr show dev "$name" scope global | awk '$0 !~ / dynamic / { print $4 }')
		while read -r route; do
			[[ -n $route ]] && state_add stacked_route4 "$name $route"
		done < <(route_lines -4 "$name")
		while read -r route; do
			[[ -n $route ]] && state_add stacked_route6 "$name $route"
		done < <(route_lines -6 "$name")
	done
	# NetworkManager first, so it does not bring the interfaces back up once they are down
	# Interfaces on top that are down too: NetworkManager could activate them once the interface is up
	local upper uppers=()
	for upper in "/sys/class/net/$interface"/upper_*; do
		[[ -e $upper ]] && uppers+=("${upper##*/upper_}")
	done
	for name in "$interface" "${uppers[@]}"; do
		[[ -z $(nm_device_state "$name") || $(nm_device_state "$name") == unmanaged ]] && continue
		nmcli device set "$name" managed no 2> "$workdir/nmcli.log" ||
			stop_here "NetworkManager did not let go of $name ($(head -n1 "$workdir/nmcli.log")), and would reconnect it as soon as it is up"
		[[ $name == "$interface" ]] || state_add stacked_nm "$name"
		echo "[*] NetworkManager no longer manages $name (so it cannot reset the MAC address or send DHCP requests)"
	done
	# Multicast groups the stopped services leave while the interface is down are reported once it is up
	# again with IGMPv3 and MLDv2, which keep the leaves to send later. IGMPv2 and MLDv1 send them at
	# once, into the down interface. The persona's settings put the versions back before it comes up.
	set_sysctl "net/ipv4/conf/$interface/force_igmp_version" 2
	ipv6_present && set_sysctl "net/ipv6/conf/$interface/force_mld_version" 1
	ip link set dev "$interface" down
	# The kernel brings every VLAN on the interface up when the interface comes up, those that were down
	# too, unless its binding is loose
	for name in "${uppers[@]}"; do
		if ip -d link show dev "$name" | grep -q 'vlan protocol' && ! ip -d link show dev "$name" | grep -q LOOSE_BINDING; then
			ip link set dev "$name" type vlan loose_binding on && state_add stacked_loose "$name"
		fi
	done
	for name in "${stacked[@]}"; do
		ip link set dev "$name" down
		echo "[*] $name is down until the original identity is restored"
	done
	# systemd-networkd would configure the interface again when it comes up. A runtime configuration
	# file tells it to leave the interface alone; the DHCP release it may send cannot leave, the
	# interface is down.
	if networkd_manages; then
		mkdir -p /run/systemd/network && printf '[Match]\nName=%s\n\n[Link]\nUnmanaged=yes\n' "$interface" > "$(networkd_file)" &&
			networkctl reload 2> /dev/null
		local tries=0
		while networkd_manages && ((tries++ < 5)); do
			sleep 1
		done
		if networkd_manages; then
			warn "systemd-networkd still manages $interface: another .network file for it comes first"
			confirm_exposure "Continue, with systemd-networkd configuring $interface (DHCP with this machine's hostname) when it comes up?" ||
				stop_here "make systemd-networkd leave $interface alone (Unmanaged=yes in its .network file), then run chameleonic again"
		else
			echo "[*] systemd-networkd no longer manages $interface"
		fi
	fi
	silence_chatter
	local pids
	pids=$(dhcp_client_pids)
	if [[ -n $pids ]]; then
		stop_processes $pids
		echo "[*] Stopped DHCP client on $interface"
	fi
	ip -4 addr flush dev "$interface"
	if ! ipv6_present; then
		echo "[*] $interface is silent: no IPv4 address, and no IPv6 in this kernel"
	elif set_sysctl "net/ipv6/conf/$interface/disable_ipv6" 1; then
		echo "[*] $interface is silent: no IPv4 address, IPv6 disabled"
	else
		confirm_exposure "IPv6 could not be disabled on $interface, so the kernel may send IPv6 router solicitations from it while it is up before the new identity is applied. Continue?" ||
			stop_here "IPv6 could not be disabled"
		echo "[*] $interface has no IPv4 address, but IPv6 could not be disabled"
	fi
}

networkd_file() {
	echo "/run/systemd/network/00-chameleonic-$interface.network"
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
	capture_pid=$!
	local elapsed=0 status stopped_by_operator=0
	trap 'stopped_by_operator=1; kill -TERM "$capture_pid" 2> /dev/null' INT
	while kill -0 "$capture_pid" 2> /dev/null; do
		sleep 1
		((++elapsed % 30 == 0)) && echo "[*] Listening... ${elapsed}s / ${listen_seconds}s"
	done
	wait "$capture_pid"
	status=$?
	capture_pid=""
	trap 'exit 130' INT
	local reason
	reason=$(grep -v -e '^$' -e '^Packets received/dropped' "$workdir/dumpcap.log" | tail -n1)
	[[ -s $capture_tmp ]] || die "Capture failed: dumpcap $(describe_status "$status")${reason:+ ($reason)}"
	mv -f "$capture_tmp" "$capture_file" || die "Could not save the capture to $capture_file"
	# Hand the file to the user who ran sudo, so it can be opened without root
	[[ -n $SUDO_UID && -n $SUDO_GID ]] && chown "$SUDO_UID:$SUDO_GID" "$capture_file"
	local packets
	packets=$(tshark -r "$capture_file" -T fields -e frame.number 2> /dev/null | wc -l)
	echo "[+] Captured $packets packets"
	# Stopped without Ctrl-C: the cable or adapter was pulled, or dumpcap failed
	if ((!stopped_by_operator && (status != 0 || elapsed + 2 < listen_seconds))); then
		warn "Listening stopped after ${elapsed}s of ${listen_seconds}s: dumpcap $(describe_status "$status")${reason:+ ($reason)}"
		require_interface
		confirm "Continue with the $packets packets captured?" || stop_here "listening stopped early"
	fi
}

################################################# Capture parsing
# Every source is turned into "mac<TAB>key<TAB>value" events, then aggregated per host.

tshark_fields() {
	local filter=$1
	shift
	tshark -n -r "$capture_file" -Y "$filter" -T fields -E separator=/t -E occurrence=a -E "aggregator=$AGG" "$@" 2> /dev/null
}

pcap_events() {
	# The addresses hosts claim for themselves in ARP
	tshark_fields "arp" -e arp.src.hw_mac -e arp.src.proto_ipv4 |
		awk -F'\t' '{ print $1 "\tip\t" $2 }'
	# Source addresses and initial TTL. A router forwards other hosts' packets with its own MAC address,
	# so these only count for the address the MAC claims (see aggregate_events). mDNS and LLMNR use fixed
	# TTLs, dhclient sends DHCP with TTL 128, and DNS answers mostly come from a server behind the router,
	# so those packets are not used for the TTL.
	tshark_fields "ip && ip.src != 0.0.0.0" -e eth.src -e ip.src -e ip.ttl -e udp.srcport -e udp.dstport |
		awk -F'\t' -v agg="$AGG" '{
			split($2, src, agg); split($3, ttl, agg); split($4, sport, agg); split($5, dport, agg)
			usable = sport[1] !~ /^(53|67|68|5353|5355)$/ && dport[1] !~ /^(67|68|5353|5355)$/
			print $1 "\tipsrc\t" src[1] "|" (usable ? ttl[1] : "-")
		}'
	# DHCP requests: hostname, FQDN, vendor class and parameter request list
	tshark_fields "!icmp && (dhcp.option.dhcp == 1 || dhcp.option.dhcp == 3 || dhcp.option.dhcp == 8)" \
		-e dhcp.hw.mac_addr -e dhcp.option.hostname -e dhcp.option.vendor_class_id -e dhcp.option.request_list_item \
		-e dhcp.fqdn.name -e dhcp.option.requested_ip_address -e dhcp.option.dhcp |
		awk -F'\t' -v agg="$AGG" '{
			gsub(agg, ",", $4)
			split($7, type, agg)
			if ($2 != "") print $1 "\tdhcp_host\t" $2
			if ($3 != "") print $1 "\tdhcp_vc\t" $3
			# Windows asks for other options in DHCPINFORM than when it requests an address
			if ($4 != "" && type[1] != 8) print $1 "\tdhcp_prl\t" $4
			if ($5 != "") print $1 "\tdhcp_fqdn\t" $5
			if ($6 != "") print $1 "\tip\t" $6
		}'
	# DHCP offers and acks: the domain name handed out by the server
	tshark_fields "!icmp && (dhcp.option.dhcp == 2 || dhcp.option.dhcp == 5)" -e eth.src -e dhcp.option.domain_name |
		awk -F'\t' '$2 != "" { print $1 "\tdomain_server\t" $2 }'
	# NetBIOS name service: queries, registrations and refreshes
	tshark_fields "nbns && !icmp && nbns.flags.response == 0" -e eth.src -e nbns.flags.opcode -e nbns.name -e nbns.nb_flags.group |
		awk -F'\t' -v agg="$AGG" '{ split($3, name, agg); split($4, group, agg); print $1 "\tnbns\t" $2 "|" name[1] "|" group[1] }'
	# Browser announcements carry the host name and Windows version. Domain/Workgroup announcements
	# (command 0x0c) carry the workgroup's name instead.
	tshark_fields "browser.server && !icmp && browser.command != 0x0c" -e eth.src -e browser.server -e browser.os_major -e browser.os_minor |
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
# sends_fqdn, name_source) and count the DNS domains seen. Each piece of evidence scores a class once
# per host; a host needs a score of 2 or more to be classified, otherwise it is "unknown". Only evidence
# specific to a workstation makes one: routers, NAS boxes and other Linux-based devices stay unknown.
aggregate_events() {
	awk -F'\t' -v OFS='\t' -v own="$own_macs" -v win_prl="${BUILTIN_PRL[windows]}" -v linux_prl="${BUILTIN_PRL[linux]}" -v agg="$AGG" \
		-v hosts_file="$workdir/hosts" -v domains_file="$workdir/domains" '
		function note(mac, tag, class, weight) {
			if ((mac, tag) in noted) return
			noted[mac, tag] = 1
			score[mac, class] += weight
			evidence[mac] = evidence[mac] (evidence[mac] == "" ? "" : ", ") tag
		}
		# Names from NetBIOS (registrations, name tables, browser announcements: priorities 3 and 4) are
		# kept apart from the others, as NetBIOS cuts them to 15 characters
		function name_candidate(mac, priority, name) {
			sub(/\.+$/, "", name)
			if (name !~ /^[A-Za-z0-9-]+$/ || length(name) > 63) return
			if (priority == 3 || priority == 4) {
				if (!(mac in netbios_priority) || priority < netbios_priority[mac]) {
					netbios_priority[mac] = priority
					netbios_name[mac] = name
				}
			} else if (!(mac in other_priority) || priority < other_priority[mac]) {
				other_priority[mac] = priority
				other_name[mac] = name
			}
			name_hints(mac, name)
		}
		# What a device name says about it, wherever the name was heard (DHCP, NetBIOS in capitals, mDNS)
		function name_hints(mac, name,   lower) {
			lower = tolower(name)
			if (lower ~ /iphone|ipad|ipod|apple-watch/) note(mac, "name:" name, "mobile", 4)
			else if (lower ~ /android|galaxy|pixel/) note(mac, "name:" name, "mobile", 3)
			else if (lower ~ /macbook|imac|mac-mini|mac-pro|mac-studio|-mbp|-mba/) note(mac, "name:" name, "macos", 2)
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
			# Written out: mawk before 2020 has no {n} repetition in patterns
			if (mac !~ /^[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]$/ || mac == "00:00:00:00:00:00" || mac == "ff:ff:ff:ff:ff:ff" || (mac in own_mac)) next
			hosts[mac] = 1
			if (key == "ip") {
				# Claimed in ARP or in a DHCP request
				if (value ~ /^[0-9.]+$/ && value != "0.0.0.0") {
					claimed[mac, value] = 1
					if (!(mac in ip)) ip[mac] = value
				}
			} else if (key == "ipsrc") {
				split(value, source, "|")
				if (!((mac, source[1]) in source_seen)) {
					source_seen[mac, source[1]] = 1
					sources[mac]++
					only_source[mac] = source[1]
				}
				if (source[2] != "-" && source[2] + 0 >= 32) source_ttl[mac, source[1], initial_ttl(source[2] + 0)]++
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
				# dhcpcd also runs on Raspberry Pis and appliances: a hint, not proof of a workstation
				else if (value ~ /^dhcpcd/) note(mac, "dhcp:dhcpcd", "linux", 1)
				else if (value ~ /^udhcp/) note(mac, "dhcp:udhcp", "other", 2)
			} else if (key == "dhcp_prl") {
				prl[mac] = value
				if (value == win_prl) note(mac, "dhcp:windows-options", "windows", 3)
				# The option list dhclient sends as shipped by Debian and Ubuntu
				else if (value == linux_prl) note(mac, "dhcp:dhclient-options", "linux", 2)
				# Every Apple system starts with 1,121,3,6,15; macOS also asks for LDAP (95) and NetBIOS
				# (44, 46), iOS and iPadOS do not
				else if (value ~ /^1,121,3,6,15,/ && (value ~ /(^|,)95(,|$)/ || (value ~ /(^|,)44(,|$)/ && value ~ /(^|,)46(,|$)/))) note(mac, "dhcp:macos-options", "macos", 3)
				else if (value ~ /^1,121,3,6,15,/) note(mac, "dhcp:ios-options", "mobile", 3)
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
				# SSH: Linux and BSD servers, NAS boxes, routers, Macs with Remote Login alike
				else if (value == 22) note(mac, "tcp:22", "other", 0)
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
				# UPnP servers on Linux are routers, TVs and NAS boxes far more often than desktops
				else if (value ~ /Linux/) note(mac, "ssdp:linux", "other", 1)
			}
		}
		END {
			# A MAC address that claimed no address in ARP or DHCP, and sent from one address only, is
			# taken to be that host. One sending from several addresses forwards for others: a router.
			for (mac in hosts) {
				if (!(mac in ip) && sources[mac] == 1) {
					ip[mac] = only_source[mac]
					claimed[mac, only_source[mac]] = 1
				}
			}
			for (key in source_ttl) {
				split(key, part, SUBSEP)
				if ((part[1], part[2]) in claimed) ttl_count[part[1], part[3]] += source_ttl[key]
			}
			for (mac in hosts) {
				if ((mac in ip) && (ip[mac] in ptr_name)) fqdn(mac, 6, ptr_name[ip[mac]])
				best_ttl = ""; best_ttl_count = 0
				split("32 64 128 255", ttls, " ")
				for (i = 1; i <= 4; i++) if (ttl_count[mac, ttls[i]] > best_ttl_count) { best_ttl = ttls[i]; best_ttl_count = ttl_count[mac, ttls[i]] }
				# The initial TTL overrules protocol hints: Windows uses 128, Unix-like systems 64
				# (a Linux NAS running Samba answers NetBIOS and SMB like Windows does). 64 alone does not
				# make a host a Linux workstation: routers, NAS boxes and appliances use it too.
				if (best_ttl == 128) {
					note(mac, "ttl:128", "windows", 2)
					score[mac, "linux"] = score[mac, "macos"] = score[mac, "mobile"] = 0
				} else if (best_ttl == 64) {
					note(mac, "ttl:64", "other", 0)
					score[mac, "windows"] = 0
				} else if (best_ttl == 255) {
					note(mac, "ttl:255", "other", 1)
					score[mac, "windows"] = 0
				}
				class = "unknown"; best_score = 1
				for (c = 1; c <= n_classes; c++) if (score[mac, classes[c]] > best_score) { class = classes[c]; best_score = score[mac, classes[c]] }
				# DHCP names beat NetBIOS ones, which beat mDNS and reverse DNS, unless the NetBIOS name is
				# a full name of 15 characters cut short: the full one, heard elsewhere, is kept then
				name = ""; name_source = "other"
				if (mac in netbios_name) {
					if ((mac in other_name) && (other_priority[mac] < netbios_priority[mac] ||
						(length(netbios_name[mac]) == 15 && tolower(substr(other_name[mac], 1, 15)) == tolower(netbios_name[mac])))) {
						name = other_name[mac]
					} else {
						name = netbios_name[mac]
						name_source = "netbios"
					}
				} else if (mac in other_name) {
					name = other_name[mac]
				}
				print mac, ip[mac], name, class, evidence[mac], prl[mac], vendor_class[mac], sends_fqdn[mac] + 0, name_source > hosts_file
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
	# A capture cut short (copied before dumpcap finished, a full disk) is still usable up to the damage
	local packets error
	tshark -n -r "$capture_file" -T fields -e frame.encap_type > "$workdir/encapsulations" 2> "$workdir/tshark.err"
	packets=$(wc -l < "$workdir/encapsulations")
	error=$(grep -v -e '^$' -e 'Running as user' "$workdir/tshark.err" | head -n1 | sed -E 's/^tshark: //; s/\.$//')
	if [[ -n $error ]]; then
		((packets > 0)) || die "Cannot read $capture_file: $error"
		confirm "$capture_file is damaged after packet $packets ($error). Continue with the $packets packets before the damage?" ||
			stop_here "the capture is damaged"
	fi
	# Hosts are told apart by their Ethernet source address. Captures on "any" (Linux cooked) or on
	# Wi-Fi have none, which leaves only the addresses inside ARP and DHCP.
	local other_links
	other_links=$(grep -cvx 1 "$workdir/encapsulations")
	if ((other_links)); then
		local encapsulation
		encapsulation=$(capinfos -E "$capture_file" 2> /dev/null | sed -nE 's/^File encapsulation: *//p')
		[[ $encapsulation == "Per packet" ]] && encapsulation="link types differ between packets"
		warn "$other_links of $packets packets in $capture_file have no Ethernet header (${encapsulation:-not Ethernet}), as in a capture on 'any' or on Wi-Fi. For those, only ARP and DHCP identify hosts: NetBIOS, mDNS, SSDP and TTL evidence is lost. A capture on 'any' also holds the traffic of this machine's other networks."
		confirm "Continue with what ARP and DHCP tell about those hosts?" ||
			stop_here "capture on the interface itself, e.g. dumpcap -i eth0"
	fi
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
	breakdown=$(describe_classes "$workdir/hosts")
	echo "[*] Fingerprints: ${breakdown:-none}"
	persona_count=0
	if [[ -n $forced_persona ]]; then
		persona=$forced_persona
		persona_count=$(awk -F'\t' -v p="$persona" '$4 == p' "$workdir/hosts" | wc -l)
		echo "[*] Persona forced with -p: $persona ($persona_count matching hosts seen)"
		return
	fi
	local counts tied
	counts=$(awk -F'\t' '$4 == "windows" || $4 == "macos" || $4 == "linux" { print $4 }' "$workdir/hosts" | sort | uniq -c | sort -nr)
	if [[ -z $counts ]]; then
		echo "[-] No workstation could be fingerprinted"
		confirm "Use the linux persona (keep this machine's network stack) and model nothing on the hosts seen?" ||
			stop_here "no workstation to imitate: $(more_traffic), or force a persona with -p"
		persona=linux
		return
	fi
	read -r persona_count persona <<< "$counts"
	# Equally common workstation types: the operator knows the network better than a coin toss
	mapfile -t tied < <(awk -v n="$persona_count" '$1 == n { print $2 }' <<< "$counts")
	if ((${#tied[@]} > 1)); then
		local listed="${tied[*]:0:${#tied[@]}-1}"
		echo "[-] ${listed// /, } and ${tied[-1]} are equally common ($persona_count hosts each)"
		local choice
		for choice in "${tied[@]}"; do
			if confirm "Use the $choice persona?"; then
				persona=$choice
				echo "[+] Persona: $persona ($persona_count hosts)"
				return
			fi
		done
		stop_here "no persona chosen. Force one with -p"
	fi
	echo "[+] Persona: $persona (most common workstation type, $persona_count hosts)"
	# Linux desktops and Macs that say little are "unknown": when they outnumber the persona's hosts, the
	# most common workstation type is not known
	local unknown
	unknown=$(awk -F'\t' '$4 == "unknown"' "$workdir/hosts" | wc -l)
	if ((unknown > persona_count)); then
		warn "$unknown hosts could not be fingerprinted (Linux desktops, quiet Macs, routers and appliances look alike), more than the $persona_count $persona hosts"
		confirm "Use the $persona persona all the same?" || stop_here "the most common workstation type is not known: force a persona with -p, or $(more_traffic)"
	fi
}

# Hosts of the persona, which the identity is modelled on
persona_filter() {
	awk -F'\t' -v p="$persona" '$4 == p' "$workdir/hosts"
}

# Names of the classes of a set of hosts, e.g. "3 mobile, 2 printer"
describe_classes() {
	awk -F'\t' '{ count[$4]++ } END { for (c in count) printf "%d %s\n", count[c], c }' "$@" | sort -nr |
		awk '{ printf "%s%d %s", (NR > 1 ? ", " : ""), $1, $2 }'
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
	# Only fingerprints that can be sent exactly as they were seen are copied: option codes 1-254, each
	# once, and a printable vendor class. Changing one to make it valid would make up a fingerprint no
	# host on the network has.
	local candidates learned
	candidates=$(persona_filter | awk -F'\t' '$6 != "" {
		valid = ($7 ~ /^[A-Za-z0-9 .:_\/-]*$/)
		n = split($6, codes, ",")
		delete seen
		for (i = 1; i <= n; i++) if (codes[i] !~ /^[0-9]+$/ || codes[i] + 0 < 1 || codes[i] + 0 > 254 || seen[codes[i]]++) valid = 0
		print (valid ? "valid" : "invalid") "\x1f" $6 "\x1f" $7 "\x1f" $8
	}')
	learned=$(grep '^valid' <<< "$candidates" | cut -d$'\x1f' -f2- | sort | uniq -c | top_entry)
	if [[ -n $learned ]]; then
		IFS=$'\x1f' read -r dhcp_prl dhcp_vendor_class dhcp_sends_fqdn <<< "$learned"
		dhcp_source="copied from $persona hosts on this network"
	else
		if [[ -n $candidates ]]; then
			echo "[-] The DHCP requests of the $persona hosts hold values that cannot be sent as they are (option codes outside 1-254, or unprintable vendor classes)"
		else
			echo "[-] No $persona host requested an address during the capture, so their DHCP fingerprint is unknown"
		fi
		confirm "Use the built-in $persona DHCP fingerprint (${BUILTIN_DESCRIPTION[$persona]})?" ||
			stop_here "no DHCP fingerprint: $(more_traffic). Machines request addresses when they start or join the network; chameleonic-probe.sh does not make them"
		dhcp_prl=${BUILTIN_PRL[$persona]}
		dhcp_vendor_class=${BUILTIN_VENDOR_CLASS[$persona]}
		dhcp_sends_fqdn=${BUILTIN_SENDS_FQDN[$persona]}
		dhcp_source="built-in $persona profile"
	fi
	# Keep only valid option codes and printable vendor classes, since both come from the network
	dhcp_prl=$(tr ',' '\n' <<< "$dhcp_prl" | grep -E '^[0-9]+$' | awk '$1 >= 1 && $1 <= 254 && !seen[$1]++' | paste -sd, -)
	dhcp_vendor_class=$(tr -cd '[:alnum:] .:_/-' <<< "$dhcp_vendor_class")
}

# TCP/IP settings that make the stack answer like the persona (TTL, TCP options, IPv6 addressing).
# Each identity gets a new IPv6 secret: random link-local addresses are derived from it, and would
# otherwise be the same for every identity applied since boot, linking them together.
persona_sysctls() {
	local rmem
	rmem=$(sysctl -n net.ipv4.tcp_rmem 2> /dev/null | awk '{ print $1, $2 }')
	case $persona in
		windows)
			# TTL 128, no TCP timestamps, window scale 8, random IPv6 interface IDs with temporary addresses
			echo "net.ipv4.ip_default_ttl=128"
			echo "net/ipv6/conf/$interface/hop_limit=128"
			echo "net.ipv4.tcp_timestamps=0"
			echo "net.ipv4.tcp_rmem=$rmem 12582912"
			echo "net/ipv6/conf/$interface/addr_gen_mode=3"
			echo "net/ipv6/conf/$interface/stable_secret=$(random_ipv6)"
			echo "net/ipv6/conf/$interface/use_tempaddr=2"
			;;
		macos)
			# TTL 64, TCP timestamps, window scale 6, random IPv6 interface IDs with temporary addresses
			echo "net.ipv4.ip_default_ttl=64"
			echo "net/ipv6/conf/$interface/hop_limit=64"
			echo "net.ipv4.tcp_timestamps=1"
			echo "net.ipv4.tcp_rmem=$rmem 3145728"
			echo "net/ipv6/conf/$interface/addr_gen_mode=3"
			echo "net/ipv6/conf/$interface/stable_secret=$(random_ipv6)"
			echo "net/ipv6/conf/$interface/use_tempaddr=2"
			;;
		linux)
			# The stack stays Linux's. Its link-local address follows the new MAC address by default
			# (addr_gen_mode 0); with stable privacy or no automatic address it would be derived from the
			# original secret, so it gets a new one.
			if [[ $(sysctl -n "net/ipv6/conf/$interface/addr_gen_mode" 2> /dev/null) =~ ^[123]$ ]]; then
				echo "net/ipv6/conf/$interface/addr_gen_mode=3"
				echo "net/ipv6/conf/$interface/stable_secret=$(random_ipv6)"
			fi
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
# A naming pattern is a template of the hostname: characters every name shares are kept, the others
# are replaced by their class: # digit, @ uppercase letter, % lowercase letter, * uppercase letter or
# digit, + lowercase letter or digit, ? any letter or digit. Hostnames never contain these symbols.

# Sets chars to the characters a template symbol stands for, or to nothing for a literal character.
# (A case rather than an associative array: bash before 5.1 rejects @ and * as array keys.)
template_chars() {
	case $1 in
		'#') chars=0123456789 ;;
		'@') chars=ABCDEFGHIJKLMNOPQRSTUVWXYZ ;;
		'%') chars=abcdefghijklmnopqrstuvwxyz ;;
		'*') chars=ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 ;;
		'+') chars=abcdefghijklmnopqrstuvwxyz0123456789 ;;
		'?') chars=ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 ;;
		*) chars="" ;;
	esac
}

template_legend() {
	case $1 in
		'#') echo "digit" ;;
		'@') echo "uppercase letter" ;;
		'%') echo "lowercase letter" ;;
		'*') echo "uppercase letter or digit" ;;
		'+') echo "lowercase letter or digit" ;;
		'?') echo "letter or digit" ;;
	esac
}

# Names a freshly installed machine gets, for networks that show no naming pattern
declare -A DEFAULT_TEMPLATE=([windows]='DESKTOP-*******' [macos]='MacBook-Pro-#')
declare -A DEFAULT_DESCRIPTION=([windows]='Windows default naming scheme' [macos]='macOS default naming scheme')
# Varying parts of the pattern that keep a value seen on the network, as "start:length" => values, and
# their kind (letters, digits, mixed)
declare -A pattern_reuse pattern_reuse_kind
# Values the other varying parts (counters) already have on the network, as "start:length:value" => 1
declare -A pattern_taken

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

# Template symbol for the characters seen at one position of the hostnames
char_class() {
	if [[ $1 =~ ^[0-9]+$ ]]; then
		echo '#'
	elif [[ $1 =~ ^[A-Z]+$ ]]; then
		echo '@'
	elif [[ $1 =~ ^[a-z]+$ ]]; then
		echo '%'
	elif [[ $1 =~ ^[A-Z0-9]+$ ]]; then
		echo '*'
	elif [[ $1 =~ ^[a-z0-9]+$ ]]; then
		echo '+'
	else
		echo '?'
	fi
}

# Work out the naming pattern of a list of hostnames: the hostnames that contain the most widely shared
# string, at its usual position and with the usual length, are compared character by character.
# Sets pattern_template, or returns 1 if there is no pattern.
find_pattern() {
	local -n names=$1
	pattern_template=""
	((${#names[@]} >= 3)) || { echo "[-] Fewer than 3 hostnames: not enough to find a naming pattern"; return 1; }

	# NetBIOS names are uppercase, while DHCP and mDNS keep the case a host was given, so one naming
	# scheme can arrive as lon-wks-0001 and LON-WKS-0040. Names are compared in the case most of them
	# use (uppercase on a tie, as NetBIOS does), unless most are mixed case, like Alices-MacBook-Pro.
	local -a folded=()
	local str upper=0 lower=0 mixed=0
	for str in "${names[@]}"; do
		if [[ $str == *[a-z]* && $str == *[A-Z]* ]]; then
			((++mixed))
		elif [[ $str == *[a-z]* ]]; then
			((++lower))
		else
			((++upper))
		fi
	done
	for str in "${names[@]}"; do
		if ((mixed * 2 > ${#names[@]})); then
			folded+=("$str")
		elif ((upper >= lower)); then
			folded+=("${str^^}")
		else
			folded+=("${str,,}")
		fi
	done

	local common
	common=$(find_largest_common folded)
	[[ -n $common ]] || { echo "[-] The hostnames share no common string: no naming pattern"; return 1; }

	local -a matching=() group=()
	local prefix full_length offset
	for str in "${folded[@]}"; do
		[[ $str == *"$common"* ]] && matching+=("$str")
	done
	full_length=$(for str in "${matching[@]}"; do echo "${#str}"; done | sort | uniq -c | top_entry)
	offset=$(for str in "${matching[@]}"; do
		((${#str} == full_length)) || continue
		prefix=${str%%"$common"*}
		echo "${#prefix}"
	done | sort | uniq -c | top_entry)
	for str in "${matching[@]}"; do
		prefix=${str%%"$common"*}
		((${#str} == full_length && ${#prefix} == offset)) && group+=("$str")
	done
	((${#group[@]} >= 3)) || {
		echo "[-] Only ${#group[@]} hostnames share the same layout ($(examples group)): not enough for a naming pattern"
		return 1
	}

	local i chars
	for ((i = 0; i < full_length; i++)); do
		chars=""
		for str in "${group[@]}"; do
			chars+=${str:i:1}
		done
		if [[ -z ${chars//"${chars:0:1}"/} ]]; then
			pattern_template+=${chars:0:1}
		else
			pattern_template+=$(char_class "$chars")
		fi
	done
	echo "[*] Naming pattern of ${#group[@]} of ${#names[@]} hostnames: $(describe_template "$pattern_template")"

	# The varying parts are split where letters give way to digits: a site code followed by a counter.
	# Letters (site, department, user codes) keep one of the values seen, as often as they are seen:
	# random letters would name a site or user that does not exist. Digits and mixed parts whose values
	# repeat (a floor) do the same; those that differ on every host (counters, service tags) are random,
	# without repeating a value another host has there: UK-MAN-LT00037 next to UK-LON-LT00037 would be a
	# duplicate asset number.
	pattern_reuse=()
	pattern_reuse_kind=()
	pattern_taken=()
	pattern_counters=()
	local start=-1 c kind segment_kind="" values distinct
	for ((i = 0; i <= full_length; i++)); do
		c=${pattern_template:i:1}
		template_chars "$c"
		case $c in
			'@' | '%') kind=letters ;;
			'#') kind=digits ;;
			*) kind=mixed ;;
		esac
		if [[ -n $chars && ($start -lt 0 || $kind == "$segment_kind") ]]; then
			((start < 0)) && start=$i segment_kind=$kind
			continue
		fi
		if ((start >= 0)); then
			values=$(for str in "${group[@]}"; do echo "${str:start:i-start}"; done)
			distinct=$(sort -u <<< "$values")
			if [[ $segment_kind == letters ]] || (($(wc -l <<< "$distinct") * 2 <= ${#group[@]})); then
				pattern_reuse[$start:$((i - start))]=$values
				pattern_reuse_kind[$start:$((i - start))]=$segment_kind
				echo "[*] ${pattern_template:start:i-start} at character $((start + 1)) keeps one of the values seen: $(paste -sd' ' <<< "$distinct" | cut -c1-60)"
			else
				pattern_counters+=("$start:$((i - start))")
				while read -r str; do
					pattern_taken[$start:$((i - start)):$str]=1
				done <<< "$distinct"
			fi
			start=-1
		fi
		# A symbol of another kind starts the next part right away
		if [[ -n $chars ]]; then
			start=$i
			segment_kind=$kind
		fi
	done
}

# The template followed by the meaning of its symbols, e.g. "LON-WKS-#### (#: digit)"
describe_template() {
	local template=$1 symbol legend=""
	for symbol in '#' '@' '%' '*' '+' '?'; do
		[[ $template == *"$symbol"* ]] && legend+="${legend:+, }$symbol: $(template_legend "$symbol")"
	done
	echo "$template${legend:+ ($legend)}"
}

template_matches() {
	local template=$1 name=$2 regex="" i c chars
	for ((i = 0; i < ${#template}; i++)); do
		c=${template:i:1}
		template_chars "$c"
		if [[ -n $chars ]]; then
			regex+="[$chars]"
		else
			regex+=$c
		fi
	done
	# Case is ignored, as find_pattern compares names in one case
	[[ $name =~ ^$regex$ || ${name^^} =~ ^$regex$ || ${name,,} =~ ^$regex$ ]]
}

# Sets generated to a random name following the template. With reuse set to 1, the parts of the
# naming pattern in pattern_reuse take one of the values seen.
generate_from_template() {
	local template=$1 reuse=$2 i c chars
	generated=""
	for ((i = 0; i < ${#template}; i++)); do
		c=${template:i:1}
		template_chars "$c"
		if [[ -n $chars ]]; then
			generated+=${chars:RANDOM % ${#chars}:1}
		else
			generated+=$c
		fi
	done
	((reuse)) || return 0
	local key start length values=()
	for key in "${!pattern_reuse[@]}"; do
		# reuse 2: letters only, so digits numbered per site (LON-PC-01, MAN-PC-01) give new numbers
		((reuse == 2)) && [[ ${pattern_reuse_kind[$key]} != letters ]] && continue
		start=${key%:*}
		length=${key#*:}
		mapfile -t values <<< "${pattern_reuse[$key]}"
		generated=${generated:0:start}${values[RANDOM % ${#values[@]}]}${generated:start+length}
	done
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

is_valid_hostname() {
	[[ $1 =~ ^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$ ]]
}

# Whether a varying part of the generated name has a value another host already has there
part_taken() {
	local segment start length
	for segment in "${pattern_counters[@]}"; do
		start=${segment%:*}
		length=${segment#*:}
		[[ -n ${pattern_taken[$segment:${generated:start:length}]} ]] && return 0
	done
	return 1
}

# Generate a name from the template that no host seen uses. Sets hostname_new, or returns 1.
# reuse=1 for the naming pattern found on the network (see generate_from_template).
hostname_from_template() {
	local template=$1 reuse=$2 attempt mode
	for ((attempt = 1; attempt <= MAX_HOSTNAME_ATTEMPTS; attempt++)); do
		# Half the attempts with every repeated part kept, then digits drawn anew: when every
		# combination of the values seen is taken, the digits are counters numbered per site
		mode=$reuse
		((reuse && attempt > MAX_HOSTNAME_ATTEMPTS / 2)) && mode=2
		generate_from_template "$template" "$mode"
		((reuse)) && part_taken && continue
		# macOS numbers the second Mac of a name -2, never -0 or -1
		[[ $template == "${DEFAULT_TEMPLATE[macos]}" && $generated == *-[01] ]] && continue
		if is_hostname_unique "$generated"; then
			hostname_new=$generated
			echo "[+] Hostname: $hostname_new (not used by any host seen)"
			return 0
		fi
	done
	echo "[-] Every name tried from $template is already in use ($MAX_HOSTNAME_ATTEMPTS attempts)"
	return 1
}

# Some examples of a list of names, e.g. "iPhone-0, iPhone-1, HP-Printer-0, ..."
examples() {
	local -n list=$1
	local out="" name
	for name in "${list[@]:0:4}"; do
		out+="${out:+, }$name"
	done
	((${#list[@]} > 4)) && out+=", ..."
	echo "$out"
}

# The hostname, from the first of these the operator accepts: the naming pattern of the persona's
# hosts, the pattern of all hosts seen, the persona's default naming scheme, a name typed in.
choose_hostname() {
	mapfile -t all_names < <(cut -f3 "$workdir/hosts" | grep -v '^$' | sort -uf)
	# NetBIOS cuts names to 15 characters: names heard only there, and that long, may be cut short
	local cut_short
	cut_short=$(awk -F'\t' '$9 == "netbios" && length($3) == 15' "$workdir/hosts" | wc -l)
	((cut_short)) && echo "[*] $cut_short hostnames heard only through NetBIOS may be cut to 15 characters: they are not used for the naming pattern"
	local -a pattern_names
	mapfile -t pattern_names < <(awk -F'\t' '$3 != "" && !($9 == "netbios" && length($3) == 15) { print $3 }' "$workdir/hosts" | sort -uf)
	if [[ -n $forced_hostname ]]; then
		hostname_new=$forced_hostname
		is_hostname_unique "$hostname_new" || confirm "Hostname $hostname_new (set with -H) is already used by a host seen on the network. Use it anyway?" ||
			stop_here "choose another hostname with -H"
		echo "[+] Hostname: $hostname_new (set with -H)"
		return
	fi
	local -a persona_names persona_cut
	mapfile -t persona_names < <(persona_filter | awk -F'\t' '$3 != "" && !($9 == "netbios" && length($3) == 15) { print $3 }' | sort -uf)
	mapfile -t persona_cut < <(persona_filter | awk -F'\t' '$9 == "netbios" && length($3) == 15 { print $3 }' | sort -uf)

	if ((${#persona_names[@]})); then
		echo "[*] Analysing ${#persona_names[@]} $persona hostnames: $(examples persona_names)"
		find_pattern persona_names && hostname_from_template "$pattern_template" 1 && return
	elif ((${#persona_cut[@]})); then
		echo "[-] The $persona hostnames seen ($(examples persona_cut)) may be cut to 15 characters by NetBIOS"
	else
		echo "[-] No $persona hostnames seen"
	fi

	# Another kind of host's pattern only fits if the persona's own hosts, if any, follow it
	if ((${#pattern_names[@]} > ${#persona_names[@]})); then
		echo "[*] Looking for a naming pattern across all ${#pattern_names[@]} hostnames seen"
		if find_pattern pattern_names; then
			local name fits=0
			for name in "${persona_names[@]}"; do
				template_matches "$pattern_template" "$name" && fits=1
			done
			# Names cut short by NetBIOS are compared on their first 15 characters
			for name in "${persona_cut[@]}"; do
				template_matches "${pattern_template:0:15}" "$name" && fits=1
			done
			if ((${#persona_names[@]} + ${#persona_cut[@]} && !fits)); then
				local -a persona_all=("${persona_names[@]}" "${persona_cut[@]}")
				echo "[-] The $persona hosts seen ($(examples persona_all)) do not follow it"
			else
				local -a following=()
				for name in "${pattern_names[@]}"; do
					template_matches "$pattern_template" "$name" && following+=("$name")
				done
				confirm "Name this machine after the pattern $(describe_template "$pattern_template") of $(examples following)?" &&
					hostname_from_template "$pattern_template" 1 && return
			fi
		fi
	fi

	if [[ -n ${DEFAULT_TEMPLATE[$persona]} ]]; then
		confirm "Use the ${DEFAULT_DESCRIPTION[$persona]} (${DEFAULT_TEMPLATE[$persona]//\*/X})?" &&
			hostname_from_template "${DEFAULT_TEMPLATE[$persona]}" && return
	fi

	((assume_yes)) && stop_here "no hostname to use: set one with -H"
	local answer
	while true; do
		answer=$(ask "Type a hostname to use, or press Enter to stop:") || exit 1
		[[ -n $answer ]] || stop_here "no hostname chosen. Set one with -H"
		if ! is_valid_hostname "$answer"; then
			echo "[-] A hostname has up to 63 letters, digits and hyphens, and does not start or end with a hyphen"
		elif ! is_hostname_unique "$answer"; then
			echo "[-] $answer is already used by a host seen on the network"
		else
			hostname_new=$answer
			echo "[+] Hostname: $hostname_new (chosen by the operator)"
			return
		fi
	done
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

# Most common vendor prefix (OUI) among the hosts read on stdin. Locally administered MACs (randomised
# by phones and recent Windows and macOS, or VMs) carry no vendor information and are ignored.
most_common_oui() {
	awk -F'\t' 'tolower(substr($1, 2, 1)) !~ /[26ae]/ { print substr($1, 1, 8) }' | sort | uniq -c | top_entry
}

# A MAC address that no host seen uses, from the vendor prefix, or locally administered without one
generate_mac() {
	local oui=$1 attempt
	for ((attempt = 1; attempt <= MAX_HOSTNAME_ATTEMPTS; attempt++)); do
		if [[ -n $oui ]]; then
			mac_new="$oui:$(printf "%02x:%02x:%02x" $((RANDOM % 256)) $((RANDOM % 256)) $((RANDOM % 256)))"
		else
			mac_new=$(printf "%02x:%02x:%02x:%02x:%02x:%02x" $(((RANDOM & 0xfc) | 0x02)) $((RANDOM % 256)) $((RANDOM % 256)) \
				$((RANDOM % 256)) $((RANDOM % 256)) $((RANDOM % 256)))
		fi
		grep -q "^$mac_new"$'\t' "$workdir/hosts" || break
	done
}

# The vendor prefix of the persona's hosts, or the first of these the operator accepts: a randomised
# MAC address if that is what the persona's hosts use, the most common vendor among all hosts seen,
# a random vendor.
choose_mac() {
	mac_vendor=""
	mac_oui=$(persona_filter | most_common_oui)
	if [[ -n $mac_oui ]]; then
		mac_vendor=$(vendor_of "$mac_oui")
		generate_mac "$mac_oui"
		echo "[+] MAC address: $mac_new ($mac_vendor, most common vendor among $persona hosts)"
		return
	fi

	if [[ -n $(persona_filter) ]]; then
		echo "[-] The $persona hosts seen all use randomised MAC addresses, which name no vendor"
		if confirm "Use a randomised (locally administered) MAC address too?"; then
			mac_vendor="randomised, no vendor"
			generate_mac ""
			echo "[+] MAC address: $mac_new (randomised, like the $persona hosts)"
			return
		fi
	else
		echo "[-] No $persona host seen to take a vendor from"
	fi

	local oui
	oui=$(most_common_oui < "$workdir/hosts")
	if [[ -n $oui ]]; then
		local users
		users=$(awk -F'\t' -v oui="$oui" 'substr($1, 1, 8) == oui' "$workdir/hosts" | describe_classes)
		if confirm "Use the most common vendor among all hosts seen, $(vendor_of "$oui") ($oui, used by $users)?"; then
			mac_vendor=$(vendor_of "$oui")
			generate_mac "$oui"
			echo "[+] MAC address: $mac_new ($mac_vendor, most common vendor among all hosts)"
			return
		fi
	fi

	if confirm "Use a random MAC address with a random vendor (macchanger -A)?"; then
		mac_new=""
		echo "[+] MAC address: random, with a random vendor"
		return
	fi
	stop_here "no MAC address chosen: $(more_traffic), or force a persona with -p"
}

################################################# Inbound firewall

# nftables rules that make unsolicited inbound traffic on the interface get the persona's answer:
# Windows Defender Firewall drops it silently, a Mac or Linux host with nothing listening answers
# with closed ports. Replies to our own traffic, DHCP, IPv6 neighbour discovery, IGMP and the allowed
# ports always get through.
firewall_rules() {
	local entry tcp=() udp=() ping=0
	for entry in ${allow_list//,/ }; do
		# nft reads numbers with a leading zero as octal: 0445 would be port 293
		[[ $entry =~ ^([0-9]+)(-([0-9]+))?(/.*)?$ ]] &&
			entry=$((10#${BASH_REMATCH[1]}))${BASH_REMATCH[3]:+-$((10#${BASH_REMATCH[3]}))}${BASH_REMATCH[4]}
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
		# Closed ports answer like a host with nothing listening; other ICMP and protocols are left to
		# the stack, which answers timestamps and unknown protocols the way Linux and macOS do
		echo "		meta l4proto tcp reject with tcp reset"
		echo "		meta l4proto udp reject"
	fi
	echo "	}"
	echo "}"
}

describe_firewall() {
	if ((!firewall)) && [[ $previous_firewall == dry ]]; then
		echo "the previous run's rules are loaded: applying asks whether to keep them"
	elif ((!firewall)) && [[ -n $previous_firewall ]]; then
		echo "removed (the previous run's rules)"
	elif ((!firewall)); then
		echo "unchanged"
	elif [[ $persona == windows ]]; then
		echo "unsolicited traffic silently dropped, like Windows Defender Firewall (allowed: ${allow_list:-nothing})"
	else
		echo "all ports answer as closed, hiding local listeners (allowed: ${allow_list:-nothing})"
	fi
}

# A previous run's inbound firewall is still loaded: a run without -f would remove it, and expose the
# listeners it hid. Asked rather than decided.
check_previous_firewall() {
	previous_firewall=""
	((firewall)) && return
	command -v nft > /dev/null 2>&1 && nft list table $FIREWALL_TABLE > /dev/null 2>&1 || return 0
	previous_firewall=yes
	# A dry run changes nothing, so it only says what applying would ask
	if ((dry_run)); then
		previous_firewall=dry
		return
	fi
	local previous
	previous=$(cat "$STATE_DIR/firewall" 2> /dev/null)
	if confirm "The previous run's inbound firewall is still loaded (allowed: ${previous:-nothing}). Keep it for the new identity?"; then
		firewall=1
		allow_list=$previous
		previous_firewall=""
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
	if firewall_rules | nft -f /dev/stdin 2> "$workdir/nft.log"; then
		# What a run after this one offers to keep
		printf '%s\n' "$allow_list" > "$STATE_DIR/firewall"
		echo "[*] Inbound firewall: $(describe_firewall)"
	else
		warn "Failed to load the inbound firewall rules ($(grep -v '^$' "$workdir/nft.log" | head -n1))"
		confirm_exposure "Bring $interface up without the inbound firewall, so unsolicited traffic gets Linux's answers?" ||
			stop_here "the inbound firewall could not be loaded"
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
		# Windows and macOS send a client identifier (option 61); Debian's dhclient does not
		[[ $persona == linux ]] || echo "send dhcp-client-identifier = hardware;"
		# dhclient would also send a DNS update of its own after getting an address, which Windows
		# clients do not (they use secure updates to Active Directory)
		echo "do-forward-updates false;"
		[[ -n $dhcp_vendor_class ]] && echo "send vendor-class-identifier \"$dhcp_vendor_class\";"
		if ((dhcp_sends_fqdn)); then
			echo "send fqdn.fqdn \"$fqdn\";"
			echo "send fqdn.encoded off;"
			echo "send fqdn.server-update off;"
		fi
		# macOS always sends a lease time and maximum message size
		if [[ $persona == macos ]]; then
			echo "send dhcp-lease-time 7776000;"
			echo "send dhcp-max-message-size 1500;"
		fi
		(IFS=,; echo "request ${names[*]};") | sed 's/,/, /g'
	} > "$DHCLIENT_CONF"
}

# Replace the 127.0.1.1 lines of /etc/hosts with the lines given (none removes them), where the first
# one was. The rest of the file stays as it is, including entries added during the engagement, and it is
# rewritten in place, keeping its ownership, permissions and bind mounts.
replace_hosts_line() {
	HOSTS_LINES=$1 awk '
		/^127\.0\.1\.1[[:space:]]/ { if (!done && ENVIRON["HOSTS_LINES"] != "") print ENVIRON["HOSTS_LINES"]; done = 1; next }
		{ print }
		END { if (!done && ENVIRON["HOSTS_LINES"] != "") print ENVIRON["HOSTS_LINES"] }' /etc/hosts > "$workdir/hosts.new" &&
		cat "$workdir/hosts.new" > /etc/hosts
}

# The original name stays on a line of its own, so the machine still resolves its name after a reboot,
# as itself rather than as an alias of the persona's
set_hosts_entry() {
	local lines="127.0.1.1"$'\t'"$hostname_new" original
	[[ -n $domain ]] && lines="127.0.1.1"$'\t'"$hostname_new.$domain"$'\t'"$hostname_new"
	original=$(state_get hostname_static)
	[[ -n $original && ${original,,} != "${hostname_new,,}" ]] && lines+=$'\n'"127.0.1.1"$'\t'"$original"
	replace_hosts_line "$lines"
}

apply_identity() {
	require_interface
	ip link set dev "$interface" down

	# MAC address
	local mac_before
	mac_before=$(current_mac)
	if [[ -n $mac_new ]]; then
		macchanger -m "$mac_new" "$interface" > "$workdir/macchanger.log" 2>&1
	else
		macchanger -A "$interface" > "$workdir/macchanger.log" 2>&1
	fi
	if [[ -n $mac_new && $(current_mac) != "$mac_new" ]] || [[ -z $mac_new && $(current_mac) == "$mac_before" ]]; then
		warn "Failed to set the MAC address of $interface ($(grep -v '^$' "$workdir/macchanger.log" | tail -n1))"
		local original=""
		[[ $(current_mac) == "$(state_get mac)" ]] && original=", its original address"
		confirm_exposure "Continue with the MAC address $interface has now, $(current_mac)$original?" ||
			stop_here "the MAC address could not be set"
	fi
	echo "[*] MAC address of $interface is now $(current_mac)"

	# Hostname, until the next reboot only, like the MAC address: after a reboot the original MAC address
	# with the persona's name would link the two identities
	hostname "$hostname_new" 2> "$workdir/hostname.log" ||
		stop_here "the hostname could not be set ($(head -n1 "$workdir/hostname.log"))"
	set_hosts_entry
	echo "[*] Hostname is now $(hostname) until the next reboot (the saved name is still $(hostnamectl --static 2> /dev/null))"

	# TCP/IP stack. A previous run's persona is undone first, so its settings do not outlive it.
	restore_sysctls "net/ipv6/conf/$interface/disable_ipv6"
	local setting failed=()
	# Only the interface that holds an address answers ARP for it, as Windows and macOS do. Otherwise
	# another interface on the same network answers for the new address with its own MAC address.
	while read -r setting; do
		[[ $setting == net/ipv6/* ]] && ! ipv6_present && continue
		[[ -n $setting ]] && { set_sysctl "${setting%%=*}" "${setting#*=}" || failed+=("${setting%%=*}"); }
	done < <(persona_sysctls; echo "net.ipv4.conf.all.arp_ignore=1"; echo "net.ipv4.conf.all.arp_announce=2")
	if ((${#failed[@]})); then
		confirm_exposure "Continue with a TCP/IP stack that is only partly $persona's (${failed[*]} could not be set)?" ||
			stop_here "the TCP/IP stack could not be set"
	fi
	echo "[*] TCP/IP stack: $(describe_stack)"
	apply_firewall
	sysctl -qw "net/ipv6/conf/$interface/disable_ipv6=$(state_get "sysctl:net/ipv6/conf/$interface/disable_ipv6")" > /dev/null 2>&1

	# DHCP
	ip link set dev "$interface" up
	mkdir -p "${DHCLIENT_CONF%/*}" "${DHCLIENT_LEASES%/*}"
	write_dhclient_conf
	echo "[*] Requesting an address with the $persona DHCP fingerprint ($dhcp_source)..."
	# A previous identity's lease would make dhclient ask for that identity's address, linking the two
	# in the DHCP server's log, or take it over unasked when no server answers
	: > "$DHCLIENT_LEASES"
	local attempt=1
	until dhclient -4 -1 -v -cf "$DHCLIENT_CONF" -lf "$DHCLIENT_LEASES" -pf "$DHCLIENT_PID" "$interface" > "$workdir/dhclient.log" 2>&1 {lock_fd}>&-; do
		warn "No DHCP lease obtained ($(grep -v '^$' "$workdir/dhclient.log" | tail -n1))"
		((attempt++ < 3)) && confirm "Request an address again?" && continue
		confirm "Keep the new identity on $interface without an IPv4 address (you can set one with 'ip addr add')?" && break
		stop_here "no address obtained"
	done
	ip_new=$(ip -4 -o addr show dev "$interface" | awk '{ print $4; exit }')
	[[ -n $ip_new ]] && echo "[+] Got address $ip_new"
	changing=0

	# The DHCP server is the most reliable source for the domain when none was seen in the capture
	if [[ -z $domain && -n $ip_new ]]; then
		# The first one if the server hands out several ("corp.example lab.example")
		domain=$(sed -nE 's/^ *option domain-name "([^" ]+).*/\1/p' "$DHCLIENT_LEASES" | tail -n1 | tr 'A-Z' 'a-z')
		if [[ -n $domain ]]; then
			set_hosts_entry
			echo "[+] DNS domain from DHCP: $domain"
		fi
	fi
	# NetworkManager (for its other interfaces) or a DHCP hook could have set the hostname back
	if [[ $(hostname) != "$hostname_new" ]]; then
		warn "The hostname changed to $(hostname) after chameleonic set it"
		confirm "Set it to $hostname_new again?" && hostname "$hostname_new"
	fi
	if [[ -n $ip_new ]]; then
		local others
		# Asking DNS only: /etc/hosts already has the new name
		others=$({
			getent -s dns ahostsv4 "$hostname_new"
			[[ -n $domain ]] && getent -s dns ahostsv4 "$hostname_new.$domain"
		} 2> /dev/null | awk '{ print $1 }' | sort -u | grep -v -e "^${ip_new%/*}$" -e '^127\.' | paste -sd' ' -)
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

# Something that could not be put back: noted, and the saved state is kept so -r can try again
restore_failed() {
	warn "Could not restore $*"
	not_restored+=("$*")
}

restore_identity() {
	[[ -f $STATE_FILE ]] || die "Nothing to restore: no saved identity in $STATE_DIR"
	interface=$(state_get interface)
	not_restored=()
	identity_failed=0
	echo "[*] Restoring the original identity of $interface"
	# A USB adapter unplugged, or a VLAN deleted, since the identity was applied
	local present=1
	if [[ ! -e /sys/class/net/$interface ]]; then
		present=0
		warn "$interface no longer exists"
		confirm "Restore the rest (hostname, TCP/IP stack, firewall, services) and forget what was saved for $interface? If it comes back, it has its own MAC address again" ||
			stop_here "connect or create $interface again, then run '$RESTORE_COMMAND'"
	fi

	if ((present)); then
		# A restore run again after one that stopped part way turned their binding back: VLANs that were
		# down would come up with the interface
		local name
		while read -r name; do
			[[ -n $name && -e /sys/class/net/$name ]] && ip link set dev "$name" type vlan loose_binding on 2> /dev/null
		done < <(state_get_all stacked_loose)
		# Down first, then a plain signal: "dhclient -x" would renew the persona's lease on its way out
		ip link set dev "$interface" down
		local pids
		pids=$(own_dhclient_pid) && stop_processes $pids && echo "[*] Stopped chameleonic's DHCP client"
		rm -f "$DHCLIENT_PID"
		pids=$(dhcp_client_pids)
		stop_processes $pids
		ip -4 addr flush dev "$interface"

		local mac_old
		mac_old=$(state_get mac)
		[[ -z $mac_old || $(current_mac) == "$mac_old" ]] || macchanger -m "$mac_old" "$interface" > /dev/null 2>&1
		if [[ -z $mac_old || $(current_mac) != "$mac_old" ]]; then
			restore_failed "the MAC address ${mac_old:-(not saved)}"
			identity_failed=1
		fi
		echo "[*] MAC address of $interface is now $(current_mac)"
		restore_sysctls
	else
		local pid
		pid=$(own_dhclient_pid) && stop_processes $pid
		rm -f "$DHCLIENT_PID"
		# systemd-networkd would ignore the interface when it comes back
		[[ -f $(networkd_file) ]] && rm -f "$(networkd_file)" && networkctl reload 2> /dev/null
		restore_sysctls "*/conf/$interface/*" "*.conf.$interface.*"
	fi
	local key
	for key in "${sysctl_failed[@]}"; do
		not_restored+=("$key")
	done
	echo "[*] Restored TCP/IP stack settings"

	# The persona's name was only set until the next reboot; identities applied by earlier versions of
	# chameleonic also changed the saved one
	local hostname_old hostname_static
	hostname_old=$(state_get hostname)
	hostname_static=$(state_get hostname_static)
	if ! state_has hostname_static; then
		hostnamectl set-hostname "$hostname_old" 2> /dev/null || restore_failed "the hostname $hostname_old"
	else
		[[ $(hostname) == "$hostname_old" ]] || hostname "$hostname_old" 2> /dev/null
		if [[ $(hostname) != "$hostname_old" ]]; then
			restore_failed "the hostname $hostname_old"
			identity_failed=1
		fi
		[[ -z $hostname_static || $(hostnamectl --static 2> /dev/null) == "$hostname_static" ]] ||
			hostnamectl set-hostname --static "$hostname_static" 2> /dev/null || restore_failed "the saved hostname $hostname_static"
	fi
	replace_hosts_line "$(grep '^127\.0\.1\.1[[:space:]]' "$STATE_DIR/hosts.bak")" || restore_failed "/etc/hosts"
	local resolv_link
	resolv_link=$(state_get resolv_link)
	if [[ -n $resolv_link && $(readlink /etc/resolv.conf) != "$resolv_link" ]]; then
		ln -sfn "$resolv_link" /etc/resolv.conf || restore_failed "the /etc/resolv.conf link"
	fi
	if [[ -f $STATE_DIR/resolv.conf.bak ]] && ! cmp -s "$STATE_DIR/resolv.conf.bak" /etc/resolv.conf; then
		cat "$STATE_DIR/resolv.conf.bak" > /etc/resolv.conf || restore_failed "/etc/resolv.conf"
	fi
	echo "[*] Hostname is now $(hostname), /etc/hosts and /etc/resolv.conf restored"

	if command -v nft > /dev/null 2>&1 && nft list table $FIREWALL_TABLE > /dev/null 2>&1; then
		nft delete table $FIREWALL_TABLE && echo "[*] Removed chameleonic's inbound firewall rules" ||
			restore_failed "the firewall (nftables table $FIREWALL_TABLE is still loaded)"
	fi

	if ((present)) && [[ $(state_get resolved) == yes ]] && command -v resolvectl > /dev/null 2>&1; then
		resolvectl revert "$interface" 2> /dev/null || restore_failed "LLMNR and mDNS in systemd-resolved on $interface"
	fi
	# Half an identity is worse than none: with the persona's MAC address and the original name, or the
	# other way round, the interface stays down and the services stopped, until -r can finish
	if ((identity_failed)); then
		warn "Not restored: $(IFS=';'; echo "${not_restored[*]}" | sed 's/;/; /g')"
		warn "$interface stays down and the services stay stopped, so the original name is not heard with the persona's MAC address"
		echo "[*] The saved identity is kept in $STATE_DIR: fix the cause and run '$RESTORE_COMMAND' again"
		return 1
	fi
	local service
	while read -r service; do
		[[ -n $service ]] && { systemctl unmask --runtime "$service" > /dev/null 2>&1 || restore_failed "$service (still masked)"; }
	done < <(state_get_all masked)
	while read -r service; do
		[[ -n $service ]] || continue
		if systemctl start "$service" 2> /dev/null; then
			echo "[*] Started $service"
		else
			restore_failed "$service (does not start)"
		fi
	done < <(state_get_all service)

	if ((present)); then
		restore_network
		local name
		# VLANs deleted since then (or created at run time and gone with a reboot) are only mentioned
		local line cidr route
		while read -r name; do
			[[ -n $name ]] || continue
			[[ -e /sys/class/net/$name ]] || { echo "[*] $name no longer exists: nothing to restore on it"; continue; }
			ip link set dev "$name" type vlan loose_binding off 2> /dev/null || restore_failed "$name (VLAN binding)"
		done < <(state_get_all stacked_loose)
		while read -r name; do
			[[ -n $name && -e /sys/class/net/$name ]] || continue
			ip link set dev "$name" up 2> /dev/null || restore_failed "$name (does not come up)"
		done < <(state_get_all stacked)
		while read -r line; do
			name=${line%% *}
			cidr=${line#* }
			[[ -e /sys/class/net/$name ]] || continue
			ip addr replace "$cidr" dev "$name" 2> /dev/null || restore_failed "the address $cidr on $name"
		done < <(state_get_all stacked_address)
		while read -r line; do
			name=${line%% *}
			route=${line#* }
			[[ -e /sys/class/net/$name ]] || continue
			ip -4 route replace $route dev "$name" 2> /dev/null || restore_failed "the route $route on $name"
		done < <(state_get_all stacked_route4)
		while read -r line; do
			name=${line%% *}
			route=${line#* }
			[[ -e /sys/class/net/$name ]] || continue
			ip -6 route replace $route dev "$name" 2> /dev/null || restore_failed "the route $route on $name"
		done < <(state_get_all stacked_route6)
		while read -r name; do
			[[ -n $name && -e /sys/class/net/$name ]] || continue
			nmcli device set "$name" managed yes 2> /dev/null || restore_failed "NetworkManager managing $name"
		done < <(state_get_all stacked_nm)
	fi
	if ((${#not_restored[@]})); then
		warn "Not restored: $(IFS=';'; echo "${not_restored[*]}" | sed 's/;/; /g')"
		echo "[*] The saved identity is kept in $STATE_DIR: fix the cause and run '$RESTORE_COMMAND' again"
		return 1
	fi
	rm -f "$DHCLIENT_CONF" "$DHCLIENT_LEASES" "$DHCLIENT_PID"
	rm -rf "$STATE_DIR"
	if ((present)); then
		echo "[+] Original identity restored"
	else
		echo "[+] Original identity restored, except $interface, which no longer exists"
	fi
}

# Hand the interface back to what configured it, bringing it up only if it was up
restore_network() {
	local mode
	mode=$(state_get network)
	[[ $(state_get link) == down && $mode != nm && $mode != networkd ]] || ip link set dev "$interface" up
	case $mode in
		nm)
			if nmcli device set "$interface" managed yes 2> /dev/null; then
				echo "[*] NetworkManager manages $interface again"
				local connection
				connection=$(state_get nm_connection)
				if [[ -n $connection && $(nm_device_state "$interface") != connected ]]; then
					nmcli connection up uuid "$connection" ifname "$interface" > /dev/null 2>&1 ||
						restore_failed "NetworkManager connection $connection on $interface"
				fi
			else
				restore_failed "NetworkManager managing $interface"
			fi
			;;
		networkd)
			rm -f "$(networkd_file)"
			if networkctl reload 2> /dev/null && networkctl reconfigure "$interface" 2> /dev/null; then
				echo "[*] systemd-networkd manages $interface again"
			else
				restore_failed "systemd-networkd managing $interface"
			fi
			;;
		dhclient)
			local command args=()
			while read -r command; do
				[[ -n $command ]] || continue
				read -ra args <<< "$command"
				setsid "${args[@]}" > /dev/null 2>&1 < /dev/null {lock_fd}>&- &
				echo "[*] Started the DHCP client again: $command"
			done < <(state_get_all dhcp_command)
			if [[ -z $(state_get dhcp_command) ]]; then
				# Identities applied by earlier versions of chameleonic did not save the command
				confirm "The saved identity does not say how the DHCP client on $interface was started. Start 'dhclient -4 -nw $interface'?" &&
					dhclient -4 -nw "$interface" > /dev/null 2>&1 {lock_fd}>&-
			fi
			;;
		static)
			local cidr route gateway
			while read -r cidr; do
				[[ -n $cidr ]] || continue
				ip addr replace "$cidr" dev "$interface" 2> /dev/null || restore_failed "the address $cidr"
			done < <(state_get_all address)
			while read -r route; do
				[[ -n $route ]] || continue
				ip -4 route replace $route dev "$interface" 2> /dev/null || restore_failed "the route $route"
			done < <(state_get_all route4)
			while read -r route; do
				[[ -n $route ]] || continue
				ip -6 route replace $route dev "$interface" 2> /dev/null || restore_failed "the route $route"
			done < <(state_get_all route6)
			# Identities applied by earlier versions of chameleonic saved only the gateway
			gateway=$(state_get gateway)
			[[ -n $gateway && -z $(state_get route4) ]] && ip route replace default via "$gateway" dev "$interface" 2> /dev/null
			echo "[*] Restored static addresses and routes on $interface"
			;;
	esac
	if [[ $(state_get nm_external) == yes ]]; then
		if nmcli device set "$interface" managed yes 2> /dev/null; then
			echo "[*] NetworkManager watches $interface again"
		else
			restore_failed "NetworkManager watching $interface"
		fi
	fi
	[[ $(state_get link) == down ]] && echo "[*] $interface is down, as it was"
}

################################################# Main logic

parse_args() {
	local positional=()
	listen_seconds=$LISTEN_SECONDS
	while (($#)); do
		case $1 in
			-t | --time | -p | --persona | -H | --hostname | -a | --allow | -x | --exclude)
				(($# >= 2)) || die "Option $1 needs a value"
				;;
		esac
		case $1 in
			-t | --time) listen_seconds=$2; time_given=1; shift 2 ;;
			-p | --persona) forced_persona=$2; shift 2 ;;
			-H | --hostname) forced_hostname=$2; shift 2 ;;
			-f | --firewall) firewall=1; shift ;;
			-a | --allow) allow_list=$2; firewall=1; shift 2 ;;
			-x | --exclude) exclude_list=$2; shift 2 ;;
			-n | --dry-run) dry_run=1; shift ;;
			-y | --yes) assume_yes=1; shift ;;
			-r | --restore) restore=1; shift ;;
			-h | --help) show_help; exit 0 ;;
			--) shift; positional+=("$@"); break ;;
			-*) show_help; die "Unknown option: $1" ;;
			*) positional+=("$1"); shift ;;
		esac
	done
	((${#positional[@]} <= 2)) || die "Too many arguments: ${positional[*]:2}"
	((dry_run && restore)) && die "-n and -r do not go together: -r changes the machine back, a dry run changes nothing"
	interface=${positional[0]}
	capture_file=${positional[1]}
	capture_given=$((${#positional[@]} == 2))
	[[ $listen_seconds =~ ^[1-9][0-9]*$ ]] || die "Listening time must be a number of seconds"
	[[ -z $forced_persona || $forced_persona =~ ^(windows|macos|linux)$ ]] || die "Persona must be windows, macos or linux"
	[[ -z $forced_hostname ]] || is_valid_hostname "$forced_hostname" ||
		die "Invalid hostname '$forced_hostname': up to 63 letters, digits and hyphens, not starting or ending with a hyphen"
	local entry port
	for entry in ${exclude_list//,/ }; do
		[[ $entry =~ ^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$ ]] || die "Invalid MAC address '$entry' in --exclude"
	done
	for entry in ${allow_list//,/ }; do
		[[ $entry == ping ]] && continue
		[[ $entry =~ ^([0-9]+)(-([0-9]+))?(/(tcp|udp))?$ ]] || die "Invalid --allow entry '$entry': use PORT, PORT-PORT, PORT/udp or ping"
		for port in ${entry//[^0-9]/ }; do
			((10#$port >= 1 && 10#$port <= 65535)) || die "Invalid port $port in --allow"
		done
		[[ -z ${BASH_REMATCH[3]} ]] || ((10#${BASH_REMATCH[1]} < 10#${BASH_REMATCH[3]})) || die "Invalid port range $entry in --allow: the first port must be lower"
	done
}

main() {
	parse_args "$@"
	workdir=$(mktemp -d)
	trap on_exit EXIT
	trap 'exit 130' INT
	# Killed or hung up (a dropped SSH session): still say what state the interface was left in
	trap 'exit 143' TERM
	trap 'exit 129' HUP
	if ((restore)); then
		require_root
		require_commands ip:iproute2 macchanger:macchanger sysctl:procps
		lock_run
		restore_identity
		return
	fi
	if [[ -z $interface ]]; then
		show_help
		die "No interface provided."
	fi
	capture_file=${capture_file:-./chameleonic-$interface-$(date +%Y%m%d-%H%M%S).pcapng}
	# A dry run on a capture only shows a plan, so it can run on another machine, without that interface
	if ((dry_run)) && [[ -s $capture_file && ! -d $capture_file ]]; then
		if [[ ! -e /sys/class/net/$interface ]]; then
			echo "[*] $interface does not exist here: showing the plan for the machine where it does"
		elif [[ $(cat "/sys/class/net/$interface/type") != 1 || -d /sys/class/net/$interface/wireless || -e /sys/class/net/$interface/phy80211 ]]; then
			echo "[*] $interface is not a wired Ethernet interface: chameleonic could not apply this plan to it"
		fi
	else
		[[ -e /sys/class/net/$interface ]] || die "This interface does not exist."
		[[ $(cat "/sys/class/net/$interface/type") == 1 ]] ||
			die "$interface is not an Ethernet interface (a VPN tunnel or loopback?): it has no MAC address to change"
		if [[ -d /sys/class/net/$interface/wireless || -e /sys/class/net/$interface/phy80211 ]]; then
			die "$interface is a wireless interface: chameleonic needs a wired interface, since NetworkManager and wpa_supplicant control the MAC address and association on Wi-Fi"
		fi
		[[ -e /sys/class/net/$interface/master ]] &&
			die "$interface is part of $(basename "$(readlink -f "/sys/class/net/$interface/master")") (a bridge or bond), which holds its address: run chameleonic on that one"
	fi
	have_capture=0
	if [[ -d $capture_file ]]; then
		die "$capture_file is a directory: give the path of a capture file"
	elif [[ -s $capture_file ]]; then
		[[ -r $capture_file ]] || die "Cannot read $capture_file"
		have_capture=1
	elif [[ -e $capture_file ]]; then
		confirm "$capture_file is empty. Listen for ${listen_seconds}s and save a new capture there instead?" ||
			stop_here "give the path of a capture that has packets in it"
	elif ((capture_given)); then
		confirm "$capture_file does not exist. Listen for ${listen_seconds}s and save a new capture there?" ||
			stop_here "check the path of the capture file"
	fi

	if ((dry_run && have_capture)); then
		require_commands tshark:tshark
	else
		require_root
		require_commands tshark:tshark
		((have_capture)) || require_commands dumpcap:wireshark-common
		((dry_run)) || require_commands ip:iproute2 macchanger:macchanger hostnamectl:systemd getent:libc-bin \
			dhclient:isc-dhcp-client sysctl:procps pgrep:procps
		((dry_run || !firewall)) || require_commands nft:nftables
		((dry_run)) || lock_run
		local saved_interface
		saved_interface=$(state_get interface)
		((dry_run)) || [[ -z $saved_interface || $saved_interface == "$interface" ]] ||
			die "An identity is already applied to $saved_interface. Run '$RESTORE_COMMAND' first."
	fi
	((have_capture && time_given)) && warn "-t has no effect: $capture_file exists, so chameleonic analyses it instead of listening"
	if [[ -e /sys/class/net/$interface ]]; then
		check_parent_interface
		check_stacked_interfaces
		check_dhcpcd
	fi
	check_tshark
	((have_capture)) || check_capture_path
	own_macs="$(current_mac) $(state_get mac) ${exclude_list//,/ }"

	if ((!have_capture)); then
		if ((dry_run)); then
			echo "[*] Dry run: listening with the current identity of $interface, nothing is changed"
		else
			take_over_interface
			if ! macchanger -A "$interface" > /dev/null 2>&1 || [[ $(current_mac) == "$(state_get mac)" ]]; then
				warn "Failed to set a temporary random MAC address"
				confirm "Listen with the original MAC address $(current_mac)? Listening sends nothing, but the capture records it" ||
					stop_here "no temporary MAC address"
			fi
			echo "[*] MAC address for listening: $(current_mac)"
			own_macs+=" $(current_mac)"
			ip link set dev "$interface" up
		fi
		listen_passively
	fi

	analyse_capture
	[[ -s $workdir/hosts ]] || warn "No hosts found in the capture ($(more_traffic) for better results)"
	print_hosts
	choose_persona
	choose_domain
	choose_hostname
	choose_mac
	choose_dhcp_fingerprint
	check_previous_firewall
	print_plan

	if ((dry_run)); then
		# The random parts are drawn again when the identity is applied
		echo "[*] Applying draws the hostname's random characters and the MAC address's last bytes again${forced_hostname:+ (the hostname set with -H stays)}"
		[[ -z $forced_hostname ]] && echo "[*] To apply this hostname, pass -H $hostname_new"
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
