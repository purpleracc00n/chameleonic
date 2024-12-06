#!/bin/bash
################################################# Run checks
# Show help
show_help() {
	echo "[*] Usage: sudo chameleonic.sh <interface> <bettercap_file>"
}

if ! [ $(id -u) = 0 ]; then
	echo "[-] Run this as root!"
	exit 1
fi
interface=$1
bettercap_file=$2
if [ "$interface" == "" ]; then
	echo "[-] No interface provided."
	show_help
	exit
fi
if [ "$bettercap_file" == "" ]; then
	echo "[-] No bettercap file path provided."
	show_help
	exit
fi
interface_up=$(ip a show "$interface" up 2>&1)
if [[ $interface_up == *"does not exist."* ]]; then
	echo "[-] This interface does not exist."
	exit
elif [[ -z $interface_up ]]; then
	echo "[-] This interface is not up."
	exit
fi

################################################# Functions

# Function to find substrings of a given string
find_substrings() {
    local str=$1
    local length=${#str}
    substrings=()

    for ((i=0; i<length; i++)); do
        for ((j=i+3; j<=length; j++)); do  # Substrings must be at least 3 characters long
            substr="${str:i:j-i}"
            substrings+=("$substr")
        done
    done

    echo "${substrings[@]}"
}

# Function to find the largest, most common substring based on the new criteria
find_largest_common() {
    local -n arr=$1
    local -A substring_count
    local largest_common=""
    local max_count=0

    # Generate substrings for all strings and count occurrences
    for str in "${arr[@]}"; do
        substrings=($(find_substrings "$str"))
        for substr in "${substrings[@]}"; do
            ((substring_count["$substr"]++))
        done
    done

    # Find the substring that meets the criteria
    for substr in "${!substring_count[@]}"; do
        local count=${substring_count["$substr"]}
        local length=${#substr}

        # Check if the substring meets the criteria (occurs in at least 3 names, is at least 3 chars long)
        local occurrence=0
        for str in "${arr[@]}"; do
            if [[ $str == *"$substr"* ]]; then
                ((occurrence++))
            fi
        done

        if ((occurrence >= 3 && length >= 3)); then
            # Prioritize occurrence first, then length
            if ((count > max_count || (count == max_count && length > ${#largest_common}))); then
                max_count=$count
                largest_common=$substr
            fi
        fi
    done

    echo "$largest_common"
}

################################################# Main logic

# MAC stuff
if ! [ -e $bettercap_file ]; then
	echo "[*] Running network reconnaissance using ARP and reverse DNS..."
	bettercap -no-colors -iface $interface -eval "net.probe on; sleep 30; q" > "$bettercap_file"
fi
echo "[*] Disabling interface $interface"
ifconfig $interface down
mostcommonvendor=$(cat "$bettercap_file" | grep "detected as" | rev | cut -d'(' -f1 | rev | cut -d')' -f1 | sort | uniq -c | sort -nr | head -n1 | cut -c 9-)

if [[ ! -z $mostcommonvendor ]]; then
	echo "[*] Most common hardware vendor on the network is $mostcommonvendor"
	mostcommonvendor_MAC=$(cat "$bettercap_file" | grep "detected as"| grep "$mostcommonvendor" | awk -F'detected as' '{print $2}' | cut -d " " -f 2 | sort -uf | cut -c1-8 | sort | uniq -c | sort -nr | head -n 1 | cut -c9- )
	macrandomsegment=$(printf "%02x:%02x:%02x" $((RANDOM%256)) $((RANDOM%256)) $((RANDOM%256)))
	macchanger -m "$mostcommonvendor_MAC:$macrandomsegment" $interface >/dev/null 2>&1
	echo "[*] Set new MAC address on eth3: $mostcommonvendor_MAC:$macrandomsegment ($mostcommonvendor)"
else
	echo "[*] Not enough hostnames identified... will assign a random MAC address"
	macchanger -A $interface >/dev/null 2>&1
fi

# Hostname stuff
names=$(cat "$bettercap_file" | grep "detected as" | awk -F'detected as' '{print $1}' | grep -oP '\(\K[^\)]*' | sort -uf)
names_count=$(echo $names | wc -w)
if (( $names_count < 3 )); then
	echo "[-] Not enough hostnames identified... will assign hostname 'unknown'"
	hostname_new="unknown"
else
	echo "[*] Found $names_count computers, analysing names..."
	IFS=$'\n' read -r -d '' -a names_array <<< "$names"
	largest_common=$(find_largest_common names_array)
	if [ -z "$largest_common" ]; then
		echo "[-] Could not find a reliable hostname pattern... will assign hostname 'unknown'"
		hostname_new="unknown"
	else
		echo "[*] Largest Most Common String: $largest_common"

		while true
		do
			random_number=$((RANDOM % 999 + 1))
			hostname_new="$largest_common$random_number"
			if [[ ! ${names_array[@]} =~ $hostname_new ]]; then
				break
			fi
		done
	fi
fi
hostname_old=$(hostnamectl hostname)

# Removing past hostname from DNS cache and configure the new one 
sed -i "/$hostname_old/d" /etc/hosts
echo "[*] Assigning hostname: $hostname_new"
hostnamectl set-hostname "$hostname_new"
echo "127.0.1.1	$hostname_new" >> /etc/hosts
ifconfig eth3 up
echo "[*] Enabling interface $interface"
ifconfig $interface up
echo "[*] Done"
