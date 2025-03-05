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

# After the largest most common string is found, check the length of all hostnames containing it and return the most common length 
find_length_of_hostnames_with_most_common_string() {
	largest_common_length=$(printf "%s\n" "${names[@]}" | grep $1 | awk '{print length}' | sort | uniq -c | sort -nr | head -n1 | awk '{print $2}')
	echo $largest_common_length
}

# Function to classify character types
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

# Function to generate random characters based on type
generate_random_chars() {
	local length="$1"
	case "$most_common_type" in
		"Digits only") chars="0123456789" ;;
		"Uppercase letters only") chars="ABCDEFGHIJKLMNOPQRSTUVWXYZ" ;;
		"Lowercase letters only") chars="abcdefghijklmnopqrstuvwxyz" ;;
		"Alphanumeric (letters only, both cases)") chars="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz" ;;
		"Alphanumeric (digits + uppercase)") chars="ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" ;;
		"Alphanumeric (digits + lowercase)") chars="abcdefghijklmnopqrstuvwxyz0123456789" ;;
		"Alphanumeric (digits + both cases)") chars="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" ;;
	*) chars="ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz" ;; # Fallback for mixed characters
	esac
	tr -dc "$chars" < /dev/urandom | head -c "$length"
}

# Hostname generation
generate_new_hostname(){
	names=$(cat "$bettercap_file" | grep "detected as" | awk -F'detected as' '{print $1}' | grep -oP '\(\K[^\)]*' | cut -d '.' -f 1 | sort -uf)
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
			echo "[*] Largest most common string: $largest_common"
			largest_common_full_hostname_length=$(find_length_of_hostnames_with_most_common_string $largest_common)
			echo "[*] Most common length of hostnames containing $largest_common is $largest_common_full_hostname_length"
			# Extract remaining parts
			remaining_parts=()
			hostnames_with_common_string=$(echo $names | tr ' ' '\n' | grep $largest_common)
			IFS=$'\n' read -r -d '' -a hostnames_with_common_string_array <<< "$hostnames_with_common_string"
			for str in "${hostnames_with_common_string_array[@]}"; do
				remaining_parts+=("${str:((${#largest_common}))}")
			done
			# Find the most common character type in remaining substrings
			declare -A char_type_count
			for part in "${remaining_parts[@]}"; do
				type="$(classify_chars "$part")"
				((char_type_count["$type"]++))
			done
			most_common_type="$(printf "%s\n" "${!char_type_count[@]}" | sort -nr -k2 | head -n1 | sed 's/ [0-9]*$//')"
			echo "[*] Most common characters type in remaining substrings: $most_common_type"
			# Determine the length of the most common remaining substring
			remaining_length=$(($largest_common_full_hostname_length-${#largest_common}))
			echo "[*] Remaining characters to fill: $remaining_length"
			# Generate a new serial with the common prefix and random characters of the same type
			random_part=$(generate_random_chars $((remaining_length)))
			hostname_new="$largest_common$random_part"
		fi
	fi
}

is_hostname_unique() {
    local hostname="$1"
    if nslookup "$hostname" >/dev/null 2>&1; then
        return 1  # Hostname exists, return failure
    else
        return 0  # Hostname is unique, return success
    fi
}

get_unique_hostname() {
    while :; do
        generate_new_hostname  # Generate a new hostname
        echo "[*] Checking if hostname '$hostname_new' is not in use..."
        if is_hostname_unique "$hostname_new"; then
            echo "[+] Hostname '$hostname_new' is not in use!"
            break
        else
            echo "[*] Hostname '$hostname_new' is already in use, generating a new one..."
        fi
    done
}

################################################# Main logic

# MAC generation
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

get_unique_hostname
hostname_old=$(hostnamectl hostname)

# Removing past hostname from DNS cache and configure the new one 
sed -i "/$hostname_old/d" /etc/hosts
echo "[*] Assigning hostname: $hostname_new"
hostnamectl set-hostname "$hostname_new"
echo "127.0.1.1	$hostname_new" >> /etc/hosts
echo "[*] Enabling interface $interface"
ifconfig $interface up
echo "[*] Done"
