#!/bin/bash
interface=$1
if [ "$interface" == "" ]; then
	echo "[-] No interface provided."
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

echo "[*] Running network reconnaissance using ARP and reverse DNS..."
bettercap -iface $interface -eval "net.probe on; sleep 30; q" > bettercap_network_recon2.txt
echo "[*] Disabling interface $interface"
ifconfig $interface down
mostcommonvendor=$(cat bettercap_network_recon2.txt | grep "detected as" | rev | cut -d'(' -f1 | rev | cut -d')' -f1 | sort | uniq -c | sort -nr | head -n1 | cut -d' ' -f7-)
echo "[*] Most common hardware vendor on the network is $mostcommonvendor"
macaddvendor=$(sudo macchanger -l | grep "$mostcommonvendor" | cut -d ' ' -f 3 | shuf -n 1)
macrandomsegment=$(printf "%02x:%02x:%02x" $((RANDOM%256)) $((RANDOM%256)) $((RANDOM%256)))
macchanger -m "$macaddvendor:$macrandomsegment" $interface >/dev/null 2>&1
echo "[*] Set new MAC address on eth3: $macaddvendor:$macrandomsegment ($mostcommonvendor)"

names=$(cat bettercap_network_recon.txt | grep "detected as" | awk -F'detected as' '{print $1}' | grep -oP '\(\K[^\)]*' | sort -uf)
echo "[*] Found $(echo $names | wc -w) computers, analysing names..."
IFS=$'\n' read -r -d '' -a names_array <<< "$names"

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
largest_common=$(find_largest_common names_array)
echo "[*] Largest Most Common String: $largest_common"

while true
do
	random_number=$((RANDOM % 999 + 1))
	hostname_new="$largest_common$random_number"
	if [[ ! ${names_array[@]} =~ $hostname_new ]]; then
		break
	fi
done
echo "[*] Assigning hostname: $hostname_new"
hostnamectl set-hostname "$hostname_new"
echo "127.0.1.1	$hostname_new" >> /etc/hosts
ifconfig eth3 up
echo "[*] Enabling interface $interface"
ifconfig $interface up
echo "[*] Done"
