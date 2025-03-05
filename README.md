# chameleonic
Script to help with blending into a network environment.

Scans the local network using bettercap in order to identify devices, mainly for their MAC addresses and hostnames. 

Uses this information to identify the most common vendor and assign a MAC address similar to most of the network devices. If not enough data was collected, will assign a random MAC.

Does a simple search for the most common largest string present among hostnames checks the most common length of the hostnames containing that common string, and figures out the predominant type of characters within the remaining, unique hostname substring. Then generates a new hostname using this information or 'unknown' if not enough data was collected from the network or no conclusive pattern could be extracted.

Usage:

```
sudo ./chameleonic.sh <interface> <bettercap_file>
```
If you do not currently have a bettercap output file, chameleonic will generate one with `bettercap -no-colors -iface $interface -eval "net.probe on; sleep 30; q" > "$bettercap_file"`.
If you already have a file, specify it into <bettercap_file> and chameleonic will use this one as inspiration for hostnames / MAC addresses.
