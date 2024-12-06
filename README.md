# chameleonic
Script to help with blending into a network environment.

Scans the local network using bettercap (ARP and reverse DNS) in order to identify devices, mainly for their MAC addresses and hostnames. 

Uses this information to identify the most common vendor and assign a MAC address similar to most of the network devices.

Does a simple search for the most common largest string present among hostnames and assigns a new hostname of the form <most_common_largest_string><number from 1-999> or 'unknown' if not enough data was collected from the network, or no conclusive pattern could be extracted.

Usage:

```
sudo ./chameleonic.sh <interface> <bettercap_file>
```
