from scapy.all import *

# Utwórz pakiet DHCP Discover
dhcp_discover = Ether(dst="ff:ff:ff:ff:ff:ff")/IP(src="0.0.0.0", dst="255.255.255.255")/UDP(sport=68, dport=67)/BOOTP(chaddr="00:11:22:33:44:55", xid=0x01020304)/DHCP(options=[("message-type", "discover"), "end"])

# Wyślij pakiet DHCP Discover
sendp(dhcp_discover, iface="enp0s3")