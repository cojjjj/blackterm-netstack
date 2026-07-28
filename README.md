# BLACKTERM // NETSTACK

A userspace network stack written in C from first principles.

BLACKTERM // NETSTACK explores how modern networking works below the socket API by implementing network protocols directly from their wire formats.

## Current Architecture

```text
Application
     |
     v
+------------+
|    TCP     |  planned
+------------+
      |
+------------+
|    UDP     |  planned
+------------+
      |
+------------+
| IPv4/ICMP  |  planned
+------------+
      |
+------------+
|    ARP     |  planned
+------------+
      |
+------------+
|  Ethernet  |  in development
+------------+
      |
      v
Linux interface / TUN/TAP / raw packet I/O
