# This script is used to decode network bytes into protocol fields

Exemplo de Uso:

```
PS C:\Python Scripts\network_bytes_decoder> python3.10.exe .\network_bytes_decoder.py

ETHERNET

SRC MAC: 00:0d:60:00:0c:29
DST MAC: 00:0c:29:06:1f:db
Ether_Type: IPv4
SRC MAC VENDOR: IBM Corp
DST MAC VENDOR: {"errors":{"detail":"Too Many Requests","message":"Please slow down your requests or upgrade your plan at https://macvendors.com"}}

L3 - IPv4

IP IHL: 5
IP_header: 4500002c000040004006b8cec0a80017c0a80096 - size: 40
IP Version: 4
IP TOS: 00
IP TOTAL LENGTH: 002c
IP IDENTIFICATION: 0000
IP FLAGS: 010
IP FRAGMENT OFFSET: 0000000000000
IP TTL: 64
IP PROTOCOL: 06
IP HEADER CHECKSUM: b8ce
IP SRC: 192.168.0.23
IP DST: 192.168.0.150

L4 - TCP

TCP HEADER LENGTH: 6
TCP HEADER: 0050c1001a4f8778efba215a601272102fdb0000020405b4 Size: 48
TCP SRC PORT: 80
TCP DST PORT: 49408
TCP SEQ NUM: 441419640
TCP ACK NUM: 4021952858
TCP BITS TEMP: 000000010010
TCP RESERVED BITS: 000000
TCP FLAGS: URG False, ACK True, PSH False, RST False, SYN True, FIN False
TCP WINDOW SIZE: 29200
```
TCP CHECKSUM: 29200
TCP URGENT POINTER: 0
