import os
import requests

# Functions
# format MAC
def format_mac(mac):
    n = 2
    list_mac = [mac[i:i+n] for i in range(0, len(mac), n)]
    return ":".join(list_mac)


# Convert Hex IP to dotted decimal
def convert_ip_hex_dec(ip_hex):
    n = 2
    octets = [ip_hex[i:i+n] for i in range(0, len(ip_hex), n)] 
    return ".".join([str(int(i, 16)) for i in octets])

# Ler arquivo bytes (em hexa) TXT
file = "bytes4.txt"

with open(file, "r") as f:
    bytes = f.read()

# Remover espaços
bytes = bytes.replace(" ", "")

# Remover new line \n
bytes = bytes.replace("\n", "")

# print(bytes)

# Split bytes Ethernet
print("\nETHERNET\n")
ether_header = bytes[0:28]

## Identicar campos Ethernet:
## MAC ORIGEM
src_mac = ether_header[0:12]
print(f"SRC MAC: {format_mac(src_mac)}")

## MAC DESTINO
dst_mac = ether_header[12:24]
print(f"DST MAC: {format_mac(dst_mac)}")

## ETHER PROTOCOLO

common_ether_type = {
    "0800": "IPv4",
    "0806": "ARP",
    "86DD": "IPv6"
}

ether_type = ether_header[24:]
print(f"Ether_Type: {common_ether_type[ether_type]}")

## LOOKUP MAC VENDOR

def mac_lookup_vendor(mac):
    url = "https://api.macvendors.com/"
    try:
        resp = requests.get(f"{url}/{mac}")
        return resp.text
    except Exception as e:
        print(f"Error: {e}")

print(f"SRC MAC VENDOR: {mac_lookup_vendor(src_mac)}")
print(f"DST MAC VENDOR: {mac_lookup_vendor(dst_mac)}")

# Split bytes IP

if common_ether_type[ether_type].lower() == "ipv4":
    print("\nL3 - IPv4\n")
    ip_ihl = bytes[29:30] # ip_header[1]
    print(f"IP IHL: {ip_ihl}")
    # Size of IP header (usualy 20 bytes - 40 hex characters)
    ip_header_end = 28 + int(ip_ihl) * 8
    ip_header = bytes[28:ip_header_end]
    print(f"IP_header: {ip_header} - size: {len(ip_header)}" )
    ip_version = ip_header[0]
    print(f"IP Version: {ip_version}")
    ip_tos = ip_header[2:4]
    print(f"IP TOS: {ip_tos}")
    ip_total_length = ip_header[4:8]
    print(f"IP TOTAL LENGTH: {ip_total_length}")
    ip_identification = ip_header[8:12]
    print(f"IP IDENTIFICATION: {ip_identification}")
    ip_line2_temp = ip_header[12:16]
    # convert hex to bin
    ip_line2_temp_bin = format(int(ip_line2_temp, 16), '0>18b')[2:]
    ip_flags = ip_line2_temp_bin[:3]
    print(f"IP FLAGS: {ip_flags}")  
    ip_fragment_offset = ip_line2_temp_bin[3:]
    print(f"IP FRAGMENT OFFSET: {ip_fragment_offset}")  
    ip_ttl = ip_header[16:18]
    print(f"IP TTL: {int(ip_ttl, 16)}")  
    ip_protocol = format(int(ip_header[18:20], 16), '0>2')
    print(f"IP PROTOCOL: {ip_protocol}")  
    ip_header_checksum = ip_header[20:24]
    print(f"IP HEADER CHECKSUM: {ip_header_checksum}") 
    ip_src = ip_header[24:32]
    print(f"IP SRC: {convert_ip_hex_dec(ip_src)}") 
    ip_dst = ip_header[32:40]
    print(f"IP DST: {convert_ip_hex_dec(ip_dst)}") 
else: 
    print(f"Ether Type {common_ether_type[ether_type]} not defined")

common_ip_proto = {
    "06": "tcp",
    "17": "udp",
    "01": "icmp"
}
# Split bytes TCP
if common_ip_proto[ip_protocol].lower() == "tcp":
    print("\nL4 - TCP\n")
    tcp_header_start = ip_header_end
    tcp_header_temp = bytes[tcp_header_start:]
    tcp_header_length = int(tcp_header_temp[24], 16)
    print(f'TCP HEADER LENGTH: {tcp_header_length}')
    # (tcp header length * 4 bytes) * 2 hex character
    tcp_header_end = tcp_header_start + ((tcp_header_length * 4) * 2)
    tcp_header = bytes[tcp_header_start:tcp_header_end]
    print(f'TCP HEADER: {tcp_header} Size: {len(tcp_header)}')
    tcp_src_port = int(tcp_header[0:4], 16)
    print(f'TCP SRC PORT: {tcp_src_port}')
    tcp_dst_port = int(tcp_header[4:8], 16)
    print(f'TCP DST PORT: {tcp_dst_port}')
    tcp_seq_num = int(tcp_header[8:16], 16)
    print(f'TCP SEQ NUM: {tcp_seq_num}')
    tcp_ack_num = int(tcp_header[16:24], 16)
    print(f'TCP ACK NUM: {tcp_ack_num}')
    # tcp_header_length = int(tcp_header_temp[24], 16)
    tcp_bits_temp = format(int(tcp_header[25:28], 16), '0>14b')[2:]
    print(f'TCP BITS TEMP: {tcp_bits_temp}')
    tcp_reserved_bits = tcp_bits_temp[0:6]
    print(f'TCP RESERVED BITS: {tcp_reserved_bits}')
    urg, ack, psh, rst, syn, fin = tcp_bits_temp[6:12]
    print(f'TCP FLAGS: URG {bool(int(urg))}, ACK {bool(int(ack))}, PSH {bool(int(psh))}, RST {bool(int(rst))}, SYN {bool(int(syn))}, FIN {bool(int(fin))}')
    tcp_window_size = int(tcp_header[28:32], 16)
    print(f'TCP WINDOW SIZE: {tcp_window_size}')
    tcp_checksum = int(tcp_header[32:36], 16)
    print(f'TCP CHECKSUM: {tcp_window_size}')
    tcp_urgent_pointer = int(tcp_header[36:40], 16)
    print(f'TCP URGENT POINTER: {tcp_urgent_pointer}')

    if len(tcp_header) > 64:
        tcp_options = tcp_header[40:]
        print(f'TCP HEX OPTIONS: {tcp_options}')

    if bool(int(psh)):
        # Split bytes payload
        payload_start = bytes[tcp_header_end:]
        print('\nPAYLOAD\n')
        print(f'{bytearray.fromhex(payload_start).decode()}')
elif common_ip_proto[ip_protocol].lower() == "udp":
    print("\nL4 - UDP\n")
    udp_header_length = 8 # bytes
    udp_header_start = ip_header_end
    udp_header_end = udp_header_start + ((udp_header_length) * 2)
    udp_header = bytes[udp_header_start:udp_header_end]
    print(f'UDP HEADER: {udp_header} Size: {len(udp_header)}')
    udp_src_port = udp_header[0:4]
    print(f'UDP SRC PORT: {int(udp_src_port, 16)}')
    udp_dst_port = udp_header[4:8]
    print(f'UDP DST PORT: {int(udp_dst_port, 16)}')
    udp_length = udp_header[8:12]
    print(f'UDP LENGTH: {int(udp_length, 16)}')
    udp_checksum = udp_header[8:16]
    print(f'UDP CHECKSUM: {int(udp_checksum, 16)}')
    if len(bytes) > udp_header_end:
        # Split bytes payload
        payload_start = bytes[udp_header_end:]
        print('\nPAYLOAD\n')
        print(f'{bytearray.fromhex(payload_start).decode()}')
else: 
    print(f"IP Protocol {common_ip_proto[ip_protocol]} not defined")


