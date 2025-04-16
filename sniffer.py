import socket
import struct

def mac_format(mac_bytes):
    return ':'.join('%02x' % b for b in mac_bytes)

def main():
    # Create a raw socket and bind it to all interfaces
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    print("Listening for packets... (Ctrl+C to stop)\n")

    while True:
        raw_data, addr = conn.recvfrom(65535)
        dest_mac, src_mac, proto = struct.unpack('!6s6sH', raw_data[:14])
        print(f"Destination: {mac_format(dest_mac)}, Source: {mac_format(src_mac)}, Protocol: {proto}")

if __name__ == "__main__":
    main()
