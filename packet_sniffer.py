
import socket
import struct
import logging
import argparse
from collections import Counter
from datetime import datetime


LOG_FILE = "network_log.txt"

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)


class NetworkPacketSniffer:

    def __init__(self):
        self.packet_count = 0
        self.protocol_stats = Counter()
        self.running = True

    def parse_ipv4(self, packet):
        if len(packet) < 20:
            return None

        version_ihl = packet[0]
        version = version_ihl >> 4
        ihl = (version_ihl & 0x0F) * 4

        if version != 4 or ihl < 20 or len(packet) < ihl:
            return None

        total_length = struct.unpack("!H", packet[2:4])[0]
        protocol = packet[9]

        source_ip = socket.inet_ntoa(packet[12:16])
        destination_ip = socket.inet_ntoa(packet[16:20])

        return {
            "header_length": ihl,
            "total_length": total_length,
            "protocol": protocol,
            "source_ip": source_ip,
            "destination_ip": destination_ip
        }

    def parse_transport(self, packet, ip_info):
        offset = ip_info["header_length"]
        total_length = min(
            len(packet),
            ip_info["total_length"]
        )

        if total_length < offset:
            return "Invalid transport header"

        protocol = ip_info["protocol"]

        if protocol == 6:  # TCP
            if total_length - offset < 20:
                return "Incomplete TCP header"

            source_port, destination_port = struct.unpack(
                "!HH", packet[offset:offset + 4]
            )

            tcp_offset = (packet[offset + 12] >> 4) * 4

            if tcp_offset < 20 or offset + tcp_offset > total_length:
                return "Invalid TCP header length"

            return f"TCP | Source Port: {source_port} | Destination Port: {destination_port}"

        elif protocol == 17:  # UDP
            if total_length - offset < 8:
                return "Incomplete UDP header"

            source_port, destination_port, udp_length = struct.unpack(
                "!HHH", packet[offset:offset + 6]
            )

            if udp_length < 8:
                return "Invalid UDP length"

            return f"UDP | Source Port: {source_port} | Destination Port: {destination_port}"

        elif protocol == 1:
            return "ICMP"

        return f"Other Protocol ({protocol})"

    def process_packet(self, packet):
        ip_info = self.parse_ipv4(packet)

        if not ip_info:
            return

        self.packet_count += 1

        protocol = ip_info["protocol"]
        protocol_names = {
            1: "ICMP",
            6: "TCP",
            17: "UDP"
        }

        protocol_name = protocol_names.get(
            protocol, f"OTHER-{protocol}"
        )

        self.protocol_stats[protocol_name] += 1

        transport_info = self.parse_transport(packet, ip_info)

        summary = (
            f"Packet #{self.packet_count} | "
            f"Source: {ip_info['source_ip']} | "
            f"Destination: {ip_info['destination_ip']} | "
            f"Protocol: {protocol_name} | "
            f"{transport_info} | "
            f"Size: {ip_info['total_length']} bytes"
        )

        print(summary)
        logging.info(summary)

    def show_statistics(self):
        print("\n========== NETWORK STATISTICS ==========")
        print(f"Total Packets Captured: {self.packet_count}")

        for protocol, count in self.protocol_stats.items():
            print(f"{protocol}: {count}")

        print("========================================\n")

    def start(self, interface=None):
        try:
            # Windows raw socket capture
            sniffer = socket.socket(
                socket.AF_INET,
                socket.SOCK_RAW,
                socket.IPPROTO_IP
            )

            host_ip = socket.gethostbyname(socket.gethostname())

            sniffer.bind((host_ip, 0))
            sniffer.setsockopt(
                socket.IPPROTO_IP,
                socket.IP_HDRINCL,
                1
            )

            # Enable receiving IPv4 packets on this interface
            sniffer.ioctl(
                socket.SIO_RCVALL,
                socket.RCVALL_ON
            )

            print(f"[*] Sniffer started on {host_ip}")
            print("[*] Press CTRL+C to stop capture.\n")

            logging.info(f"Sniffer started on {host_ip}")

            while self.running:
                packet, address = sniffer.recvfrom(65535)
                self.process_packet(packet)

        except PermissionError:
            print("[!] Administrator privileges are required.")

        except OSError as error:
            print(f"[!] Socket error: {error}")

        except KeyboardInterrupt:
            print("\n[*] Capture stopped.")

        finally:
            if "sniffer" in locals():
                try:
                    sniffer.ioctl(
                        socket.SIO_RCVALL,
                        socket.RCVALL_OFF
                    )
                except OSError:
                    pass
                sniffer.close()

            self.show_statistics()
            logging.info(
                f"Capture finished. Total packets: {self.packet_count}"
            )


def main():
    parser = argparse.ArgumentParser(
        description="Python Network Packet Sniffer"
    )

    parser.add_argument(
        "--interface",
        help="Optional interface selection (reserved for future use)"
    )

    args = parser.parse_args()

    print("=" * 55)
    print("          NETWORK PACKET SNIFFER")
    print("=" * 55)

    sniffer = NetworkPacketSniffer()
    sniffer.start(args.interface)


if __name__ == "__main__":
    main()
