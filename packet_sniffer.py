import socket
import struct
import datetime
import collections
import os

packet_count = 0
protocol_count = collections.Counter()
log_file = "packet_log.txt"


def write_log(message):
    with open(log_file, "a", encoding="utf-8") as file:
        file.write(message + "\n")


def get_local_ip():
    try:
        connection = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        connection.connect(("1.1.1.1", 80))
        local_ip = connection.getsockname()[0]
        connection.close()
        return local_ip
    except OSError:
        return None


def analyze_packet(packet):
    global packet_count

    if len(packet) < 20:
        return

    ip_header = struct.unpack("!BBHHHBBH4s4s", packet[:20])

    version = ip_header[0] >> 4
    header_length = (ip_header[0] & 15) * 4

    if version != 4 or header_length < 20:
        return

    if len(packet) < header_length:
        return

    total_length = ip_header[2]

    if total_length < header_length:
        return

    total_length = min(total_length, len(packet))

    source_ip = socket.inet_ntoa(ip_header[8])
    destination_ip = socket.inet_ntoa(ip_header[9])

    protocol = ip_header[6]

    source_port = "-"
    destination_port = "-"
    payload_size = 0

    if protocol == 6:
        protocol_name = "TCP"

        if total_length >= header_length + 20:
            tcp_header = packet[header_length:header_length + 20]
            tcp = struct.unpack("!HHIIHHHH", tcp_header)

            source_port = tcp[0]
            destination_port = tcp[1]

            tcp_header_length = ((tcp[4] >> 12) & 15) * 4

            if tcp_header_length >= 20:
                payload_size = max(
                    0,
                    total_length - header_length - tcp_header_length
                )

    elif protocol == 17:
        protocol_name = "UDP"

        if total_length >= header_length + 8:
            udp_header = packet[header_length:header_length + 8]
            udp = struct.unpack("!HHHH", udp_header)

            source_port = udp[0]
            destination_port = udp[1]

            payload_size = max(0, udp[2] - 8)

    elif protocol == 1:
        protocol_name = "ICMP"
        payload_size = max(0, total_length - header_length)

    else:
        protocol_name = "OTHER"
        payload_size = max(0, total_length - header_length)

    packet_count += 1
    protocol_count[protocol_name] += 1

    current_time = datetime.datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    message = (
        f"[{current_time}] "
        f"{protocol_name} | "
        f"Source: {source_ip}:{source_port} | "
        f"Destination: {destination_ip}:{destination_port} | "
        f"Payload: {payload_size} bytes"
    )

    print(message)
    write_log(message)


def show_statistics():
    print("\n===================================")
    print("        PACKET STATISTICS")
    print("===================================")

    print("Total Packets Captured:", packet_count)

    if protocol_count:
        for protocol, count in protocol_count.items():
            print(f"{protocol}: {count}")
    else:
        print("No packets captured.")

    print("===================================")
    print("Log file:", os.path.abspath(log_file))


def start_sniffer():
    sniffer = None
    capture_started = False

    local_ip = get_local_ip()

    if not local_ip:
        print("Unable to detect local IP address.")
        return

    print("\n===================================")
    print("       NETWORK PACKET SNIFFER")
    print("===================================")

    print("Local IP Address:", local_ip)
    print("Protocol: IPv4")
    print("Starting packet capture...")

    try:
        sniffer = socket.socket(
            socket.AF_INET,
            socket.SOCK_RAW,
            socket.IPPROTO_IP
        )

        sniffer.bind((local_ip, 0))

        sniffer.setsockopt(
            socket.IPPROTO_IP,
            socket.IP_HDRINCL,
            1
        )

        sniffer.ioctl(
            socket.SIO_RCVALL,
            socket.RCVALL_ON
        )

        capture_started = True

        write_log("\n========== NEW CAPTURE SESSION ==========")

        print("\nPacket capture started successfully!")
        print("Open websites or generate network traffic.")
        print("Press CTRL + C to stop capturing.\n")

        while True:
            packet, address = sniffer.recvfrom(65535)
            analyze_packet(packet)

    except PermissionError:
        print("\nAdministrator permission is required.")
        print("Close the terminal and reopen it as Administrator.")

    except OSError as error:
        print("\nNetwork error:", error)

    except KeyboardInterrupt:
        print("\n\nPacket capture stopped by user.")

    finally:
        if sniffer:
            if capture_started:
                try:
                    sniffer.ioctl(
                        socket.SIO_RCVALL,
                        socket.RCVALL_OFF
                    )
                except OSError:
                    pass

            sniffer.close()

        show_statistics()


if __name__ == "__main__":
    start_sniffer()