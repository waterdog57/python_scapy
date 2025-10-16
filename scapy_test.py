from scapy.all import *
import threading
import time


def scapy_init():
    # Retrieve and print the list of available network interfaces
    interfaces = get_if_list()
    # print("Available network interfaces:", interfaces)
    # Return the first interface (or None if no interfaces are found)
    return interfaces[0] if interfaces else None


def scapy_send(interface):
    # Define source and destination MAC and IP addresses
    src_mac = "68:00:00:00:00:00"
    dst_mac = "ff:ff:ff:ff:ff:ff"
    src_ip = "192.168.0.1"
    dst_ip = "192.168.1.2"

    # Construct a packet with Ethernet, IP, ICMP, and Raw layers
    packet = (
        Ether(src=src_mac, dst=dst_mac)
        / IP(src=src_ip, dst=dst_ip)
        / ICMP()
        / Raw(load="Hello, Scapy!")
    )
    # Print a summary of the packet being sent
    print("Sending packet:", packet.summary())
    # Send the packet on the specified interface
    sendp(packet, iface=interface, count=1, inter=1)


def scapy_sniff(interface):
    def packet_callback(packet):
        # Print detailed information about the captured packet
        print("\n=== Captured Packet ===")
        packet.show()  # Display all layers and fields of the packet
        # Extract and print the payload if it exists
        if packet.haslayer(Raw):
            print("Payload content:", packet[Raw].load.decode("utf-8", errors="ignore"))
        print("================\n")

    def sniff_filter(packet):
        # Filter packets with a specific source MAC address
        if packet.haslayer(Ether) and packet[Ether].src == "68:00:00:00:00:00":
            return True
        return False

    # Start sniffing packets on the specified interface with a filter
    print("Starting packet sniffing...")
    sniff(
        iface=interface,
        prn=packet_callback,
        count=1,
        timeout=10,
        promisc=True,
        lfilter=sniff_filter,
    )


if __name__ == "__main__":
    # Initialize and get the network interface
    interface = scapy_init()
    if not interface:
        print("No network interfaces found, exiting program.")
        exit(1)
    interface = "en0"  # Replace with your actual interface name if needed
    # Create a thread for sniffing packets
    thread1 = threading.Thread(target=scapy_sniff, args=(interface,))
    thread1.start()

    # Wait briefly to ensure the sniffing thread is ready
    time.sleep(1)

    # Send the packet
    scapy_send(interface)

    # Wait for the sniffing thread to complete
    thread1.join()
    print("Program execution completed!")
