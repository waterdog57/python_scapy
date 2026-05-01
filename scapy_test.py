from scapy.all import *
import threading
import time
import socket
import random


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


def scapy_postman_request(host, port=80, method="GET", path="/", headers=None, body=""):
    """
    A Postman-like function using Scapy to send HTTP requests.
    Supports GET/POST and custom headers/body.
    """
    print(f"\n[Postman] Sending {method} to http://{host}:{port}{path}...")
    
    try:
        # 1. Resolve hostname
        dst_ip = socket.gethostbyname(host)
        src_port = random.randint(1024, 65535)

        # 2. 3-Way Handshake
        # SYN
        syn = IP(dst=dst_ip) / TCP(sport=src_port, dport=port, flags="S")
        syn_ack = sr1(syn, timeout=2, verbose=0)
        
        if not syn_ack or not syn_ack.haslayer(TCP) or syn_ack[TCP].flags != "SA":
            print("Error: Failed to establish TCP connection (No SYN-ACK).")
            return

        # ACK
        ack = IP(dst=dst_ip) / TCP(sport=src_port, dport=port, flags="A", 
                                   seq=syn_ack[TCP].ack, ack=syn_ack[TCP].seq + 1)
        send(ack, verbose=0)

        # 3. Construct HTTP Request
        http_request = f"{method} {path} HTTP/1.1\r\n"
        http_request += f"Host: {host}\r\n"
        http_request += "User-Agent: Scapy-Postman/1.0\r\n"
        http_request += "Connection: close\r\n"
        
        if headers:
            for k, v in headers.items():
                http_request += f"{k}: {v}\r\n"
        
        if body:
            http_request += f"Content-Length: {len(body)}\r\n"
            http_request += "\r\n"
            http_request += body
        else:
            http_request += "\r\n"

        # 4. Send HTTP Request (PSH-ACK)
        request_pkt = IP(dst=dst_ip) / TCP(sport=src_port, dport=port, flags="PA", 
                                           seq=syn_ack[TCP].ack, ack=syn_ack[TCP].seq + 1) / Raw(load=http_request)
        
        print("Waiting for response...")
        response = sr1(request_pkt, timeout=5, verbose=0)

        # 5. Display Response
        if response:
            print("\n" + "="*40)
            print("         SCAPY POSTMAN RESPONSE")
            print("="*40)
            if response.haslayer(Raw):
                payload = response[Raw].load.decode(errors='ignore')
                print(payload)
            else:
                response.show()
            print("="*40 + "\n")
        else:
            print("No response received from server.")

    except Exception as e:
        print(f"Postman Error: {e}")


if __name__ == "__main__":
    # Initialize and get the network interface
    interface = scapy_init()
    if not interface:
        print("No network interfaces found, exiting program.")
        exit(1)
    
    # On macOS, en0 is common. If your network is different, change it here.
    # interface = "en0" 

    print("Choose action:")
    print("1. Run Original Test (Sniff + Send)")
    print("2. Run Postman Test (GET example.com)")
    print("3. Run Postman Test (POST placeholder)")
    
    choice = input("Enter choice (1-3): ")

    if choice == "1":
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

    elif choice == "2":
        # GET request to example.com
        scapy_postman_request(host="example.com", port=80, method="GET", path="/")

    elif choice == "3":
        # POST request example
        headers = {"Content-Type": "application/json"}
        body = '{"message": "Hello from Scapy Postman"}'
        scapy_postman_request(host="postman-echo.com", port=80, method="POST", path="/post", 
                               headers=headers, body=body)

    else:
        print("Invalid choice.")
