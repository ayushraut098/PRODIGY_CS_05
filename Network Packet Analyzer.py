from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw

def packet_callback(packet):
    print("=" * 60)

    if IP in packet:
        ip_layer = packet[IP]
        print(f"[+] Source IP      : {ip_layer.src}")
        print(f"[+] Destination IP : {ip_layer.dst}")
        print(f"[+] Protocol       : {ip_layer.proto}")

        # Detect protocol type
        if TCP in packet:
            print("[+] Protocol Type  : TCP")
        elif UDP in packet:
            print("[+] Protocol Type  : UDP")
        elif ICMP in packet:
            print("[+] Protocol Type  : ICMP")

        # Show payload data if present
        if Raw in packet:
            print("[+] Payload:")
            try:
                payload = packet[Raw].load.decode('utf-8', errors='replace')
                print(payload)
            except Exception as e:
                print("[!] Could not decode payload.")

# Main function to start packet sniffing
def start_sniffer():
    print("[*] Starting packet sniffer...")
    sniff(prn=packet_callback, store=False)

if __name__ == "__main__":
    start_sniffer()
