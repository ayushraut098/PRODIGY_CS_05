# PRODIGY_CS_05

How to Use:
Install Dependencies:

Ensure Python and scapy are installed:
"pip install scapy"
Save the Code:
Save the script as packet_sniffer.py.
Run the Script:
Windows: Run the script using python packet_sniffer.py in an elevated Command Prompt (run as Administrator).
Linux/macOS: Run it using sudo python3 packet_sniffer.py to capture packets with the required permissions.
Capture Packets:
The script will display details such as the source and destination IPs, protocols (TCP/UDP/ICMP), and any payload data it can decode.
Stop the Sniffer:
Stop the script by pressing Ctrl+C.
Explanation of the Code:
sniff(): This function from scapy captures the network packets. The prn parameter specifies a callback function (packet_callback) that will be invoked for each captured packet.
packet_callback(): This function processes each packet, displaying the source and destination IPs, the protocol type, and the payload if available.
Protocols: The script checks for common network protocols such as TCP, UDP, and ICMP and displays the relevant data.
Payload: If the packet contains raw data (Raw), the script attempts to decode it and print it out.
Ethical Considerations:
Only use this tool on networks you own or have permission to analyze.
Packet sniffing can be illegal if performed on unauthorized networks, as it may capture sensitive data.
This tool is intended solely for educational purposes to learn about network protocols, network security, and how sniffers work.
