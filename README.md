# Network-traffic-capture-and-analysis-with-Wireshark
## AIM:
To capture and analyze network traffic using Wireshark in order to observe protocols, packets, and potential anomalies.
## Requirements:
- **Hardware:**
    - Computer with internet access
    - Network adapter (Ethernet/Wi-Fi)
- **Software:**
    - Wireshark (latest stable version)
    - Sample PCAP files (optional for offline analysis)
## Architecture:
```mermaid
flowchart TD
    A[Network Interface Card] --> B[Wireshark Packet Capture Engine]
    B --> C[Packet Decoder & Protocol Analyzer]
    C --> D[Packet Display & Filtering Interface]
    D --> E[Investigator Analyzes Network Data]
    E --> F[Findings: IPs, Ports, Protocols, Anomalies]
```
## DESIGN STEPS:
### Step 1:
Install Wireshark on the system.

### Step 2:
Launch Wireshark and select the network interface (Ethernet/Wi-Fi).

### Step 3:
Start the capture, apply filters (like http, tcp, ip.addr == x.x.x.x) to analyze specific traffic, and stop the capture after observing relevant data.
### Step 4:
**Analyze traffic to identify:**
  - Source & Destination IP addresses
  - Protocols (HTTP, DNS, TCP, UDP, etc.)
  - Suspicious activities (e.g., unusual ports, repeated requests).
## PROGRAM:
Wireshark Packet Capture and Filter Usage

## OUTPUT:

- Captured Packets with Protocol Analysis and Detailed Packet Info

![image](https://github.com/user-attachments/assets/f387facb-28db-4353-88ff-70a3f9a3cf07)

- **Start Capturing Packets**

• Click the blue shark fin icon or double-click the interface.

• Wireshark will start capturing all real-time traffic.

![image](https://github.com/user-attachments/assets/3b0da9da-047e-45f9-a0bc-ca3a7158b474)

- **Apply Filters to Focus on Specific Traffic**
  
• Use filters like http, ip.addr == 192.168.1.1, or tcp.port == 80 in the top filter bar to narrow down results.

![image](https://github.com/user-attachments/assets/5739b9a9-38b1-4c79-ba4e-fde143ea680b)

- **Analyze Packet Details**
  
• Click on a packet to view its detailed breakdown including frame, Ethernet,IP, TCP/UDP layers, and data payload.

![image](https://github.com/user-attachments/assets/051c53c4-0f8f-4846-88cd-d02469e9d656)
## RESULT:
Network traffic was successfully captured and analyzed using Wireshark.
