\# Network Packet Sniffer



A Python-based Network Packet Sniffer that captures and analyzes IPv4 network traffic on Windows using raw sockets.



\## Features



\- Live IPv4 packet capture

\- Source and destination IP address extraction

\- IPv4 header parsing

\- TCP header decoding

\- UDP header decoding

\- Source and destination port identification

\- Protocol identification (TCP, UDP, ICMP)

\- Packet count and protocol statistics

\- Automatic network traffic logging

\- Keyboard interrupt handling for safe capture termination



\## Technologies Used



\- Python 3

\- Socket Programming

\- Struct Module

\- Logging Module

\- Collections Module



\## Project Structure



```text

Network-Packet-Sniffer/

├── packet\_sniffer.py

├── network\_log.txt

├── requirements.txt

├── .gitignore

└── screenshots/

```



\## Requirements



\- Windows operating system

\- Python 3.10 or later

\- Administrator privileges for raw socket capture



\## Installation



Clone the repository:



```bash

git clone https://github.com/dhanmee7-lab/Network-Packet-Sniffer.git

cd Network-Packet-Sniffer

```



Create a virtual environment:



```bash

python -m venv .venv

```



Activate it:



```powershell

.\\.venv\\Scripts\\Activate.ps1

```



No external Python packages are required.



\## Usage



Open PowerShell as Administrator and navigate to the project directory.



Run:



```bash

python packet\_sniffer.py

```



The application captures IPv4 packets and displays:



\- Source IP

\- Destination IP

\- Protocol

\- Source and destination ports

\- Packet size



Press `CTRL + C` to stop packet capture and display statistics.



\## Sample Statistics



Example capture results:



| Protocol | Packets |

|---|---:|

| TCP | 596 |

| UDP | 146 |

| Total | 742 |



\## Sample Network Log



The `network\_log.txt` file contains sanitized example packet entries.



\## Screenshots



Screenshots of project setup, execution, packet capture, protocol statistics, and network logs are available in the `screenshots/` directory.



\## Security Notice



Use this tool only on devices and networks you own or have explicit authorization to monitor.



This project analyzes IPv4 packet headers and transport-layer metadata. It does not decrypt encrypted application traffic.



\## Author



\*\*Dhanmeeswaran G.\*\*



Cybersecurity | Network Security | Python Development



GitHub: https://github.com/dhanmee7-lab



