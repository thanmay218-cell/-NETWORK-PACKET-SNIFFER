# Network Packet Sniffer

## Project Description

Network Packet Sniffer is a Python-based network monitoring tool that captures and analyzes IPv4 network packets.

It identifies different network protocols and displays packet information in the command prompt.

## Features

1. Captures live IPv4 network packets.
2. Identifies source IP addresses.
3. Identifies destination IP addresses.
4. Detects TCP protocol.
5. Detects UDP protocol.
6. Detects ICMP protocol.
7. Extracts TCP and UDP port numbers.
8. Calculates packet payload size.
9. Displays packet information.
10. Saves packet details in a log file.
11. Displays protocol statistics.

## Technologies Used

- Python
- Socket Programming
- Struct Module
- Collections Module
- Datetime Module

## Requirements

- Windows Operating System
- Python 3
- Administrator Permission
- Active Network Connection

## Installation

No additional Python packages are required.

## How to Run

1. Open Command Prompt as Administrator.
2. Navigate to the project folder.
3. Execute the following command:

python packet_sniffer.py

## How to Stop

Press CTRL + C.

## Output

The program displays:

- Source IP
- Destination IP
- Protocol
- Source Port
- Destination Port
- Payload Size
- Total Packet Count

Captured packet information is stored in packet_log.txt.

## Security Note

Use this application only on networks and devices you own or have permission to monitor.