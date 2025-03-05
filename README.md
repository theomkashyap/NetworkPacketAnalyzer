# **Network Packet Analyzer**  

As part of my development work, I created a **Network Packet Analyzer**, a Python-based tool that captures and analyzes network traffic using **packet sniffing techniques**. This project was developed to provide users with a graphical interface for monitoring and analyzing packets in real time.  

## **Overview**  
The Network Packet Analyzer is built using **Python, Tkinter, and Scapy**, enabling users to **capture, filter, and analyze network traffic** efficiently. The tool features a **user-friendly GUI**, allowing seamless navigation between the packet sniffer and analyzer modules.  

## **Features**  
- **Real-time Packet Sniffing**: Captures live network traffic using **Scapy**.  
- **GUI-Based Control**: A **Tkinter-based interface** to start, stop, and manage packet capture.  
- **Packet Filtering**: Users can filter traffic based on **protocol, IP address, and time range**.  
- **Export Functionality**: Save captured packets in **XML, TXT, and CSV** formats.  
- **Packet Analysis**: Inspect and analyze captured network packets for security and debugging purposes.  
- **Landing Page**: A Tkinter-based **navigation interface** for switching between the **sniffer** and **analyzer** modules.  

## **Requirements**  
- Python 3.x  
- Scapy (for packet sniffing)  
- Tkinter (for GUI development)  
- Pandas (for exporting data)  

## **How to Run**  
1. Install the required dependencies using:  
   ```bash
   pip install scapy pandas
