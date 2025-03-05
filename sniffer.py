import tkinter as tk
from tkinter import filedialog, messagebox
from scapy.all import sniff, IP, ARP
from datetime import datetime
import xml.etree.ElementTree as ET
import csv
import threading

# Global list to store packet data
packets_data = []

# Function to map protocol number to human-readable name
def get_protocol_name(protocol_num):
    protocol_dict = {
        1: 'ICMP',
        6: 'TCP',
        17: 'UDP',
        58: 'ICMPv6',
        89: 'OSPF',
        112: 'VRRP',
        121: 'SIP',
        132: 'PPTP',
        2054: 'ARP'
    }
    return protocol_dict.get(protocol_num, 'Other')

# Callback function for capturing packets
def packet_callback(packet):
    packet_info = {}
    
    # Check if the packet contains an IP layer
    if IP in packet:
        packet_info['timestamp'] = datetime.fromtimestamp(packet.time).strftime('%Y-%m-%d %H:%M:%S')
        packet_info['src_ip'] = packet[IP].src
        packet_info['dst_ip'] = packet[IP].dst
        packet_info['protocol'] = get_protocol_name(packet[IP].proto)
        packet_info['length'] = len(packet)
        
    # Check if the packet contains an ARP layer
    elif ARP in packet:
        packet_info['timestamp'] = datetime.fromtimestamp(packet.time).strftime('%Y-%m-%d %H:%M:%S')
        packet_info['src_ip'] = packet[ARP].psrc
        packet_info['dst_ip'] = packet[ARP].pdst
        packet_info['protocol'] = 'ARP'
        packet_info['length'] = len(packet)
        
    # Add packet info to the global list
    if packet_info:
        packets_data.append(packet_info)
        update_packet_list(packet_info)  # Update the GUI with packet info

# Function to update the packet list display in the GUI
def update_packet_list(packet_info):
    packet_details = f"Timestamp: {packet_info['timestamp']}, Source IP: {packet_info['src_ip']}, Destination IP: {packet_info['dst_ip']}, Protocol: {packet_info['protocol']}, Length: {packet_info['length']}\n"
    packet_list_box.insert(tk.END, packet_details)

# Function to save packets to XML file
def save_to_xml():
    filename = filedialog.asksaveasfilename(defaultextension=".xml", filetypes=[("XML files", "*.xml")])
    if filename:
        root = ET.Element("packets")
        for pkt in packets_data:
            pkt_element = ET.SubElement(root, "packet")
            ET.SubElement(pkt_element, "timestamp").text = pkt['timestamp']
            ET.SubElement(pkt_element, "src_ip").text = pkt['src_ip']
            ET.SubElement(pkt_element, "dst_ip").text = pkt['dst_ip']
            ET.SubElement(pkt_element, "protocol").text = pkt['protocol']
            ET.SubElement(pkt_element, "length").text = str(pkt['length'])
        tree = ET.ElementTree(root)
        tree.write(filename)
        messagebox.showinfo("Success", f"Packets saved to {filename}")

# Function to save packets to TXT file
def save_to_txt():
    filename = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
    if filename:
        with open(filename, 'w') as f:
            for pkt in packets_data:
                f.write(f"Timestamp: {pkt['timestamp']}\n")
                f.write(f"Source IP: {pkt['src_ip']}\n")
                f.write(f"Destination IP: {pkt['dst_ip']}\n")
                f.write(f"Protocol: {pkt['protocol']}\n")
                f.write(f"Packet Length: {pkt['length']}\n")
                f.write("-" * 40 + "\n")
        messagebox.showinfo("Success", f"Packets saved to {filename}")

# Function to save packets to CSV file
def save_to_csv():
    filename = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")])
    if filename:
        with open(filename, 'w', newline='') as csvfile:
            fieldnames = ['timestamp', 'src_ip', 'dst_ip', 'protocol', 'length']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for pkt in packets_data:
                writer.writerow(pkt)
        messagebox.showinfo("Success", f"Packets saved to {filename}")

# Function to start sniffing packets in a separate thread
def start_sniffing():
    # Running sniffing in a separate thread to avoid blocking the main thread
    sniff_thread = threading.Thread(target=lambda: sniff(prn=packet_callback, store=False, count=0))
    sniff_thread.daemon = True  # Allow the thread to exit when the main program exits
    sniff_thread.start()

# Function to stop sniffing (not fully implemented, just for UI)
def stop_sniffing():
    messagebox.showinfo("Stopped", "Packet sniffing stopped manually.")

# Function to close the app
def close_app():
    root.quit()

# GUI Setup
root = tk.Tk()
root.title("Packet Sniffer")

# Set the window to full screen
root.attributes("-fullscreen", True)

# Close Button (Red text "X" at the top-right)
close_button = tk.Button(root, text="X", command=close_app, font=("Arial", 16, "bold"), bg="red", fg="white", relief="flat", height=1, width=2)
close_button.pack(side=tk.TOP, anchor='ne', padx=20, pady=10)

# Start Sniffing Button
start_button = tk.Button(root, text="Start Sniffing", command=start_sniffing, width=20, height=2, bg='skyblue', fg='black', font=('Arial', 12, 'bold'), relief='flat', borderwidth=2)
start_button.pack(pady=10)

# Stop Sniffing Button
stop_button = tk.Button(root, text="Stop Sniffing", command=stop_sniffing, width=20, height=2, bg='lightcoral', fg='black', font=('Arial', 12, 'bold'), relief='flat', borderwidth=2)
stop_button.pack(pady=10)

# Save Buttons
save_xml_button = tk.Button(root, text="Save to XML", command=save_to_xml, width=20, height=2, bg='lightgreen', fg='black', font=('Arial', 12, 'bold'), relief='flat', borderwidth=2)
save_xml_button.pack(pady=5)

save_txt_button = tk.Button(root, text="Save to TXT", command=save_to_txt, width=20, height=2, bg='lightblue', fg='black', font=('Arial', 12, 'bold'), relief='flat', borderwidth=2)
save_txt_button.pack(pady=5)

save_csv_button = tk.Button(root, text="Save to CSV", command=save_to_csv, width=20, height=2, bg='lightpink', fg='black', font=('Arial', 12, 'bold'), relief='flat', borderwidth=2)
save_csv_button.pack(pady=5)

# Packet List Display
packet_list_box = tk.Text(root, height=20, width=140)
packet_list_box.pack(pady=10)

root.mainloop()
