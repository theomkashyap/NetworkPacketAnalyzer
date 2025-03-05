import tkinter as tk
from tkinter import filedialog, messagebox
import re
from datetime import datetime
import pandas as pd
from fpdf import FPDF  # Import fpdf for PDF creation

class PacketAnalyzerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Packet Analyzer")
        
        # Set the window to full screen
        self.root.attributes("-fullscreen", True)

        self.packets = []  # To store parsed packets
        
        # Create UI elements
        self.create_widgets()

    def create_widgets(self):
        # Close Button (Red 'X' at the top-right corner)
        close_button = tk.Button(self.root, text="X", command=self.close_app, font=("Arial", 16, "bold"), bg="red", fg="white", relief="flat", height=1, width=2)
        close_button.pack(side=tk.TOP, anchor='ne', padx=20, pady=10)

        # File selection frame
        self.file_frame = tk.Frame(self.root)
        self.file_frame.pack(pady=10)

        self.file_label = tk.Label(self.file_frame, text="Packet Log File:")
        self.file_label.grid(row=0, column=0, padx=10)
        
        self.file_entry = tk.Entry(self.file_frame, width=40)
        self.file_entry.grid(row=0, column=1, padx=10)
        
        self.browse_button = tk.Button(self.file_frame, text="Browse", command=self.browse_file, width=20, height=2, bg='lightblue', fg='black', font=('Arial', 12, 'bold'), relief='flat', borderwidth=2)
        self.browse_button.grid(row=0, column=2, padx=10)

        # Protocol filter input
        self.protocol_frame = tk.Frame(self.root)
        self.protocol_frame.pack(pady=10)

        self.protocol_label = tk.Label(self.protocol_frame, text="Filter by Protocol (comma separated):")
        self.protocol_label.grid(row=0, column=0, padx=10)

        self.protocol_entry = tk.Entry(self.protocol_frame, width=40)
        self.protocol_entry.grid(row=0, column=1, padx=10)

        # Minimum packet length filter
        self.length_frame = tk.Frame(self.root)
        self.length_frame.pack(pady=10)

        self.length_label = tk.Label(self.length_frame, text="Minimum Packet Length:")
        self.length_label.grid(row=0, column=0, padx=10)

        self.length_entry = tk.Entry(self.length_frame, width=40)
        self.length_entry.grid(row=0, column=1, padx=10)

        # Time filter (start and end time)
        self.time_frame = tk.Frame(self.root)
        self.time_frame.pack(pady=10)

        self.time_label = tk.Label(self.time_frame, text="Filter by Time (Start - End):")
        self.time_label.grid(row=0, column=0, padx=10)

        self.start_time_entry = tk.Entry(self.time_frame, width=20)
        self.start_time_entry.grid(row=0, column=1, padx=10)
        
        self.end_time_entry = tk.Entry(self.time_frame, width=20)
        self.end_time_entry.grid(row=0, column=2, padx=10)

        # IP filter (source and destination IP)
        self.ip_frame = tk.Frame(self.root)
        self.ip_frame.pack(pady=10)

        self.ip_label = tk.Label(self.ip_frame, text="Filter by IP (Source - Destination):")
        self.ip_label.grid(row=0, column=0, padx=10)

        self.source_ip_entry = tk.Entry(self.ip_frame, width=20)
        self.source_ip_entry.grid(row=0, column=1, padx=10)

        self.dest_ip_entry = tk.Entry(self.ip_frame, width=20)
        self.dest_ip_entry.grid(row=0, column=2, padx=10)

        # Analyze button
        self.analyze_button = tk.Button(self.root, text="Analyze Packets", command=self.analyze_packets, width=20, height=2, bg='lightgreen', fg='black', font=('Arial', 12, 'bold'), relief='flat', borderwidth=2)
        self.analyze_button.pack(pady=20)

        # Export to PDF button
        self.export_button = tk.Button(self.root, text="Export to PDF", command=self.export_to_pdf, width=20, height=2, bg='lightblue', fg='black', font=('Arial', 12, 'bold'), relief='flat', borderwidth=2)
        self.export_button.pack(pady=20)

        # Output Display with Scrollbar
        self.output_frame = tk.Frame(self.root)
        self.output_frame.pack(padx=10, pady=10)

        self.output_text = tk.Text(self.output_frame, height=20, width=140)
        self.output_text.pack(side=tk.LEFT, padx=10, pady=10)

        self.scrollbar = tk.Scrollbar(self.output_frame, orient="vertical", command=self.output_text.yview)
        self.scrollbar.pack(side=tk.RIGHT, fill="y")

        self.output_text.config(yscrollcommand=self.scrollbar.set)

    def browse_file(self):
        """Function to browse and select a file."""
        file_path = filedialog.askopenfilename(title="Select a Packet Log File", filetypes=(("Text Files", "*.txt"), ("All Files", "*.*")))
        if file_path:
            self.file_entry.delete(0, tk.END)
            self.file_entry.insert(0, file_path)

    def parse_packet_data_from_file(self, file_path):
        """Reads and parses packet data from a file."""
        packets = []

        try:
            with open(file_path, 'r') as file:
                packet_data = file.read()
        except Exception as e:
            messagebox.showerror("Error", f"Unable to read file: {e}")
            return packets

        # Regex to extract packet details
        pattern = re.compile(
            r"Timestamp:\s*(?P<timestamp>.+?)\n"  # Match Timestamp
            r"Source IP:\s*(?P<source_ip>.+?)\n"  # Match Source IP
            r"Destination IP:\s*(?P<destination_ip>.+?)\n"  # Match Destination IP
            r"Protocol:\s*(?P<protocol>.+?)\n"  # Match Protocol
            r"Packet Length:\s*(?P<packet_length>\d+)",  # Match Packet Length
            re.DOTALL  # Allow multiline matching
        )

        matches = pattern.finditer(packet_data)

        for match in matches:
            try:
                packet_info = {
                    'timestamp': datetime.strptime(match.group('timestamp'), "%Y-%m-%d %H:%M:%S"),
                    'source_ip': match.group('source_ip'),
                    'destination_ip': match.group('destination_ip'),
                    'protocol': match.group('protocol'),
                    'packet_length': int(match.group('packet_length')),
                }
                packets.append(packet_info)
            except Exception as e:
                print(f"Error parsing packet: {e}")

        return packets

    def filter_packets(self, packets, protocol_filter=None, min_length=None, start_time=None, end_time=None, source_ip=None, dest_ip=None):
        """Filters packets based on various criteria."""
        filtered_packets = []
        
        for packet in packets:
            if protocol_filter and packet['protocol'].upper() not in protocol_filter:
                continue
            if min_length and packet['packet_length'] < min_length:
                continue
            if start_time and packet['timestamp'] < start_time:
                continue
            if end_time and packet['timestamp'] > end_time:
                continue
            if source_ip and packet['source_ip'] != source_ip:
                continue
            if dest_ip and packet['destination_ip'] != dest_ip:
                continue
            filtered_packets.append(packet)

        return filtered_packets

    def analyze_packets(self):
        """Analyzes packets and prints the analysis."""
        file_path = self.file_entry.get().strip()

        if not file_path:
            messagebox.showerror("Error", "Please select a file first.")
            return

        # Parse the packet data from the file
        packets = self.parse_packet_data_from_file(file_path)

        if not packets:
            self.output_text.delete(1.0, tk.END)
            self.output_text.insert(tk.END, "No packets found or invalid format.")
            return

        # Get filter values
        protocol_filter_input = self.protocol_entry.get().strip().upper()
        protocol_filter = [protocol.strip() for protocol in protocol_filter_input.split(',')] if protocol_filter_input else None
        
        min_length_input = self.length_entry.get().strip()
        min_length = int(min_length_input) if min_length_input else None

        # Time filter
        start_time_input = self.start_time_entry.get().strip()
        end_time_input = self.end_time_entry.get().strip()
        start_time = datetime.strptime(start_time_input, "%Y-%m-%d %H:%M:%S") if start_time_input else None
        end_time = datetime.strptime(end_time_input, "%Y-%m-%d %H:%M:%S") if end_time_input else None

        # IP filter
        source_ip = self.source_ip_entry.get().strip() if self.source_ip_entry.get().strip() else None
        dest_ip = self.dest_ip_entry.get().strip() if self.dest_ip_entry.get().strip() else None

        # Apply filters
        filtered_packets = self.filter_packets(packets, protocol_filter=protocol_filter, min_length=min_length,
                                                start_time=start_time, end_time=end_time,
                                                source_ip=source_ip, dest_ip=dest_ip)

        # Prepare analysis output
        output = self.get_analysis_summary(filtered_packets)
        
        # Display the result in the output text box
        self.output_text.delete(1.0, tk.END)
        self.output_text.insert(tk.END, output)

        # Display the raw packet records
        self.output_text.insert(tk.END, "\n\n--- Packet Records ---\n")
        for packet in filtered_packets:
            self.output_text.insert(tk.END, f"Timestamp: {packet['timestamp']} | Source IP: {packet['source_ip']} | Destination IP: {packet['destination_ip']} | Protocol: {packet['protocol']} | Packet Length: {packet['packet_length']} bytes\n")

    def get_analysis_summary(self, packets):
        """Generates and returns the analysis summary as a string."""
        if not packets:
            return "No packets to analyze after applying filters."

        protocol_count = {}
        total_length = 0
        largest_packet = None
        smallest_packet = None
        source_ips = {}
        destination_ips = {}

        for packet in packets:
            protocol = packet['protocol']
            length = packet['packet_length']

            total_length += length
            protocol_count[protocol] = protocol_count.get(protocol, 0) + 1

            if largest_packet is None or length > largest_packet['packet_length']:
                largest_packet = packet
            if smallest_packet is None or length < smallest_packet['packet_length']:
                smallest_packet = packet

            source_ips[packet['source_ip']] = source_ips.get(packet['source_ip'], 0) + 1
            destination_ips[packet['destination_ip']] = destination_ips.get(packet['destination_ip'], 0) + 1

        total_packets = len(packets)
        average_length = total_length / total_packets if total_packets > 0 else 0

        # Top N Source and Destination IPs
        top_source_ips = sorted(source_ips.items(), key=lambda x: x[1], reverse=True)[:5]
        top_destination_ips = sorted(destination_ips.items(), key=lambda x: x[1], reverse=True)[:5]

        output = []
        output.append(f"Total Packets: {total_packets}")
        output.append(f"Average Packet Length: {average_length:.2f} bytes")

        output.append("\nProtocol Distribution:")
        for protocol, count in protocol_count.items():
            output.append(f"  {protocol}: {count} packets ({(count / total_packets) * 100:.2f}%)")

        if largest_packet:
            output.append(f"\nLargest Packet: {largest_packet['packet_length']} bytes")
            output.append(f"  Timestamp: {largest_packet['timestamp']}")
            output.append(f"  Source IP: {largest_packet['source_ip']}")
            output.append(f"  Destination IP: {largest_packet['destination_ip']}")
            output.append(f"  Protocol: {largest_packet['protocol']}")

        if smallest_packet:
            output.append(f"\nSmallest Packet: {smallest_packet['packet_length']} bytes")
            output.append(f"  Timestamp: {smallest_packet['timestamp']}")
            output.append(f"  Source IP: {smallest_packet['source_ip']}")
            output.append(f"  Destination IP: {smallest_packet['destination_ip']}")
            output.append(f"  Protocol: {smallest_packet['protocol']}")

        output.append("\nTop Source IPs:")
        for ip, count in top_source_ips:
            output.append(f"  {ip}: {count} packets")

        output.append("\nTop Destination IPs:")
        for ip, count in top_destination_ips:
            output.append(f"  {ip}: {count} packets")

        return "\n".join(output)

    def export_to_pdf(self):
        """Exports the current analysis to a PDF file."""
        output = self.output_text.get(1.0, tk.END).strip()
        
        if not output:
            messagebox.showerror("Error", "No analysis to export.")
            return

        # Create PDF
        pdf = FPDF()
        pdf.add_page()

        pdf.set_font("Arial", size=8)  # Set font to Arial with size 9
        pdf.multi_cell(0, 10, output)  # Add the analysis output text

        # Save the PDF
        file_path = filedialog.asksaveasfilename(defaultextension=".pdf", filetypes=[("PDF Files", "*.pdf")])
        if file_path:
            pdf.output(file_path)
            messagebox.showinfo("Success", f"PDF saved successfully to {file_path}")

    def close_app(self):
        """Closes the application."""
        self.root.quit()


# Create the main window
root = tk.Tk()
app = PacketAnalyzerApp(root)
root.mainloop()
