import tkinter as tk
from tkinter import ttk
from scapy.all import sniff, IP, TCP, UDP, ARP, ICMP, Ether
import threading
import pandas as pd
from datetime import datetime

class WiresharkApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Wireshark-Like App")
        self.root.geometry("950x550")
        self.root.configure(bg="#2e2e2e")  # Dark background color

        # Initialize packet list
        self.packet_data = []
        self.filtered_data = []  # To store filtered packets
        self.capture_active = False  # Flag to control the sniffing process
        self.auto_scroll_enabled = True  # To control auto-scroll behavior

        # Define the columns for Treeview
        self.columns = ("Time", "Source IP", "Dest IP", "Protocol", "Source Port", "Dest Port", "Additional Info")

        # Create UI elements
        self.create_widgets()

    def create_widgets(self):
        # Create a frame for the buttons
        button_frame = tk.Frame(self.root, bg="#2e2e2e")
        button_frame.pack(pady=10, fill="x")

        # Start and Stop buttons
        self.start_button = tk.Button(button_frame, text="Start", command=self.start_capture, bg="#444", fg="white", font=("Arial", 12), width=15)
        self.start_button.grid(row=0, column=0, padx=5)

        self.stop_button = tk.Button(button_frame, text="Stop", command=self.stop_capture, bg="#444", fg="white", font=("Arial", 12), width=15)
        self.stop_button.grid(row=0, column=1, padx=5)

        # Clear button
        self.clear_button = tk.Button(button_frame, text="Clear", command=self.clear_packets, bg="#444", fg="white", font=("Arial", 12), width=15)
        self.clear_button.grid(row=0, column=2, padx=5)

        # Save button
        self.save_button = tk.Button(button_frame, text="Save", command=self.save_packets, bg="#444", fg="white", font=("Arial", 12), width=15)
        self.save_button.grid(row=0, column=3, padx=5)

        # Reset Filters button
        self.reset_filters_button = tk.Button(button_frame, text="Reset Filters", command=self.reset_filters, bg="#444", fg="white", font=("Arial", 12), width=15)
        self.reset_filters_button.grid(row=0, column=4, padx=5)

        # Filter options
        filter_frame = tk.Frame(self.root, bg="#2e2e2e")
        filter_frame.pack(pady=10, fill="x")

        self.filter_ip_label = tk.Label(filter_frame, text="IP (Src/Dst):", fg="white", bg="#2e2e2e")
        self.filter_ip_label.grid(row=0, column=0, padx=5)

        self.filter_ip_entry = tk.Entry(filter_frame, bg="#444", fg="white", font=("Arial", 12), width=20)
        self.filter_ip_entry.grid(row=0, column=1, padx=5)

        self.filter_protocol_label = tk.Label(filter_frame, text="Protocol:", fg="white", bg="#2e2e2e")
        self.filter_protocol_label.grid(row=0, column=2, padx=5)

        self.filter_protocol_entry = tk.Entry(filter_frame, bg="#444", fg="white", font=("Arial", 12), width=20)
        self.filter_protocol_entry.grid(row=0, column=3, padx=5)

        self.filter_port_label = tk.Label(filter_frame, text="Port (Src/Dst):", fg="white", bg="#2e2e2e")
        self.filter_port_label.grid(row=1, column=0, padx=5)

        self.filter_port_entry = tk.Entry(filter_frame, bg="#444", fg="white", font=("Arial", 12), width=20)
        self.filter_port_entry.grid(row=1, column=1, padx=5)

        self.filter_button = tk.Button(filter_frame, text="Apply Filter", command=self.apply_filter, bg="#444", fg="white", font=("Arial", 12), width=15)
        self.filter_button.grid(row=1, column=2, padx=5)

        # Create a frame for the Treeview and Scrollbar
        table_frame = tk.Frame(self.root)
        table_frame.pack(pady=20, fill="both", expand=True)

        self.canvas = tk.Canvas(table_frame)
        self.scrollbar = tk.Scrollbar(table_frame, orient="vertical", command=self.canvas.yview)

        self.tree_frame = tk.Frame(self.canvas)

        self.canvas.configure(yscrollcommand=self.scrollbar.set)
        self.scrollbar.pack(side="right", fill="y")
        self.canvas.pack(side="left", fill="both", expand=True)
        self.canvas.create_window((0, 0), window=self.tree_frame, anchor="nw")

        # Create the Treeview (table) inside the tree_frame
        self.tree = ttk.Treeview(self.tree_frame, columns=self.columns, show="headings", height=15)

        # Style the table
        self.tree.heading("Time", text="Time")
        self.tree.heading("Source IP", text="Source IP")
        self.tree.heading("Dest IP", text="Dest IP")
        self.tree.heading("Protocol", text="Protocol")
        self.tree.heading("Source Port", text="Source Port")
        self.tree.heading("Dest Port", text="Dest Port")
        self.tree.heading("Additional Info", text="Additional Info")

        # Remove hardcoded widths for the columns
        self.tree.column("Time", anchor="center", width=100, stretch=tk.YES)
        self.tree.column("Source IP", anchor="center", stretch=tk.YES)
        self.tree.column("Dest IP", anchor="center", stretch=tk.YES)
        self.tree.column("Protocol", anchor="center", width=100, stretch=tk.YES)
        self.tree.column("Source Port", anchor="center", width=100, stretch=tk.YES)
        self.tree.column("Dest Port", anchor="center", width=100, stretch=tk.YES)
        self.tree.column("Additional Info", anchor="center", stretch=tk.YES)

        # Pack the Treeview and ensure it fills both the width and height of its container
        self.tree.pack(fill="both", expand=True)


        # Packet counter label
        self.packet_counter_label = tk.Label(self.root, text="Packets Captured: 0", fg="white", bg="#2e2e2e", font=("Arial", 12))
        self.packet_counter_label.pack(pady=10)

    def start_capture(self):
        if not self.capture_active:  # Start sniffing only if it's not already running
            self.capture_active = True
            # Start packet sniffing in a separate thread
            self.sniff_thread = threading.Thread(target=self.sniff_packets)
            self.sniff_thread.daemon = True
            self.sniff_thread.start()

    def sniff_packets(self):
        # Capture packets indefinitely and display detailed info
        sniff(prn=self.process_packet, store=0, iface="Ethernet")  # Removed stop_filter argument

    def process_packet(self, pkt):
        if self.capture_active:
            time = datetime.now().strftime("%H:%M:%S")

            # IP layer
            source_ip = pkt[IP].src if IP in pkt else "N/A"
            dest_ip = pkt[IP].dst if IP in pkt else "N/A"
            protocol = self.get_protocol(pkt)

            # Ports (TCP/UDP)
            source_port = pkt[TCP].sport if TCP in pkt else (pkt[UDP].sport if UDP in pkt else "N/A")
            dest_port = pkt[TCP].dport if TCP in pkt else (pkt[UDP].dport if UDP in pkt else "N/A")

            # Get the additional information about services based on ports
            additional_info = self.get_service_info(source_port, dest_port)

            # Add the packet data to the internal list
            packet_info = (time, source_ip, dest_ip, protocol, source_port, dest_port, additional_info)
            self.packet_data.append(packet_info)

            # Update the Treeview with the new packet data
            self.tree.insert("", tk.END, values=packet_info)

            # Update packet counter
            self.packet_counter_label.config(text=f"Packets Captured: {len(self.packet_data)}")

            if self.auto_scroll_enabled:
                # Automatically scroll to the bottom
                self.canvas.yview_moveto(1)

    def get_protocol(self, pkt):
        if IP in pkt:
            if TCP in pkt:
                return "TCP"
            elif UDP in pkt:
                return "UDP"
            elif ICMP in pkt:
                return "ICMP"
            else:
                return "IP"
        elif ARP in pkt:
            return "ARP"
        else:
            return "Other"

    def get_service_info(self, source_port, dest_port):
        # Map ports to protocols/services
        services = {
            20: "FTP Data",
            21: "FTP Control",
            22: "SSH",
            23: "TELNET",
            25: "SMTP",
            37: "Time Protocol",
            53: "DNS",
            69: "TFTP",
            80: "HTTP",
            123: "NTP",
            443: "HTTPS",
            445: "SMB",
            3389: "RDP (Remote Desktop)",
            5353: "mDNS",
            6881: "BitTorrent",
            6882: "BitTorrent",
            6883: "BitTorrent",
            6884: "BitTorrent",
            6885: "BitTorrent",
            6886: "BitTorrent",
            6887: "BitTorrent",
            6888: "BitTorrent",
            6889: "BitTorrent",
            465: "SMTP SSL",
            587: "SMTP Submission",
        }

        # Check if either source or destination port matches a known service
        service = services.get(source_port, services.get(dest_port, "Other"))
        return service

    def apply_filter(self):
        # Get filter values from input fields
        filter_ip = self.filter_ip_entry.get().strip()
        filter_protocol = self.filter_protocol_entry.get().strip()
        filter_port = self.filter_port_entry.get().strip()

        # Filter packets based on user input
        self.filtered_data = [
            packet for packet in self.packet_data
            if (filter_ip.lower() in packet[1].lower() or filter_ip.lower() in packet[2].lower()) and
            (filter_protocol.lower() in packet[3].lower()) and
            (filter_port in str(packet[4]) or filter_port in str(packet[5]))
        ]

        # Clear Treeview and insert filtered data
        for row in self.tree.get_children():
            self.tree.delete(row)

        for packet in self.filtered_data:
            self.tree.insert("", tk.END, values=packet)

    def reset_filters(self):
        self.filter_ip_entry.delete(0, tk.END)
        self.filter_protocol_entry.delete(0, tk.END)
        self.filter_port_entry.delete(0, tk.END)
        self.filtered_data = []
        self.update_treeview()

    def update_treeview(self):
        # Clear the Treeview and insert the original or filtered data
        for row in self.tree.get_children():
            self.tree.delete(row)

        data_to_display = self.filtered_data if self.filtered_data else self.packet_data
        for packet in data_to_display:
            self.tree.insert("", tk.END, values=packet)

    def stop_capture(self):
        self.capture_active = False

    def clear_packets(self):
        self.packet_data.clear()
        self.filtered_data.clear()
        self.update_treeview()
        self.packet_counter_label.config(text="Packets Captured: 0")

    def save_packets(self):
        # Save the packet data to a CSV file
        if self.packet_data:
            df = pd.DataFrame(self.packet_data, columns=self.columns)
            df.to_csv("captured_packets.csv", index=False)
            print("Packets saved to captured_packets.csv")
        else:
            print("No packets to save.")

if __name__ == "__main__":
    root = tk.Tk()
    app = WiresharkApp(root)
    root.mainloop()