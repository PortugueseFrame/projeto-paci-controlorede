import tkinter as tk # For GUI
from tkinter import ttk # For GUI
from scapy.all import sniff, IP, TCP, UDP, ARP, ICMP # Importing differente layers from Scapy
import threading # Used to create a thread with the packets
import pandas as pd # For exporting the packets to CSV
from datetime import datetime # To regiser the time the packet was captured
import platform  # For OS detection

class WiresharkApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Wireshark-Like App") # App Name
        self.root.geometry("950x550") # Window Size
        self.root.configure(bg="#2e2e2e")  # Dark background color

        self.packet_data = [] # Packet Data
        self.filtered_data = []  # Store filtered packets
        self.capture_active = False  # Flag to control the sniffing process
        self.auto_scroll_enabled = True  # Auto-scroll to bottom behavior

        # Detect default interface based on OS
        self.default_interface = self.get_default_interface()

        # Define the columns for treeview
        self.columns = ("Time", "Source IP", "Dest IP", "Protocol", "Source Port", "Dest Port", "Additional Info")

        # Create UI elements
        self.create_widgets()

    def get_default_interface(self):
        # Determine the default network interface based on the OS
        system = platform.system()
        if system == "Darwin":  # macOS
            return "en0"
        elif system == "Windows":  # Windows
            return "Ethernet"
        else:
            return None  # Linux or other OS

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

        # IP Option - Label and Entry
        self.filter_ip_label = tk.Label(filter_frame, text="IP (Src/Dst):", fg="white", bg="#2e2e2e")
        self.filter_ip_label.grid(row=0, column=0, padx=5)

        self.filter_ip_entry = tk.Entry(filter_frame, bg="#444", fg="white", font=("Arial", 12), width=20)
        self.filter_ip_entry.grid(row=0, column=1, padx=5)

        # Protocol Option - Label and Entry
        self.filter_protocol_label = tk.Label(filter_frame, text="Protocol:", fg="white", bg="#2e2e2e")
        self.filter_protocol_label.grid(row=0, column=2, padx=5)

        self.filter_protocol_entry = tk.Entry(filter_frame, bg="#444", fg="white", font=("Arial", 12), width=20)
        self.filter_protocol_entry.grid(row=0, column=3, padx=5)

        # Port Option - Label and Entry
        self.filter_port_label = tk.Label(filter_frame, text="Port (Src/Dst):", fg="white", bg="#2e2e2e")
        self.filter_port_label.grid(row=1, column=0, padx=5)

        self.filter_port_entry = tk.Entry(filter_frame, bg="#444", fg="white", font=("Arial", 12), width=20)
        self.filter_port_entry.grid(row=1, column=1, padx=5)

        # Apply filter button
        self.filter_button = tk.Button(filter_frame, text="Apply Filter", command=self.apply_filter, bg="#444", fg="white", font=("Arial", 12), width=15)
        self.filter_button.grid(row=1, column=2, padx=5)

        # Create a frame for the treeview and scrollbar
        table_frame = tk.Frame(self.root)
        table_frame.pack(pady=20, fill="both", expand=True)

        # Creates a canvas for displaying scrollable content
        self.canvas = tk.Canvas(table_frame)

        # Creates the scrollbar linked to the canvas
        self.scrollbar = tk.Scrollbar(table_frame, orient="vertical", command=self.canvas.yview)

        # Frame to hold the treeview inside the scrollable canvas
        self.tree_frame = tk.Frame(self.canvas)

        # Configure the canvas to work with the scrollbar
        self.canvas.configure(yscrollcommand=self.scrollbar.set)

        # Pack the scrollbar to the right side of the frame
        self.scrollbar.pack(side="right", fill="y")

        # Pack the canvas to the left side of the frame and make it expandable
        self.canvas.pack(side="left", fill="both", expand=True)

        # Create a Treeview widget to display captured packets
        self.canvas.create_window((0, 0), window=self.tree_frame, anchor="nw")

        self.tree = ttk.Treeview(self.tree_frame, columns=self.columns, show="headings", height=15)

        # Set the column headings for the treeview
        self.tree.heading("Time", text="Time")
        self.tree.heading("Source IP", text="Source IP")
        self.tree.heading("Dest IP", text="Dest IP")
        self.tree.heading("Protocol", text="Protocol")
        self.tree.heading("Source Port", text="Source Port")
        self.tree.heading("Dest Port", text="Dest Port")
        self.tree.heading("Additional Info", text="Additional Info")

        # Pack the treeview widget to fill the available space
        self.tree.pack(fill="both", expand=True)

        # Label to display the packet counter at the bottom of the UI
        self.packet_counter_label = tk.Label(self.root, text="Packets Captured: 0", fg="white", bg="#2e2e2e", font=("Arial", 12))
        self.packet_counter_label.pack(pady=10)

    # Starts the packet capture
    def start_capture(self):
        if not self.capture_active:
            self.capture_active = True
            self.sniff_thread = threading.Thread(target=self.sniff_packets)
            self.sniff_thread.daemon = True
            self.sniff_thread.start()

    # Sniffs the packets
    def sniff_packets(self):
        if self.default_interface:
            sniff(
                prn=self.process_packet,
                store=0,
                iface=self.default_interface,
                stop_filter=self.stop_sniffing
            )
        else:
            print("No default network interface detected. Please specify one.")

    def stop_sniffing(self, pkt):
        # Stop sniffing when capture_active is set to False
        return not self.capture_active

    def stop_capture(self):
        # Set capture_active to False to stop the sniffing process
        if self.capture_active:
            self.capture_active = False
            print("Stopping packet capture...")
        else:
            print("Packet capture is not active.")

    # Packet processing
    def process_packet(self, pkt):
        time = datetime.now().strftime("%H:%M:%S")
        source_ip = pkt[IP].src if IP in pkt else "N/A"
        dest_ip = pkt[IP].dst if IP in pkt else "N/A"
        protocol = self.get_protocol(pkt)
        source_port = pkt[TCP].sport if TCP in pkt else (pkt[UDP].sport if UDP in pkt else "N/A")
        dest_port = pkt[TCP].dport if TCP in pkt else (pkt[UDP].dport if UDP in pkt else "N/A")
        additional_info = self.get_service_info(source_port, dest_port)

        packet_info = (time, source_ip, dest_ip, protocol, source_port, dest_port, additional_info)
        self.packet_data.append(packet_info)

        self.tree.insert("", tk.END, values=packet_info)
        self.packet_counter_label.config(text=f"Packets Captured: {len(self.packet_data)}")

    # Gets the packet protocol
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

    # Gets additional info based on the Ports shown in the Packet
    # Not all of them but some of the most important
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

        # Checks if either source or destination port matches a known service
        service = services.get(source_port, services.get(dest_port, "Other"))
        return service

    # Apllies filters to already captured packets and not incoming ones
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

        # Clears the treeview and inserts the filtered data
        for row in self.tree.get_children():
            self.tree.delete(row)

        for packet in self.filtered_data:
            self.tree.insert("", tk.END, values=packet)

    # Resets the filters
    def reset_filters(self):
        self.filter_ip_entry.delete(0, tk.END)
        self.filter_protocol_entry.delete(0, tk.END)
        self.filter_port_entry.delete(0, tk.END)
        self.filtered_data = []
        self.update_treeview()

    # Updates the treeview
    def update_treeview(self):
        # Clears the treeview and inserts the original or filtered data
        for row in self.tree.get_children():
            self.tree.delete(row)

        data_to_display = self.filtered_data if self.filtered_data else self.packet_data
        for packet in data_to_display:
            self.tree.insert("", tk.END, values=packet)

    # Clears the packets
    def clear_packets(self):
        self.packet_data.clear()
        self.filtered_data.clear()
        self.update_treeview()
        self.packet_counter_label.config(text="Packets Captured: 0")

    # Save the packet data to a CSV file
    #? Missing option to name the file and where to store it
    def save_packets(self):
        if self.packet_data:
            df = pd.DataFrame(self.packet_data, columns=self.columns)
            df.to_csv("captured_packets.csv", index=False)
            print("Packets saved to captured_packets.csv")
        else:
            print("No packets to save.")


# Starts the program
if __name__ == "__main__":
    root = tk.Tk()
    app = WiresharkApp(root)
    root.mainloop()