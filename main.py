import platform
from scapy.all import sniff, conf

def packet_callback(packet):
    #Função que roda para cada pacote capturado.
    print(packet.summary())

# Deteta o sistema operativo
os_type = platform.system()

if os_type == "Windows":
    print("Detected Windows OS. Configuring for Npcap/WinPcap...")
    conf.use_pcap = True  # Usa o Npcap ou o Winpcap para o Windows
elif os_type == "Darwin":  # macOS
    print("Detected macOS. Using default configuration...")
else:
    print(f"Unsupported OS: {os_type}. Exiting.")
    exit(1)

# Começa à procuras
print("Starting packet capture... Press Ctrl+C to stop.")
sniff(prn=packet_callback, count=100000)  # Captura 10 pacotes e para.