from scapy.all import sniff

def packet_callback(packet):
    """
    Esta função corre para cada pacote capturado.
    """
    print(packet.summary())

# Começa à procura de pacotes na interface de rede default
print("Starting packet capture... Press Ctrl+C to stop.")
sniff(prn=packet_callback, count=10)  # Captura 10 pacotes e depois para.