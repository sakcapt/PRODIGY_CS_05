from scapy.all import sniff, IP, TCP, UDP

def analyze(packet):
    if IP in packet:
        src = packet[IP].src
        dst = packet[IP].dst
        proto = packet[IP].proto

        if TCP in packet:
            proto_name = "TCP"
            payload = bytes(packet[TCP].payload)
        elif UDP in packet:
            proto_name = "UDP"
            payload = bytes(packet[UDP].payload)
        else:
            proto_name = "OTHER"
            payload = b""

        print(f"{src} -> {dst} | {proto_name} | Payload: {payload[:30]}")

sniff(prn=analyze, store=False)
