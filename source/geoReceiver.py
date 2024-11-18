from scapy.all import sniff, ICMP, IP

def packetHandler(packet):
    if ICMP in packet:
        src = packet[IP].src
        dst = packet[IP].dst
        type = packet[ICMP].type
        print(f'Source: {src} Destination: {dst} Type: {int(type)} Decoded Payload: {chr(type)}')

if __name__ == '__main__':
    sniff(prn=packetHandler)