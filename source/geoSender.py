from scapy.all import IP, ICMP, send
import sys
import getopt

def argParse(argv):
    ip = None
    msg = None
    try:
        opts, args = getopt.getopt(argv, "h:m:")
    except:
        print("Argument Error")
    for opt, arg in opts:
        if '-h' in opt:
            ip = arg
        elif '-m' in opt:
            msg = arg
    if ip is None or msg is None:
        print("Either the target host or the message is missing")
        sys.exit(1)
    return ip, msg

def encodePayload(payload):
    stepOne = ''.join(format(ord(c), '08b') for c in payload)
    stepTwo = [stepOne[c:c + 8] for c in range(0, len(stepOne), 8)]
    return stepTwo

def sendData(data):
    payload = encodePayload(data[1])
    ipLayer = IP(dst=data[0])
    for p in payload:
        icmpLayer = ICMP(type=int(p, base=2))
        icmpPacket = ipLayer/icmpLayer
        send(icmpPacket, verbose=True)

def main(argv):
    ip, msg = argParse(argv)
    sendData([ip, msg])

if __name__ == '__main__':
    main(sys.argv[1:])