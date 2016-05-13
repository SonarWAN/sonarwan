from scapy.all import *
from sys import argv

def main(input, function):
    """Call function on each packet of a large input file"""
    with PcapReader(input) as pcap_reader:
        for pkt in pcap_reader:
            print(function(pkt))

if __name__ == '__main__':
    main(argv[1], lambda p : p.summary())

