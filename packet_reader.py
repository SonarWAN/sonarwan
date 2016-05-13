from scapy.all import *
from scapy_http import http
from sys import argv


class Matcher(object):
    def match(self, packet):
        return False

    def emit(self, packet):
        pass


class HttpHeaderMatcher(Matcher):
    header = None
    value = None

    def decode_header(self, packet):
        lst = packet[4].Headers.split(b'\r\n')

        headers = {}
        for header in lst:
            k, v = header.split(b': ')
            headers[k.lower()] = v

        return headers.get(self.header.lower())

    def match(self, packet):
        summary = packet.summary()
        if 'HTTPRequest' not in summary:
            return False

        value = self.decode_header(packet)
        return value and self.value in value

    def emit(self, packet):
        return self.decode_header(packet)


class iPhoneMatcher(HttpHeaderMatcher):
    header = b'User-Agent'
    value = b'iPhone'

class AndroidMatcher(HttpHeaderMatcher):
    header = b'User-Agent'
    value = b'Android'

matchers = [
    iPhoneMatcher(),
    AndroidMatcher(),
]


def main(input, function):
    """Call function on each packet of a large input file"""
    with PcapReader(input) as pcap_reader:
        for pkt in pcap_reader:
            for matcher in matchers:
                if matcher.match(pkt):
                    print(matcher.emit(pkt))

if __name__ == '__main__':
    main(argv[1], lambda p : p.summary())

