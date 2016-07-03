def create_http_stream(pkg):
    if hasattr(pkg.http, 'request'):
        return HTTPStream(pkg.tcp.stream,
                          ip_src=pkg.ip.src, ip_dst=pkg.ip.dst,
                          port_src=pkg.tcp.srcport, port_dst=pkg.tcp.dstport)
    return HTTPStream(pkg.tcp.stream,
                      ip_src=pkg.ip.dst, ip_dst=pkg.ip.src,
                      port_src=pkg.tcp.dstport, port_dst=pkg.tcp.srcport)


class Stream(object):

    def __init__(self, number, **kwargs):
        self.number = number
        self.ip_src = kwargs['ip_src']
        self.ip_dst = kwargs['ip_dst']
        self.port_src = kwargs['port_src']
        self.port_dst = kwargs['port_dst']

    def __repr__(self):
        return ' -> '.join(['({} - {})'.format(self.ip_src, self.port_src),
                            '({} - {})'.format(self.ip_dst, self.port_dst)])


class TCPStream(Stream):

    def __init__(self, number, **kwargs):
        super().__init__(number, **kwargs)


class HTTPStream(TCPStream):

    def __init__(self, number, **kwargs):
        super().__init__(number, **kwargs)

