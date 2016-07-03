class Stream(object):

    def __init__(self, number, **kwargs):
        self.number = number
        self.ip_src = kwargs['ip_src']
        self.ip_dst = kwargs['ip_dst']
        self.port_src = kwargs['port_src']
        self.port_dst = kwargs['port_dst']
        self.address = None

    def __repr__(self):
        return ' -> '.join(['({} - {})'.format(self.ip_src, self.port_src),
                            '({} - {})'.format(self.ip_dst, self.port_dst)])


class TCPStream(Stream):

    def __init__(self, number, **kwargs):
        super().__init__(number, **kwargs)


class HTTPStream(TCPStream):

    def __init__(self, number, **kwargs):
        super().__init__(number, **kwargs)
