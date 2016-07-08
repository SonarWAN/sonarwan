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

    def get_type(self):
        return ''


class UDPStream(Stream):

    def __init__(self, number, **kwargs):
        super().__init__(number, **kwargs)


class DNSStream(UDPStream):

    def __init__(self, number, domain_name, **kwargs):
        super().__init__(number, **kwargs)
        self.domain_name = domain_name

    def __repr__(self):
        return 'query for {}'.format(self.domain_name)

    def get_type(self):
        return 'DNS'


class TCPStream(Stream):

    def __init__(self, number, **kwargs):
        super().__init__(number, **kwargs)


class HTTPStream(TCPStream):

    def __init__(self, number, **kwargs):
        super().__init__(number, **kwargs)

    def get_type(self):
        return 'HTTP'


class SSLStream(TCPStream):

    def __init__(self, number, cipher_suite=[], **kwargs):
        super().__init__(number, **kwargs)
        self.cipher_suite = cipher_suite

    def get_type(self):
        return 'SSL'
