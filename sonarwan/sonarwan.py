import pyshark
import sys
import socket
import time

import streams
import utils


def is_query(pkg):
    return not hasattr(pkg.dns, 'a')


def is_request(pkg):
    return hasattr(pkg.http, 'request')


def is_client_hello(pkg):
    return (hasattr(pkg.ssl, 'record') and
            pkg.ssl.record.split(': ')[-1] == 'Client Hello')


def create_stream_dict(pkg):
    transport_pkg = pkg.udp if hasattr(pkg, 'udp') else pkg.tcp
    return {'ip_src': pkg.ip.src, 'ip_dst': pkg.ip.dst,
            'port_src': transport_pkg.srcport, 'port_dst': transport_pkg.dstport}


def get_cipher_suite(pkg):
    l = pkg.ssl._get_all_fields_with_alternates()
    cipher_suite = [x for x in l if x.name == 'ssl.handshake.ciphersuite']
    return list(map(lambda x: (x.raw_value, x.showname_value), cipher_suite))


class Device(object):

    def __init__(self):
        self.name = 'Unknown device'
        self.model = None
        self.streams = []  # List of Streams

    @classmethod
    def from_stream(cls, stream, pkg):
        device = cls()
        device.streams.append(stream)
        # TODO improve style
        if type(stream) is streams.HTTPStream:
            if hasattr(pkg.http, 'user_agent'):
                device.name = pkg.http.user_agent
                device.model = pkg.http.user_agent.split(',')[0]
        return device

    def __repr__(self):
        return '<Device: {}>'.format(str(self))

    def __str__(self):
        return self.name

    def __contains__(self, stream):
        for s in self.streams:
            if s.number == stream.number:
                return True
        return False

    def update(self, stream, pkg):
        # TODO update device when response come
        # Calls stream.update(pkg)
        pass


class Environment(object):

    def __init__(self):
        self.devices = []
        self.map = {'tcp': {}, 'udp': {}}
        self.functions = {
            'http': self.__http_handler,
            'dns': self.__dns_handler,
            'ssl': self.__ssl_handler,
        }

    def update(self, pkg):
        app_layer = pkg.layers[-1]
        func = self.functions.get(app_layer.layer_name, lambda p: None)
        func(pkg)

    def locate(self, pkg):
        try:
            number = pkg.tcp.stream
            transport_prot = 'tcp'
        except:
            number = pkg.udp.stream
            transport_prot = 'udp'
        t = self.map[transport_prot].get(number)
        if t:
            return t
        raise LookupError

    def __http_handler(self, pkg):
        # INVESTIGATE, some http packages are not tcp
        if not hasattr(pkg, 'tcp'):
            return

        try:
            device, stream = self.locate(pkg)
            device.update(stream, pkg)
            return
        except LookupError:
            if is_request(pkg):  # NOT neccesary, if it is response it must have been located
                stream = streams.HTTPStream(
                    pkg.tcp.stream, **create_stream_dict(pkg))
                d = Device.from_stream(stream, pkg)
                self.devices.append(d)
                self.map['tcp'][stream.number] = (d, stream)

    def __dns_handler(self, pkg):
        if is_query(pkg):
            stream = streams.DNSStream(
                pkg.udp.stream, pkg.dns.qry_name, **create_stream_dict(pkg))
            d = Device.from_stream(stream, pkg)
            self.devices.append(d)
            self.map['udp'][stream.number] = (d, stream)
        else:
            pass

    def __ssl_handler(self, pkg):
        try:
            device, stream = self.locate(pkg)
            device.update(stream, pkg)
            return
        except LookupError:
            if is_client_hello(pkg):
                stream = streams.SSLStream(
                    pkg.tcp.stream, get_cipher_suite(pkg),
                    **create_stream_dict(pkg))
                d = Device.from_stream(stream, pkg)
                self.devices.append(d)
                self.map['tcp'][stream.number] = (d, stream)
            else:
                # TODO handle different tls pkgs
                pass

    def pretty_print(self):
        for d in self.devices:
            print('Device: {}'.format(d))
            for s in d.streams:
                print('\tStream {}: {}'.format(s.get_type(), s))


class SonarWan(object):

    def __init__(self, environment):
        self.environment = environment

    def analyze(self, path):
        cap = pyshark.FileCapture(path)

        i = 0
        for pkg in cap:
            i += 1
            utils.show_progress(i)
            env.update(pkg)
        print()


if __name__ == '__main__':
    start_time = time.time()
    env = Environment()
    reader = SonarWan(environment=env)
    reader.analyze(sys.argv[1])

    env.pretty_print()
    print('Execution time: {}'.format((time.time() - start_time)))
