import pyshark
import random
import sys
import socket
import time
import re

from enum import Enum

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


class Transport(Enum):
    TCP = 1
    UDP = 2


class Device(object):

    def __init__(self):
        self.name = 'Unknown device'
        self.model = None
        self.streams = []  # List of Streams
        self.services = set()
        self.characteristics = {}
        self.os_version = None
        self.os_name = None

    def __repr__(self):
        return '<Device: {}>'.format(str(self))

    def __str__(self):
        return self.name

    def __contains__(self, stream):
        for s in self.streams:
            if s.number == stream.number:
                return True
        return False

    def match_score(self, **kwargs):
        args = kwargs.copy()
        args.pop('app_name')
        args.pop('app_version')

        characteristics = list(self.characteristics.items())
        return sum((k, v) in characteristics for k, v in args.items())

    def update(self, **kwargs):
        app_name = kwargs.pop('app_name', None)
        app_version = kwargs.pop('app_version', None)

        if app_name:
            self.services.add((app_name, app_version))

        self.characteristics.update(**kwargs)


USER_AGENT_PATTERNS = [
    r'(?P<app_name>[^\\]+)\/(?P<app_version>\d+) CFNetwork\/(?P<cfnetwork_version>[\d\.]+) Darwin\/(?P<darwin_version>[\d\.]+)',
]


class Environment(object):

    def __init__(self):
        self.devices = []
        self.map = {
            Transport.TCP: {},
            Transport.UDP: {},
        }
        self.functions = {
            'http': self.__http_handler,
            # 'dns': self.__dns_handler,
            # 'ssl': self.__ssl_handler,
        }

    def update(self, pkg):
        app_layer = pkg.layers[-1]
        func = self.functions.get(app_layer.layer_name, lambda p: None)
        func(pkg)

    def locate(self, pkg):
        try:
            number = pkg.tcp.stream
            transport_prot = Transport.TCP
        except:
            number = pkg.udp.stream
            transport_prot = Transport.UDP
        t = self.map[transport_prot].get(number)

        if not t:
            raise LookupError
        return t

    def create_device(self):
        device = Device()
        self.devices.append(device)
        return device

    def create_or_update_device(self, **kwargs):
        devices = []
        max_score = float('-inf')

        for d in self.devices:
            score = d.match_score(**kwargs)
            if score == max_score:
                devices.append(d)
            elif score > max_score:
                max_score, devices = score, [d]

        if devices:
            device = random.choice(devices)
        else:
            device = self.create_device()

        device.update(**kwargs)
        return device

        device = random.choice(deviceN)

    def analyze_user_agent(self, user_agent):
        device = None

        for pattern in USER_AGENT_PATTERNS:
            match = re.match(pattern, user_agent)
            if match:
                groups = match.groupdict()
                device = self.create_or_update_device(**groups)

        if not device:
            device = self.create_device()

        return device

    def __http_handler(self, pkg):
        # INVESTIGATE, some http packages are not tcp
        if not hasattr(pkg, 'tcp'):
            return

        try:
            device, stream = self.locate(pkg)
        except LookupError:
            if is_request(pkg):
                stream = streams.HTTPStream(
                pkg.tcp.stream, **create_stream_dict(pkg))

                if hasattr(pkg.http, 'user_agent'):
                    user_agent = pkg.http.user_agent
                    device = self.analyze_user_agent(user_agent)

                self.map[Transport.TCP][stream.number] = (device, stream)

    def __dns_handler(self, pkg):
        if is_query(pkg):
            stream = streams.DNSStream(
                pkg.udp.stream, pkg.dns.qry_name, **create_stream_dict(pkg))
            d = Device.from_stream(stream, pkg)
            self.devices.append(d)
            self.map[Transport.UDP][stream.number] = (d, stream)
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
                self.map[Transport.TCP][stream.number] = (d, stream)
            else:
                # TODO handle different tls pkgs
                pass

    def pretty_print(self):
        for d in self.devices:
            print('Device: {}'.format(d))
            for s in d.streams:
                print('\tStream {}: {}'.format(s.get_type(), s))
                print('Services:')
            for service in d.services:
                print('\t {}'.format(service))


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
