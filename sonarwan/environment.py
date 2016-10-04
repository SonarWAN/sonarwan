from enum import Enum

from device import Device

import streams
import random


def is_query(pkg):
    return not hasattr(pkg.dns, 'a')


def is_request(pkg):
    return hasattr(pkg.http, 'request')


def is_client_hello(pkg):
    return (hasattr(pkg.ssl, 'record') and
            pkg.ssl.record.split(': ')[-1] == 'Client Hello')


def create_stream_dict(pkg):
    transport_pkg = pkg.udp if hasattr(pkg, 'udp') else pkg.tcp
    return {
        'ip_src': pkg.ip.src,
        'ip_dst': pkg.ip.dst,
        'port_src': transport_pkg.srcport,
        'port_dst': transport_pkg.dstport
    }


def get_cipher_suite(pkg):
    l = pkg.ssl._get_all_fields_with_alternates()
    cipher_suite = [x for x in l if x.name == 'ssl.handshake.ciphersuite']
    return list(map(lambda x: (x.raw_value, x.showname_value), cipher_suite))


class Transport(Enum):
    TCP = 1
    UDP = 2


class Environment(object):
    def __init__(self, ua_analyzer, inference_engine):
        self.devices = []
        self.functions = {
            'http': self.__http_handler,
            # 'dns': self.__dns_handler,
            # 'ssl': self.__ssl_handler,
        }

        self.ua_analyzer = ua_analyzer
        self.inference_engine = inference_engine

    def prepare(self):
        self.map = {
            Transport.TCP: {},
            Transport.UDP: {},
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
        device = Device(self.inference_engine)
        self.devices.append(device)
        return device

    def create_or_update_device(self, device_args, app_args):
        devices = []
        max_score = 0
        for d in self.devices:
            score = d.match_score(device_args, app_args)
            if score == max_score:
                devices.append(d)
            elif score > max_score:
                max_score, devices = score, [d]

        if devices:
            device = random.choice(devices)
        else:
            device = self.create_device()

        device.update(device_args, app_args)
        return device

    def analyze_user_agent(self, user_agent):
        device = None

        matchers = self.ua_analyzer.get_best_match(user_agent)
        if matchers[0] or matchers[1]:
            device = self.create_or_update_device(matchers[0], matchers[1])

        return device

    def __http_handler(self, pkg):
        # INVESTIGATE, some http packages are not tcp
        if not hasattr(pkg, 'tcp'):
            return

        try:
            device, stream = self.locate(pkg)
        except LookupError:
            if is_request(pkg):
                stream = streams.HTTPStream(pkg.tcp.stream,
                                            **create_stream_dict(pkg))

                if hasattr(pkg.http, 'user_agent'):
                    user_agent = pkg.http.user_agent
                    device = self.analyze_user_agent(user_agent)

                if device:
                    self.map[Transport.TCP][stream.number] = (device, stream)

    def __dns_handler(self, pkg):
        if is_query(pkg):
            stream = streams.DNSStream(pkg.udp.stream, pkg.dns.qry_name,
                                       **create_stream_dict(pkg))
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
                stream = streams.SSLStream(pkg.tcp.stream,
                                           get_cipher_suite(pkg),
                                           **create_stream_dict(pkg))
                d = Device.from_stream(stream, pkg)
                self.devices.append(d)
                self.map[Transport.TCP][stream.number] = (d, stream)
            else:
                # TODO handle different tls pkgs
                pass

    def pretty_print(self):
        for d in self.devices:
            print('Device: {}'.format(d.characteristics))
            for s in d.streams:
                print('\tStream {}: {}'.format(s.get_type(), s))
                print('Services:')
            for service in d.services:
                print('\t {}'.format(service))
