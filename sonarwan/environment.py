from enum import Enum

from models import Device, DeviceLess

import streams

import json
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


class Handler(object):
    def __init__(self, environment):
        self.environment = environment

class TCPHandler(Handler):
    pass

class HTTPHandler(Handler):
    def process(self, pkg):
        if not hasattr(pkg, 'tcp'):
            return

        try:
            device, stream = self.environment.locate_device(pkg)
            self.process_existing_stream(pkg, device, stream)
        except LookupError:
            if is_request(pkg):
                self.process_new_stream(pkg)

    def process_existing_stream(self, pkg, device, stream):
        if hasattr(pkg.http, 'user_agent'):
            user_agent = pkg.http.user_agent
            self.analyze_user_agent(user_agent, stream, pkg.sniff_time, device)

    def process_new_stream(self, pkg):
        stream = streams.HTTPStream(pkg.tcp.stream, **create_stream_dict(pkg))

        if hasattr(pkg.http, 'user_agent'):
            user_agent = pkg.http.user_agent
            self.analyze_user_agent(user_agent, stream, pkg.sniff_time)

    def analyze_user_agent(self, user_agent, stream, activity_time, device_param=None):

        matchers = self.environment.ua_analyzer.get_best_match(user_agent)

        device_args = matchers.get('device_args')
        app_args = matchers.get('app_args')

        destiny = {'ip': stream.ip_dst, 'port': stream.port_dst}

        if device_args or app_args:
            device = self.create_or_update_device(device_args, app_args,
                                                  activity_time, destiny)
            if not device_param:
                device.streams.append(stream)
                self.environment.device_stream_map[Transport.TCP][stream.number] = (device,
                                                                      stream)
            else:
                device_param.update(device_args, app_args, activity_time, destiny)



    def create_or_update_device(self, device_args, app_args, activity_time,
                                destiny):
        devices = []
        max_score = 0
        for d in self.environment.devices:
            score = d.match_score(device_args, app_args)
            if max_score > 0 and score == max_score:
                devices.append(d)
            elif score > max_score:
                max_score, devices = score, [d]

        if devices:
            device = random.choice(devices)
        else:
            device = self.environment.create_device()

        device.update(device_args, app_args, activity_time, destiny)
        return device


class Environment(object):
    def __init__(self, ua_analyzer, inference_engine, ip_analyzer):
        self.devices = []
        self.authorless_services = []

        self.http_handler = HTTPHandler(self)
        self.tcp_handler = TCPHandler(self)

        self.handlers = {
            'http': self.http_handler,
            # 'tcp':self.tcp_handler,
            # 'dns': self.__dns_handler,
            # 'ssl': self.__ssl_handler,
        }
        self.ua_analyzer = ua_analyzer
        self.inference_engine = inference_engine
        self.ip_analyzer = ip_analyzer

    def prepare(self):
        self.device_stream_map = {
            Transport.TCP: {},
            Transport.UDP: {},
        }

    def update(self, pkg):
        app_layer = pkg.layers[-1]
        handler = self.handlers.get(app_layer.layer_name)
        if handler:
            handler.process(pkg)

    def locate_device(self, pkg):
        try:
            number = pkg.tcp.stream
            transport_prot = Transport.TCP
        except:
            number = pkg.udp.stream
            transport_prot = Transport.UDP
        t = self.device_stream_map[transport_prot].get(number)

        if not t:
            raise LookupError
        return t

    def create_device(self):
        device = Device(self.inference_engine)
        self.devices.append(device)
        return device

    # def __dns_handler(self, pkg):
    #     if is_query(pkg):
    #         stream = streams.DNSStream(pkg.udp.stream, pkg.dns.qry_name,
    #                                    **create_stream_dict(pkg))
    #         d = Device.from_stream(stream, pkg)
    #         self.devices.append(d)
    #         self.map[Transport.UDP][stream.number] = (d, stream)
    #     else:
    #         pass

    # def __ssl_handler(self, pkg):
    #     try:
    #         device, stream = self.locate(pkg)
    #         device.update(stream, pkg)
    #         return
    #     except LookupError:
    #         if is_client_hello(pkg):
    #             stream = streams.SSLStream(pkg.tcp.stream,
    #                                        get_cipher_suite(pkg),
    #                                        **create_stream_dict(pkg))
    #             d = Device.from_stream(stream, pkg)
    #             self.devices.append(d)
    #             self.map[Transport.TCP][stream.number] = (d, stream)
    #         else:
    #             # TODO handle different tls pkgs
    #             pass

    def toJSON(self):
        aux_devices = []
        for each in self.devices:
            aux_devices.append(
                DeviceLess(each.streams, each.services, each.characteristics,
                           each.activity))

        return json.dumps(
            aux_devices,
            default=lambda o: o.__dict__ if hasattr(o, '__dict__') else str(o),
            sort_keys=True,
            indent=4)
