from enum import Enum

from models import Device, DeviceLess, AuthorlessService

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
    def process(self, pkg):
        # TODO -> only process pkg's originated from network

        if self.needs_processing(pkg):
            service_name = self.environment.ip_analyzer.find_service(
                pkg.ip.dst)
            activity = pkg.sniff_time
            destination = pkg.ip.dst
            if service_name:
                service = self.environment.get_existing_authorless_service(
                    service_name)
                if not service:
                    service = AuthorlessService()
                    service.characteristics['name'] = service_name
                    self.environment.authorless_services.append(service)

                service.activity.append(activity)
                service.add_destination(destination)

                self.environment.device_stream_map[Transport.TCP][
                    pkg.tcp.stream] = service

    def needs_processing(self, pkg):
        return not self.environment.previously_analized_stream(pkg)


class HTTPHandler(Handler):
    def process(self, pkg):

        self.remove_unnecessary_services(pkg)

        t = self.environment.locate_device(pkg)
        if t:
            device, stream = t[0], t[1]
            self.process_existing_stream(pkg, device, stream)
        else:
            if is_request(pkg):
                self.process_new_stream(pkg)

    def remove_unnecessary_services(self, pkg):
        if self.environment.has_service_from_stream(pkg):
            service = self.environment.locate_service(pkg)
            self.environment.authorless_services.remove(service)

            d_copy = dict(self.environment.service_stream_map)
            for k, v in self.environment.service_stream_map.items():
                if v == service:
                    del d_copy[key]
            self.environment.service_stream_map = d_copy

    def process_existing_stream(self, pkg, device, stream):
        if hasattr(pkg.http, 'user_agent'):
            user_agent = pkg.http.user_agent
            self.analyze_user_agent(user_agent, stream, pkg.sniff_time, device)

    def process_new_stream(self, pkg):
        stream = streams.HTTPStream(pkg.tcp.stream, **create_stream_dict(pkg))

        if hasattr(pkg.http, 'user_agent'):
            user_agent = pkg.http.user_agent
            self.analyze_user_agent(user_agent, stream, pkg.sniff_time)

    def analyze_user_agent(self,
                           user_agent,
                           stream,
                           activity_time,
                           device_param=None):

        matchers = self.environment.ua_analyzer.get_best_match(user_agent)

        device_args = matchers.get('device_args')
        app_args = matchers.get('app_args')

        destination = {'ip': stream.ip_dst, 'port': stream.port_dst}

        if device_args or app_args:
            device = self.create_or_update_device(device_args, app_args,
                                                  activity_time, destination)
            if not device_param:
                device.streams.append(stream)
                self.environment.device_stream_map[Transport.TCP][
                    stream.number] = (device, stream)
            else:
                device_param.update(device_args, app_args, activity_time,
                                    destination)

    def create_or_update_device(self, device_args, app_args, activity_time,
                                destination):
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

        device.update(device_args, app_args, activity_time, destination)
        return device


class Environment(object):
    def __init__(self, ua_analyzer, inference_engine, ip_analyzer):
        self.devices = []
        self.authorless_services = []

        self.http_handler = HTTPHandler(self)
        self.tcp_handler = TCPHandler(self)

        self.ua_analyzer = ua_analyzer
        self.inference_engine = inference_engine
        self.ip_analyzer = ip_analyzer

    def prepare(self):
        self.device_stream_map = {
            Transport.TCP: {},
            Transport.UDP: {},
        }
        self.service_stream_map = {
            Transport.TCP: {},
            Transport.UDP: {},
        }

    def update(self, pkg):
        app_layer = pkg.layers[-1]
        if app_layer.layer_name == 'http' and pkg.layers[
                -2].layer_name == 'tcp':
            self.http_handler.process(pkg)
        elif app_layer.layer_name == 'ssl' or app_layer.layer_name == 'tcp':
            self.tcp_handler.process(pkg)

    def previously_analized_stream(self, pkg):
        return self.has_device_from_stream(
            pkg) or self.has_service_from_stream(pkg)

    def has_authorless_service(self, name):
        for each in self.authorless_services:
            if each.characteristics['name'] == name:
                return True
        return False

    def get_existing_authorless_service(self, name):
        for each in self.authorless_services:
            if each.characteristics['name'] == name:
                return each
        return None

    def has_device_from_stream(self, pkg):
        return self.locate_device(pkg) is not None

    def has_service_from_stream(self, pkg):
        return self.locate_service(pkg) is not None

    def locate_device(self, pkg):
        return self.locate(pkg, self.device_stream_map)

    def locate_service(self, pkg):
        return self.locate(pkg, self.service_stream_map)

    def locate(self, pkg, structure):
        try:
            number = pkg.tcp.stream
            transport_prot = Transport.TCP
        except:
            number = pkg.udp.stream
            transport_prot = Transport.UDP
        return structure[transport_prot].get(number)

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
        devices_less = []
        for each in self.devices:
            devices_less.append(
                DeviceLess(each.streams, each.services, each.characteristics,
                           each.activity))

        env_less = EnvironmentLess(devices_less, self.authorless_services)

        return json.dumps(
            env_less,
            default=lambda o: o.__dict__ if hasattr(o, '__dict__') else str(o),
            sort_keys=True,
            indent=4)


class EnvironmentLess(object):
    def __init__(self, devices, authorless_services):
        self.devices = devices
        self.authorless_services = authorless_services
