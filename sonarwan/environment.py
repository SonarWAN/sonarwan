from models import Device
from constants import Transport

import streams
import handlers


class Environment(object):
    def __init__(self, ua_analyzer, inference_engine, ip_analyzer):
        self.devices = []
        self.authorless_services = []

        self.http_handler = handlers.HTTPHandler(self)
        self.tcp_handler = handlers.TCPHandler(self)
        self.dns_handler = handlers.DNSHandler(self)

        self.ua_analyzer = ua_analyzer
        self.inference_engine = inference_engine
        self.ip_analyzer = ip_analyzer

        self.address_host = {}

    def prepare(self):
        self.device_stream_map = {
            Transport.TCP: {},
            Transport.UDP: {},
        }
        self.service_stream_map = {
            Transport.TCP: {},
            Transport.UDP: {},
        }
        self.temporal_stream_map = {
            Transport.TCP: {},
            Transport.UDP: {},
        }

    def update(self, pkg):
        layers = [each.layer_name for each in pkg.layers]
        if 'http' in layers and 'tcp' in layers:
            self.http_handler.process(pkg)
        elif layers[-1] == 'tcp' or 'ssl' in layers:
            self.tcp_handler.process(pkg)
        elif 'dns' == layers[-1]:
            self.dns_handler.process(pkg)

    def find_host(self, address):
        return self.address_host.get(address)

    def previously_analized_stream(self, pkg):
        return self.has_device_from_stream(
            pkg) or self.has_service_from_stream(
                pkg) or self.has_temporal_stream(pkg)

    def has_temporal_stream(self, pkg):
        return self.locate(pkg, self.temporal_stream_map) is not None

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

    def locate_temporal(self, pkg):
        return self.locate(pkg, self.temporal_stream_map)

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
