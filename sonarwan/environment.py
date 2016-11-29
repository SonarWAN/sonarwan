from models import Device
from constants import Transport
from utils import sort_by_value

import streams
import handlers


class Environment(object):
    """The Environment keeps track of Devices and Authorless Services"""

    def __init__(self, ua_analyzer, inference_engine, service_analyzer):

        self.start_time = None
        self.end_time = None

        self.devices = []
        self.authorless_services = []

        self.http_handler = handlers.HTTPHandler(self)
        self.tcp_handler = handlers.TCPHandler(self)
        self.dns_handler = handlers.DNSHandler(self)
        self.udp_handler = handlers.UDPHandler(self)

        self.ua_analyzer = ua_analyzer
        self.inference_engine = inference_engine

        self.service_analyzer = service_analyzer

        # Cache for DNS queries
        self.address_host = {}

    def sort_authorless_services(self):
        as_map = {}
        for each_authorless_service in self.authorless_services:
            as_map[each_authorless_service] = each_authorless_service.get_size(
            )

        sort_by_value(self.authorless_services, as_map)

    def sort_devices(self):
        d_map = {}
        for each_device in self.devices:
            each_device.sort_apps()
            each_device.sort_unassigned_services()
            d_map[each_device] = each_device.get_size()

        sort_by_value(self.devices, d_map)

    def sort_results(self):
        self.sort_authorless_services()
        self.sort_devices()

    def prepare(self):
        """Resets all stream maps when new file is going to be processed"""

        # Stream to device
        self.device_stream_map = {
            Transport.TCP: {},
            Transport.UDP: {},
        }

        # Stream to service
        self.service_stream_map = {
            Transport.TCP: {},
            Transport.UDP: {},
        }

        # Currently unasigned streams.
        # Saves activity only
        self.temporal_stream_map = {
            Transport.TCP: {},
            Transport.UDP: {},
        }

    def update(self, pkg):
        """A handler will process the package based on type of package"""
        self.update_time_boundaries(pkg.sniff_time)

        if hasattr(pkg, 'ip'):
            layers = [each.layer_name for each in pkg.layers]

            if 'http' in layers and 'tcp' in layers:
                self.http_handler.process(pkg)

            elif layers[-1] == 'tcp' or 'ssl' in layers:
                self.tcp_handler.process(pkg)

            elif 'dns' == layers[-1]:
                self.dns_handler.process(pkg)

            elif 'udp' in layers:
                self.udp_handler.process(pkg)

    def update_time_boundaries(self, time):
        if self.start_time is None:
            self.start_time = time
        if self.end_time is None:
            self.end_time = time
        self.start_time = min(self.start_time, time)
        self.end_time = max(self.end_time, time)

    def find_host(self, address):
        """Returns host if the IP address was answer from a DNS query.
        
        If that IP was answer for many url queries, method return None to avoid
        incorrect behaviour when name of url is url itself (for example x1.wp.com)
        """
        ret = self.address_host.get(address)
        if ret == None or len(ret) > 1:
            return None
        return ret[0]

    def already_exists_authorless_service(self, name):
        for each in self.authorless_services:
            if each.name == name:
                return True
        return False

    def get_existing_authorless_service(self, name):
        for each in self.authorless_services:
            if each.name == name:
                return each
        return None

    def previously_analized_stream(self, pkg):
        """True if corresponds to device, to authorless_service or to temporal"""

        return self.has_device_from_stream(
            pkg) or self.has_service_from_stream(
                pkg) or self.has_temporal_stream(pkg)

    def has_temporal_stream(self, pkg):
        return self.locate(pkg, self.temporal_stream_map) is not None

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
