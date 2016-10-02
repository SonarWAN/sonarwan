import pyshark
import random
import sys
import socket
import time
import re
import csv

from enum import Enum

import streams
import utils


USER_AGENT_PATTERNS_FILE = './user_agents.patterns'


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

def apple_data():
    with open("./data/apple_user_agents.csv") as f:
        csvreader = csv.DictReader(f, delimiter=";")
        return list(csvreader)

APPLE_DATA = apple_data()

def find_apple_data(data, cfnetwork_version=None, darwin_version=None):
    if cfnetwork_version:
        data = (
            row for row in data
            if row['CFNetwork Version number'].split('/')[1] == cfnetwork_version
        )
    if darwin_version:
        data = (
            row for row in data
            if row['Darwin Version'].split('/')[1] == darwin_version
        )
    return next((row['OS Version'].rsplit(' ', 1) for row in data), (None,None))


class Transport(Enum):
    TCP = 1
    UDP = 2


class Device(object):

    def __init__(self):
        self.model = None
        self.streams = []  # List of Streams
        self.services = {}
        self.characteristics = {}
        self._os_version = None
        self.os_name = None

    def __repr__(self):
        return '<Device: {}>'.format(str(self))

    def __str__(self):
        if not any([self.model, self.os_name, self.os_version]):
            return 'Unknown Device'
        return '{} {} {}'.format(self.model, self.os_name, self.os_version)

    def __contains__(self, stream):
        for s in self.streams:
            if s.number == stream.number:
                return True
        return False

    @property
    def os_version(self):
        return self._os_version

    @os_version.setter
    def os_version(self, value):
        if self._os_version is None or len(value) > len(self._os_version):
            self._os_version = value

    def similarity(self, characteristics, k, v):
        if k in characteristics:
            compare_value = characteristics[k]
            length = min(len(compare_value), len(v))
            count = 0

            for i in range(length):
                if compare_value[i] == v[i]:
                    count += 1
                else:
                    return -1
            return count / max(len(compare_value), len(v))
        return 0

    def match_score(self, device_args, app_args):
        args = kwargs.copy()

        # app_name = args.pop('app_name')
        # app_version = args.pop('app_version')

        score = 0

        for k, v in device_args.items():
            sim = self.similarity(self.characteristics, k, v)
            if sim == -1:
                return -1
            score += sim

        for service in self.services:
            for k, v in app_args.items():
                sim = self.similarity(service, k, v)
                if sim != -1:
                    score += sim

        return score

    def update(self, **kwargs):
        if app_name:
            # TODO: check that this is safe
            self.services[app_name] = app_version

        for k in self.characteristics:
            current_value = self.characteristics[k]
            new_value = kwargs.get(k)

            if new_value and len(new_value) > len(current_value):
                self.characteristics[k] = new_value

        if 'cfnetwork_version' in kwargs or 'darwin_version' in kwargs:
            self.use_apple_app_ua(kwargs)

        if 'os_version' in kwargs:
            self.os_version = kwargs['os_version']

        if 'model' in kwargs:
            self.model = kwargs['model']

    def use_apple_app_ua(self, kwargs):
        cfnetwork_version = kwargs.get('cfnetwork_version')
        darwin_version = kwargs.get('darwin_version')
        self.os_name, self.os_version = find_apple_data(
            APPLE_DATA, cfnetwork_version=cfnetwork_version, darwin_version=darwin_version)
        self.characteristics['os_version'] = self.os_version


class Environment(object):

    def __init__(self, config):
        self.devices = []
        self.functions = {
            'http': self.__http_handler,
            # 'dns': self.__dns_handler,
            # 'ssl': self.__ssl_handler,
        }

        if 'user_agent_patterns' in config:
            self.user_agent_patterns = config['user_agent_patterns']

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

        for pattern in self.user_agent_patterns:
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

    def __init__(self):
        self.environment = Environment(config=self.get_config())
        self.i = 0

    def get_config(self):
        with open(USER_AGENT_PATTERNS_FILE) as f:
            user_agent_patterns = f.read().splitlines()

        return {
            'user_agent_patterns': user_agent_patterns
        }

    def analyze(self, path):
        cap = pyshark.FileCapture(path)
        self.environment.prepare()

        for pkg in cap:
            self.i += 1
            utils.show_progress(self.i)
            self.environment.update(pkg)
        print()

    def pretty_print(self):
        self.environment.pretty_print()


if __name__ == '__main__':
    start_time = time.time()
    reader = SonarWan()
    for arg in sys.argv[1:]:
        reader.analyze(arg)

    reader.pretty_print()
    print('Execution time: {}'.format((time.time() - start_time)))
