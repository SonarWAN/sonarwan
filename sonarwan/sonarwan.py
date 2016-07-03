import pyshark
import sys
import socket

import streams
import utils


def create_http_stream(pkg):
    if hasattr(pkg.http, 'request'):
        stream = streams.HTTPStream(pkg.tcp.stream,
                                    ip_src=pkg.ip.src, ip_dst=pkg.ip.dst,
                                    port_src=pkg.tcp.srcport, port_dst=pkg.tcp.dstport)
    else:
        stream = streams.HTTPStream(pkg.tcp.stream,
                                    ip_src=pkg.ip.dst, ip_dst=pkg.ip.src,
                                    port_src=pkg.tcp.dstport, port_dst=pkg.tcp.srcport)
    try:
        stream.address = socket.gethostbyaddr(str(stream.ip_dst))[0]
    except socket.herror:
        pass
    return stream


class Device(object):

    def __init__(self):
        self.name = 'Unknown device'
        self.model = None
        self.streams = []  # List of Streams

    def __repr__(self):
        return '<Device: {}>'.format(str(self))

    def __str__(self):
        return self.name

    def add_stream(self, stream):
        self.streams.append(stream)

    def __contains__(self, stream):
        for s in self.streams:
            if s.number == stream.number:
                return True
        return False


class Environment(object):

    def __init__(self):
        self.devices = []
        self.functions = {
            'http': self.__update_http,
            'dns': self.__update_dns,
        }

    def update(self, pkg):
        app_layer = pkg.layers[-1]
        func = self.functions.get(app_layer.layer_name, lambda p: None)
        func(pkg)

    def __update_dns(self, pkg):
        pass

    def __update_http(self, pkg):
        if hasattr(pkg, 'tcp'):
            stream = create_http_stream(pkg)
            for d in self.devices:
                if stream in d:
                    # update scenario
                    return
            device = Device()
            if hasattr(pkg.http, 'user_agent'):
                device.name = pkg.http.user_agent
                device.model = pkg.http.user_agent.split(',')[0]
            device.add_stream(stream)
            self.devices.append(device)

    def pretty_print(self):
        for d in self.devices:
            print('Device: {}'.format(d))
            for s in d.streams:
                print('\tStream {}: {}'.format(s.number, s))


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
    env = Environment()
    reader = SonarWan(environment=env)
    reader.analyze(sys.argv[1])

    env.pretty_print()
