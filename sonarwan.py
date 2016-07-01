import sys
import pyshark

def show_progress(pkg_index):
    sys.stdout.write("\rProcessed packets {}".format(pkg_index))
    sys.stdout.flush()

def create_http_stream(pkg):
        if hasattr(pkg.http, 'request'):
            return HTTPStream(pkg.tcp.stream,
                                    ip_src = pkg.ip.src, ip_dst = pkg.ip.dst,
                                    port_src = pkg.tcp.srcport, port_dst = pkg.tcp.dstport)
        return HTTPStream(pkg.tcp.stream,
                                ip_src = pkg.ip.dst, ip_dst = pkg.ip.src,
                                port_src = pkg.tcp.dstport, port_dst = pkg.tcp.srcport)

class Stream(object):

    def __init__(self, number, **kwargs):
        self.number = number
        self.ip_src = kwargs['ip_src']
        self.ip_dst = kwargs['ip_dst']
        self.port_src = kwargs['port_src']
        self.port_dst = kwargs['port_dst']

    def __repr__(self):
        return ' -> '.join(['({} - {})'.format(self.ip_src, self.port_src),
                            '({} - {})'.format(self.ip_dst, self.port_dst)])


class TCPStream(Stream):

    def __init__(self, number, **kwargs):
        super().__init__(number, **kwargs)


class HTTPStream(TCPStream):

    def __init__(self, number, **kwargs):
        super().__init__(number, **kwargs)


class Device(object):

    def __init__(self):
        self.name = 'Unknown device'
        self.model = None
        self.streams = [] # List of Streams

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

    def update(self, pkg):
        app_layer = pkg.layers[-1]

        if app_layer.layer_name == 'http' and hasattr(pkg, 'tcp'):
            stream = create_http_stream(pkg)
            for d in self.devices:
                if stream in d:
                    # update scenario
                    return
            device = Device()
            if hasattr(app_layer, 'user_agent'):
                device.name = app_layer.user_agent
                device.model = app_layer.user_agent.split(',')[0]
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

        i=0
        for pkg in cap:
            i+=1
            show_progress(i)
            protocol = pkg.layers[-1].layer_name
            if protocol in ['http']:
                env.update(pkg)
        print()


if __name__ == '__main__':
    env = Environment()
    reader = SonarWan(environment=env)
    reader.analyze(sys.argv[1])

    env.pretty_print()
