import pyshark
import sys

import streams
import utils

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

    def update(self, pkg):
        app_layer = pkg.layers[-1]

        if app_layer.layer_name == 'http' and hasattr(pkg, 'tcp'):
            stream = streams.create_http_stream(pkg)
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

        i = 0
        for pkg in cap:
            i += 1
            utils.show_progress(i)
            protocol = pkg.layers[-1].layer_name
            if protocol in ['http']:
                env.update(pkg)
        print()


if __name__ == '__main__':
    env = Environment()
    reader = SonarWan(environment=env)
    reader.analyze(sys.argv[1])

    env.pretty_print()
