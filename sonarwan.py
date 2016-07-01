import sys
import pyshark

def show_progress(pkg_index):
    sys.stdout.write("\rProcessed packets {}".format(pkg_index))
    sys.stdout.flush()

class Device(object):

    def __init__(self):
        self.name = 'Unknown device'
        self.model = None
        self.streams = set()

    def __repr__(self):
        return '<Device: {}>'.format(str(self))

    def __str__(self):
        return self.name


class Environment(object):

    def __init__(self):
        self.devices = []

    def update(self, pkg):
        app_layer = pkg.layers[-1]

        if app_layer.layer_name == 'http' and hasattr(pkg, 'tcp'):
            for d in self.devices:
                if pkg.tcp.stream in d.streams:
                    # update scenario
                    return
            device = Device()
            if hasattr(app_layer, 'user_agent'):
                device.name = app_layer.user_agent
                device.model = app_layer.user_agent.split(',')[0]
            device.streams.add(pkg.tcp.stream)
            self.devices.append(device)


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
            if protocol in ['http', 'dns']:
                env.update(pkg)
        print()


if __name__ == '__main__':
    env = Environment()
    reader = SonarWan(environment=env)
    reader.analyze(sys.argv[1])

    print(env.devices)
