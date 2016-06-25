import sys
import pyshark


class Device(object):

    def __init__(self):
        self.name = 'Unknown device'
        self.model = None

    def __repr__(self):
        return '<Device: {}>'.format(str(self))

    def __str__(self):
        return self.name


class Environment(object):

    def __init__(self):
        self.devices = []

    def update(self, pkg):
        device = Device()

        app_layer = pkg.layers[-1]
        if app_layer.layer_name == 'http':
            if hasattr(app_layer, 'user_agent'):
                device.name = app_layer.user_agent
                device.model = app_layer.user_agent.split(',')[0]

        self.devices.append(device)


class SonarWan(object):

    def __init__(self, environment):
        self.environment = environment

    def analyze(self, path):
        cap = pyshark.FileCapture(path)

        for pkg in cap:
            protocol = pkg.layers[-1].layer_name
            if protocol in ['http', 'dns']:
                env.update(pkg)


if __name__ == '__main__':
    env = Environment()
    reader = SonarWan(environment=env)
    reader.analyze(sys.argv[1])

    print(env.devices)
