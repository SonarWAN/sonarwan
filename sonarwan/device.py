import csv
import random

import paths


def apple_data():
    with open(paths.INFERENCE_DIR + 'apple_inference.csv') as f:
        csvreader = csv.DictReader(f, delimiter=";")
        return list(csvreader)


APPLE_DATA = apple_data()


def find_apple_data(data, cfnetwork_version=None, darwin_version=None):
    if cfnetwork_version:
        data = (row for row in data
                if row['CFNetwork Version number'].split('/')[1] ==
                cfnetwork_version)
    if darwin_version:
        data = (row for row in data
                if row['Darwin Version'].split('/')[1] == darwin_version)
    return next((row['OS Version'].rsplit(' ', 1)
                 for row in data), (None, None))


class Device(object):
    def __init__(self):
        self.model = None
        self.streams = []  # List of Streams
        self.services = []  # List of characteristics
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

    def update(self, device_args, app_args):
        # if app_name:
        #     # TODO: check that this is safe
        #     self.services[app_name] = app_version

        for k in device_args:
            current_value = self.characteristics.get(k)
            new_value = device_args.get(k)

            if (not current_value) or (new_value and
                                       len(new_value) > len(current_value)):
                self.characteristics[k] = new_value

        services = []
        max_score = float('-inf')

        for service in self.services:
            score = 0
            incompatible = False
            for k, v in app_args.items():
                sim = self.similarity(service, k, v)
                if sim == -1:
                    incompatible = True
                else:
                    score += sim
            if not incompatible:
                if score == max_score:
                    services.append(service)
                elif score > max_score:
                    max_score, services = score, [service]

        if services:
            service = random.choice(services)
            for k in service:
                current_value = service[k]
                new_value = app_args.get(k)

                if new_value and len(new_value) > len(current_value):
                    service[k] = new_value
        else:
            self.services.append(app_args.copy())

        # TODO inferenca
        if 'cfnetwork_version' in device_args or 'darwin_version' in device_args:
            self.use_apple_app_ua(device_args)

        if 'os_version' in device_args:
            self.os_version = device_args['os_version']

        if 'model' in device_args:
            self.model = device_args['model']

    def use_apple_app_ua(self, kwargs):
        cfnetwork_version = kwargs.get('cfnetwork_version')
        darwin_version = kwargs.get('darwin_version')
        self.os_name, self.os_version = find_apple_data(
            APPLE_DATA,
            cfnetwork_version=cfnetwork_version,
            darwin_version=darwin_version)
        self.characteristics['os_version'] = self.os_version
