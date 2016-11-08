import csv
import random
from constants import Transport


def merge_dicts(base, to_merge, operation):
    for k, v in to_merge.items():
        if k in base:
            base[k] = operation(base[k], v)
        else:
            base[k] = v


def unmerge_dicts(base, to_unmerge, operation):
    for k, v in to_unmerge.items():
        if k in base:
            base[k] = operation(base[k], v)


def similarity(base, k, v):
    if k in base:
        compare_value = base[k]
        length = min(len(compare_value), len(v))
        count = 0

        for i in range(length):
            if (not compare_value[i].isalnum() and not v[i].isalnum()
                ) or compare_value[i].upper() == v[i].upper():
                count += 1
            else:
                return -1
        return count / max(len(compare_value), len(v))
    return 0


class AuxiliaryDataManager(object):
    def add_activity(self, time, bytes_count):
        time_string = time.strftime('%D %H:%M:%S')
        self.activity[time_string] = self.activity.get(time_string,
                                                       0) + int(bytes_count)

    def add_visited_host(self, host, ip):
        if host not in self.visited_hosts:
            self.visited_hosts[host] = set()
        self.visited_hosts[host].add(ip)

    def merge_activity(self, other_activity):
        def sum_fn(v1, v2):
            return v1 + v2

        merge_dicts(self.activity, other_activity, sum_fn)


class App(object):
    def __init__(self):

        self.characteristics = {}
        self.services = []

        self.stream_to_service = {}

    def update_app(self, app_args):
        for k in app_args:
            current_value = self.characteristics.get(k)
            new_value = app_args.get(k)

            if (not current_value) or (new_value and
                                       len(new_value) > len(current_value)):
                self.characteristics[k] = new_value

    def process_service(self, service, time, length, stream_number):
        existing = False
        curr_service = service

        for each in self.services:
            if each.name == service.name:
                existing = True
                curr_service = each
                break

        if not existing:
            self.services.append(curr_service)

        curr_service.add_activity(time, length)
        self.stream_to_service[stream_number] = curr_service


class Service(AuxiliaryDataManager):
    def __init__(self):
        self.activity = {}
        self.name = None
        self.type = None
        self.ips = set()

    @classmethod
    def from_characteristics(cls, characteristics):
        service = cls()
        service.name = characteristics.get('name') or 'Unknown'
        service.type = characteristics.get('type') or 'Unknown'
        return service


class AuthorlessService(Service):
    def __init__(self):
        super().__init__()

        # This services can have multiple streams from different devices
        # that are consuming this service. For example WhatsApp can be 
        # used from different devices in same capture

        self.activity_per_stream = {Transport.UDP: {}, Transport.TCP: {}}

    def add_activity_to_stream(self, protocol, stream, time, bytes_count):
        time_string = time.strftime('%D %H:%M:%S')

        if stream not in self.activity_per_stream[protocol]:
            self.activity_per_stream[protocol][stream] = {}

        self.activity_per_stream[protocol][stream][
            time_string] = self.activity_per_stream[protocol][stream].get(
                time_string, 0) + int(bytes_count)

    def remove_activity_from_stream(self, protocol, stream):
        def substract_fn(v1, v2):
            return v1 - v2

        unmerge_dicts(self.activity,
                      self.activity_per_stream[protocol][stream], substract_fn)
        del self.activity_per_stream[protocol][stream]

    def is_empty(self):
        return self.activity_per_stream[
            Transport.TCP] == {} and self.activity_per_stream[
                Transport.UDP] == {}


class Device(AuxiliaryDataManager):
    def __init__(self, inference_engine):
        self.apps = []
        self.characteristics = {}
        self.activity = {}

        self.stream_to_app = {}

        self.inference_engine = inference_engine

    def match_score(self, device_args, app_args):
        score = 0

        for k, v in device_args.items():
            sim = similarity(self.characteristics, k, v)
            if sim == -1:
                return -1
            score += sim

        for app in self.apps:
            for k, v in app_args.items():
                sim = similarity(app.characteristics, k, v)
                if sim != -1:
                    score += sim

        return score

    def update(self, device_args, app_args, stream_number):

        # Device
        if device_args:
            self.update_device(device_args)

        #Service
        if app_args:
            app = self.update_apps(app_args)
            self.stream_to_app[stream_number] = app

    def update_apps(self, app_args):
        apps = []
        max_score = float('-inf')

        for each_app in self.apps:
            score = 0
            incompatible = False
            for k, v in app_args.items():
                sim = similarity(each_app.characteristics, k, v)
                if sim == -1:
                    incompatible = True
                    break
                else:
                    score += sim
            if not incompatible:
                if score > 0:
                    if score == max_score:
                        apps.append(each_app)
                    elif score > max_score:
                        max_score, apps = score, [each_app]

        app = None
        if apps:
            app = random.choice(apps)
        elif app_args:
            app = App()
            self.apps.append(app)

        app.update_app(app_args)

        return app

    def update_device(self, device_args):
        for k in device_args:
            current_value = self.characteristics.get(k)
            new_value = device_args.get(k)

            if (not current_value) or (new_value and
                                       len(new_value) > len(current_value)):
                self.characteristics[k] = new_value

        inferences = self.inference_engine.analyze_inference(
            self.characteristics)
        if inferences:
            self.characteristics.update(inferences)

    def get_service(self, stream_number):
        app = self.stream_to_app.get(stream_number)
        if not app:
            return None
        return app.stream_to_service[stream_number]


class DeviceLess():
    pass
#     def __init__(self, services, characteristics, activity):
#         self.services = services
#         self.characteristics = characteristics
#         self.activity = activity


class AppLess():
    pass
#     def __init__(self, characteristics, activity):
#         self.characteristics = characteristics
#         self.activity = activity
