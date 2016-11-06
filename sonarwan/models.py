import csv
import random


def merge_dicts(base, to_merge, operation):
    for k, v in to_merge.items():
        if k in base:
            base[k] = operation(base[k], v)
        else:
            base[k] = v


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


class Service(object):
    def __init__(self):
        self.activity = {}
        self.characteristics = {}

    def update_service(self, app_args):
        for k in app_args:
            current_value = self.characteristics.get(k)
            new_value = app_args.get(k)

            if (not current_value) or (new_value and
                                       len(new_value) > len(current_value)):
                self.characteristics[k] = new_value

    def add_activity(self, time, bytes_count):
        time_string = time.strftime('%D %H:%M:%S')
        self.activity[time_string] = self.activity.get(time_string,
                                                       0) + int(bytes_count)

    def merge_activity(self, other_activity):
        def sum_fn(v1, v2):
            return v1 + v2

        merge_dicts(self.activity, other_activity, sum_fn)


class AuthorlessService(Service):
    def __init__(self):
        super().__init__()

        # This services can have multiple streams from different devices
        # that are consuming this service. For example WhatsApp can be 
        # used from different devices in same capture

        self.activity_per_stream = {}

    def add_activity_to_stream(self, stream, time, bytes_count):
        time_string = time.strftime('%D %H:%M:%S')
        self.activity_per_stream[stream][
            time_string] = self.activity_per_stream[stream].get(
                time_string, 0) + int(bytes_count)


class Device(object):
    def __init__(self, inference_engine):
        self.services = []
        self.characteristics = {}
        self.activity = {}
        self.stream_to_service = {}

        self.inference_engine = inference_engine

    def add_activity(self, time, bytes_count):
        time_string = time.strftime('%D %H:%M:%S')
        self.activity[time_string] = self.activity.get(time_string,
                                                       0) + int(bytes_count)

    def merge_activity(self, other_activity):
        def sum_fn(v1, v2):
            return v1 + v2

        merge_dicts(self.activity, other_activity, sum_fn)

    def match_score(self, device_args, app_args):
        score = 0

        for k, v in device_args.items():
            sim = similarity(self.characteristics, k, v)
            if sim == -1:
                return -1
            score += sim

        for service in self.services:
            for k, v in app_args.items():
                sim = similarity(service.characteristics, k, v)
                if sim != -1:
                    score += sim

        return score

    def update(self, device_args, app_args, stream_number):

        # Device
        if device_args:
            self.update_device(device_args)

        #Service
        if app_args:
            service = self.update_services(app_args)
            self.stream_to_service[stream_number] = service

    def update_services(self, app_args):
        services = []
        max_score = float('-inf')

        for service in self.services:
            score = 0
            incompatible = False
            for k, v in app_args.items():
                sim = similarity(service.characteristics, k, v)
                if sim == -1:
                    incompatible = True
                    break
                else:
                    score += sim
            if not incompatible:
                if score > 0:
                    if score == max_score:
                        services.append(service)
                    elif score > max_score:
                        max_score, services = score, [service]

        service = None
        if services:
            service = random.choice(services)
        elif app_args:
            service = Service()
            self.services.append(service)

        service.update_service(app_args)

        return service

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


class DeviceLess():
    def __init__(self, services, characteristics, activity):
        self.services = services
        self.characteristics = characteristics
        self.activity = activity


class ServiceLess():
    def __init__(self, characteristics, activity):
        self.characteristics = characteristics
        self.activity = activity
