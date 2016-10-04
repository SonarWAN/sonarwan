import csv
import random


class Device(object):
    def __init__(self, inference_engine):
        self.streams = []  # List of Streams
        self.services = []  # List of characteristics
        self.characteristics = {}

        self.inference_engine = inference_engine

    def __contains__(self, stream):
        for s in self.streams:
            if s.number == stream.number:
                return True
        return False

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

        for k in device_args:
            current_value = self.characteristics.get(k)
            new_value = device_args.get(k)

            if (not current_value) or (new_value and
                                       len(new_value) > len(current_value)):
                self.characteristics[k] = new_value

        inferences = self.inference_engine.analyze_inference(self.characteristics)
        if inferences:
            self.characteristics.update(inferences)

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
        elif app_args:
            self.services.append(app_args.copy())

