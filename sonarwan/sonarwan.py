import pyshark
import sys
import time
import json

from environment import Environment
from models import ServiceLess, DeviceLess

import utils

from tools import main_tools


class SonarWan(object):
    def __init__(self, arguments):

        self.arguments = arguments

        ua_analyzer = main_tools.UserAgentAnalyzer(
            self.arguments.user_patterns_file)
        inference_engine = main_tools.InferenceEngine(
            self.arguments.user_inference_directory)
        ip_analyzer = main_tools.IPAnalyzer(self.arguments.user_ips_directory)

        self.environment = Environment(ua_analyzer, inference_engine,
                                       ip_analyzer)
        self.i = 0

        self.start_time = time.time()
        self.file_count = 0

    def analyze(self, path):
        cap = pyshark.FileCapture(path)
        self.environment.prepare()
        self.file_count += 1

        for pkg in cap:
            self.i += 1
            if not self.arguments.json_output:
                utils.show_progress(self.i)
            self.environment.update(pkg)

    def print_info(self):
        if self.arguments.json_output:
            sonarwan_full = SonarwanRep(self)
            print(sonarwan_full.toJSON())
        else:
            utils.pretty_print(self)


class Summary(object):
    def __init__(self, sonarwan):
        self.devices = len(sonarwan.environment.devices)
        self.authorless_services = len(
            sonarwan.environment.authorless_services)
        self.packets = sonarwan.i
        self.execution_time = int(
            (time.time() - sonarwan.start_time) * 100) / 100
        self.files = sonarwan.file_count


class SonarwanRep(object):
    def __init__(self, sonarwan):
        self.summary = Summary(sonarwan)

        self.init_devices(sonarwan.environment.devices)
        self.init_services(sonarwan.environment.authorless_services)

    def init_devices(self, devices):
        self.devices = []
        for each in devices:
            self.services = []
            for s in each.services:
                self.services.append(
                    ServiceLess(s.characteristics, s.activity))
            self.devices.append(
                DeviceLess(self.services, each.characteristics, each.activity))

    def init_services(self, services):
        self.authorless_services = []
        for each in services:
            self.authorless_services.append(
                ServiceLess(each.characteristics, each.activity))

    def toJSON(self):
        return json.dumps(
            self, default=lambda o: o.__dict__, sort_keys=True, indent=4)
