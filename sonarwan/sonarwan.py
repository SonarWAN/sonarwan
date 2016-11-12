import pyshark
import time
import json

from environment import Environment
from models import AppLess, DeviceLess, ServiceLess

import utils

from tools import main_tools


class SonarWan(object):
    def __init__(self, arguments):

        self.arguments = arguments

        ua_analyzer = main_tools.UserAgentAnalyzer(
            self.arguments.user_patterns_file)

        inference_engine = main_tools.InferenceEngine(
            self.arguments.user_inference_directory)

        service_analyzer = main_tools.ServiceAnalyzer(
            self.arguments.user_services_directory)

        self.environment = Environment(ua_analyzer, inference_engine,
                                       service_analyzer)

    def show_progress(self):
        if not self.arguments.json_output:
            utils.show_progress(self.i)

        elif self.arguments.progress_output and self.i % utils.FRAMES_TO_INFORM == 0:
            utils.inform_json_progress(self.i, path)

    def run(self, files):
        self.start_time = time.time()
        self.i = 0
        self.file_count = 0

        for each in files:
            self.file_count += 1
            self.analyze(each)

        self.total_time = time.time() - self.start_time

    def analyze(self, path):
        cap = pyshark.FileCapture(path)

        # Should prepare environment first to remove all maps, 
        # as the stream numbers will be repeated between files
        self.environment.prepare()

        for pkg in cap:
            self.i += 1

            self.show_progress()
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
        self.execution_time = int(sonarwan.total_time * 100) / 100
        self.files = sonarwan.file_count


class SonarwanRep(object):
    def __init__(self, sonarwan):
        self.summary = Summary(sonarwan)

        self.init_devices(sonarwan.environment.devices)
        self.init_services(sonarwan.environment.authorless_services)

    def init_devices(self, devices):
        """Generates device list with only neccessary info for JSON output"""

        self.devices = []
        for each in devices:
            apps = []
            for each_app in each.apps:
                services = []
                for each_service in each_app.services:
                    services.append(
                        ServiceLess(each_service.activity, each_service.name,
                                    each_service.type, each_service.ips,
                                    each_service.hosts))
                apps.append(AppLess(each_app.characteristics, services))

            self.devices.append(
                DeviceLess(apps, each.characteristics, each.activity))

    def init_services(self, services):
        """Generates authorless service list with only neccessary info for JSON output"""

        self.authorless_services = []
        for each in services:
            self.authorless_services.append(
                ServiceLess(each.activity, each.name, each.type, each.ips,
                            each.hosts))

    def toJSON(self):
        """
        This will go recursively inside summary (Summary), devices (DeviceLess) and 
        authorless services (ServiceLess) and will return an appropiate JSON representation.
        """
        return json.dumps(
            {
                'Report': self
            },
            default=lambda o: o.__dict__,
            sort_keys=True,
            indent=4)
