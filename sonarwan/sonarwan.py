import pyshark
import time
import json
import sys
from logger import logger

from environment import Environment
from models import AppLess, DeviceLess, ServiceLess

import utils
import errors

from tools import main_tools


class SonarWan(object):
    def __init__(self, arguments):

        self.arguments = arguments

        try:
            ua_analyzer = main_tools.UserAgentAnalyzer(
                self.arguments.user_patterns_file)

            inference_engine = main_tools.InferenceEngine(
                self.arguments.user_inference_directory)

            service_analyzer = main_tools.ServiceAnalyzer(
                self.arguments.user_services_directory)

        except errors.ServiceDirectoryNotFoundError:
            utils.report_error(
                "--service option passed is not valid directory",
                self.arguments.json_output)
            logger.error(e)
            sys.exit(1)
        except errors.InferenceDirectoryNotFoundError:
            utils.report_error(
                "--inference option passed is not valid directory",
                self.arguments.json_output)
            logger.error(e)
            sys.exit(1)
        except errors.InvalidYAMLServiceFile as e:
            utils.report_error(
                "file {} does not match specified format for YAML service files".
                format(e.filename), self.arguments.json_output)
            logger.error(e)
            sys.exit(1)
        except errors.InvalidCSVInferenceFile:
            utils.report_error(
                "inference csv file does not match specified format for inference files".
                format(e.filename), self.arguments.json_output)
            logger.error(e)
            sys.exit(1)
        except errors.PatternFileNotFileError:
            utils.report_error("--pattern option passed is not valid file",
                               self.arguments.json_output)
            logger.error(e)
            sys.exit(1)
        except:
            utils.report_error("unexpected error occured while loading files",
                               self.arguments.json_output)
            logger.error(e)
            sys.exit(1)

        logger.info('Finish loading tools')
        self.environment = Environment(ua_analyzer, inference_engine,
                                       service_analyzer)

    def show_progress(self, path):
        if not self.arguments.json_output:
            utils.show_progress(self.i)

        elif self.arguments.progress_output and self.i % utils.FRAMES_TO_INFORM == 0:
            utils.inform_json_progress(self.i, path)

    def run(self, files):
        if not all(self.is_valid_file(f) for f in files):
            utils.report_error(
                "invalid files passed. All files must be in pcap or pcapng format",
                self.arguments.json_output)
            sys.exit(1)

        self.start_time = time.time()
        self.i = 0
        self.file_count = 0

        try:
            for each in files:
                logger.info('Processing {}'.format(each[each.rindex('/') +
                                                        1:]))
                self.file_count += 1
                self.analyze(each)

        except Exception as e:
            utils.report_error(
                "Unexpected error occured while proccesing file {}".format(
                    each[each.rindex('/') + 1:]), self.arguments.json_output)
            logger.error(str(e))
            sys.exit(1)

        logger.info('Succesfully analyzed all files')
        self.total_time = time.time() - self.start_time

    def is_valid_file(self, path):
        return path.endswith('.pcap') or path.endswith('.pcapng')

    def analyze(self, path):
        cap = pyshark.FileCapture(path)

        # Should prepare environment first to remove all maps, 
        # as the stream numbers will be repeated between files
        self.environment.prepare()

        for pkg in cap:
            self.i += 1

            self.show_progress(path)
            self.environment.update(pkg)

    def print_info(self):
        if self.arguments.json_output:
            sonarwan_full = SonarwanRep(self)
            print(sonarwan_full.toJSON())
        else:
            utils.pretty_print(self, self.arguments.file_output)


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
            unassigned_services = []
            for each_service in each.unasigned_services:
                unassigned_services.append(ServiceLess(each_service.activity, each_service.name,
                                each_service.type, each_service.ips,
                                each_service.hosts))
            for each_app in each.apps:
                services = []
                for each_service in each_app.services:
                    services.append(
                        ServiceLess(each_service.activity, each_service.name,
                                    each_service.type, each_service.ips,
                                    each_service.hosts))
                apps.append(AppLess(each_app.characteristics, services))

            self.devices.append(
                DeviceLess(unassigned_services, apps, each.characteristics, each.activity))

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
            indent=4,
            sort_keys=True)
