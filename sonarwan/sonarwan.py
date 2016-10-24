import pyshark
import sys
import time

from environment import Environment
from arguments import Arguments

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
            print(self.environment.toJSON())
        else:
            utils.pretty_print(self)


def main():
    parser = Arguments.create_parser()
    args = parser.parse_args()
    arguments = Arguments(args.json, args.patterns, args.inference, args.ips)

    sonarwan = SonarWan(arguments)

    for each in args.files:
        sonarwan.analyze(each)

    sonarwan.print_info()


if __name__ == '__main__':
    main()
