import pyshark
import sys
import time
import argparse

from environment import Environment

import utils

from tools import main_tools


class Arguments(object):
    def __init__(self, json_output, user_patterns_file,
                 user_inference_directory):
        self.json_output = json_output
        self.user_patterns_file = user_patterns_file
        self.user_inference_directory = user_inference_directory
        if user_inference_directory and user_inference_directory[-1] != '/':
            self.user_inference_directory = user_inference_directory + '/'

    def create_parser():
        parser = argparse.ArgumentParser(
            description="Recognize devices of a private network by sniffing NAT'd traffic",
            epilog="For suggestions or bug report, go to https://github.com/sonarwan/sonarwan-core"
        )
        parser.add_argument('files', nargs='+', help='List of capture files')
        parser.add_argument("-p", "--patterns", help="User's pattern file")
        parser.add_argument(
            "-i",
            "--inference",
            help="User's directory containing inference csv files")
        parser.add_argument(
            "-j",
            "--json",
            help="outputs information in JSON format.",
            action="store_true")
        return parser


class SonarWan(object):
    def __init__(self, arguments):

        self.arguments = arguments

        ua_analyzer = main_tools.UserAgentAnalyzer(
            self.arguments.user_patterns_file)
        inference_engine = main_tools.InferenceEngine(
            self.arguments.user_inference_directory)
        ip_analyzer = main_tools.IPAnalyzer()

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
    arguments = Arguments(args.json, args.patterns, args.inference)

    sonarwan = SonarWan(arguments)

    for each in args.files:
        sonarwan.analyze(each)

    sonarwan.print_info()


if __name__ == '__main__':
    main()
