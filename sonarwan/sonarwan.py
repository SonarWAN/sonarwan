import pyshark
import sys
import time
import argparse
import json

from environment import Environment

import utils

from tools import main_tools


class SonarWan(object):
    def __init__(self, json_output, user_patterns_file=None):

        self.environment = Environment(
            ua_analyzer=main_tools.UserAgentAnalyzer(user_patterns_file),
            inference_engine=main_tools.InferenceEngine())
        self.i = 0

        self.json_output = json_output

        self.start_time = time.time()
        self.file_count = 0

    def analyze(self, path):
        cap = pyshark.FileCapture(path)
        self.environment.prepare()
        self.file_count += 1

        for pkg in cap:
            self.i += 1
            if not self.json_output:
                utils.show_progress(self.i)
            self.environment.update(pkg)

    def print_info(self):
        if self.json_output:
            print(self.environment.toJSON())
        else:
            utils.pretty_print(self)


def make_argparse():
    parser = argparse.ArgumentParser(
        description="Recognize devices of a private network by sniffing NAT'd traffic",
        epilog="For suggestions or bug report, go to https://github.com/sonarwan/sonarwan-core"
    )
    parser.add_argument('files', nargs='+', help='list of capture files')
    parser.add_argument("-p", "--patterns", help="user's pattern file")
    parser.add_argument(
        "-j",
        "--json",
        help="outputs information in JSON format.",
        action="store_true")
    return parser


def main():
    args = make_argparse().parse_args()

    sonarwan = SonarWan(args.json, args.patterns)

    for each in args.files:
        sonarwan.analyze(each)

    sonarwan.print_info()


if __name__ == '__main__':
    main()
