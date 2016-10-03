import pyshark
import sys
import time

from environment import Environment

import utils

import paths


class SonarWan(object):

    def __init__(self):
        self.environment = Environment(config=self.get_config())
        self.i = 0

    def get_config(self):
        with open(paths.USER_AGENT_PATTERNS_FILE) as f:
            user_agent_patterns = f.read().splitlines()

        return {
            'user_agent_patterns': user_agent_patterns
        }

    def analyze(self, path):
        cap = pyshark.FileCapture(path)
        self.environment.prepare()

        for pkg in cap:
            self.i += 1
            utils.show_progress(self.i)
            self.environment.update(pkg)
        print()

    def pretty_print(self):
        self.environment.pretty_print()


if __name__ == '__main__':
    start_time = time.time()
    reader = SonarWan()
    for arg in sys.argv[1:]:
        reader.analyze(arg)

    reader.pretty_print()
    print('Execution time: {}'.format((time.time() - start_time)))
