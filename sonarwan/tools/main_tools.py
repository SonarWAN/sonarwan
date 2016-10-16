import paths
import re
import csv
from os import listdir
from os.path import isfile, join

from ua_parser import user_agent_parser

from tools.mobile_detector import MobileDetector


class InferenceEngine(object):
    def __init__(self):
        self.load_inference_files()

    def load_inference_files(self):
        self.inference_list = []

        path = paths.INFERENCE_DIR
        onlycsv = [f for f in listdir(path) if isfile(join(path, f))]
        onlycsv = filter(lambda x: x[-4:] == '.csv', onlycsv)
        onlycsv = map(lambda x: path + x, onlycsv)
        for each in onlycsv:
            with open(each) as f:
                csvreader = csv.DictReader(f, delimiter=";")
                self.inference_list.extend(list(csvreader))

    def analyze_inference(self, characteristics):
        candidates = [
            InferenceEngine.useful_data(characteristics, x)
            for x in self.inference_list
            if InferenceEngine.match_characteristic(characteristics, x)
        ]
        non_deterministic = set()
        ret = {}
        for each in candidates:
            for k, v in each.items():
                if k in ret.keys():
                    common = InferenceEngine.common_initial_substring(v,
                                                                      ret[k])
                    if common:
                        ret[k] = common
                    else:
                        non_deterministic.add(k)
                else:
                    ret[k] = v
        for each in non_deterministic:
            del ret[each]

        return ret

    def common_initial_substring(s1, s2):
        min_len = min(len(s1), len(s2))
        ret = ''
        for i in range(min_len):
            if s1[i].upper() != s2[i].upper():
                return ret
            else:
                ret += s1[i]
        return ret

    def useful_data(characteristics, base):
        return {
            k: v
            for k, v in base.items() if k not in (characteristics.keys())
        }

    def match_characteristic(characteristics, base):
        common = set(characteristics.keys()).intersection(set(base.keys()))
        if not common:
            return False

        for c in common:
            if characteristics[c] != base[c]:
                return False

        return True


class ComplementaryUAAnalyzers(object):
    def __init__(self):
        self.mobile_detector = MobileDetector()

    def get_additional_data(self, user_agent, device_args, app_args):
        self.run_ua_parser(user_agent, device_args, app_args)
        self.run_mobile_detector(user_agent, device_args, app_args)

    def run_ua_parser(self, user_agent, device_args, app_args):
        parsed_string = user_agent_parser.Parse(user_agent)

        brand = parsed_string.get('device').get('brand')

        if brand and ComplementaryUAAnalyzers.has_useful_data(
                brand) and 'brand' not in device_args:
            device_args['brand'] = brand

        os_family = parsed_string.get('os').get('family')

        if os_family and ComplementaryUAAnalyzers.has_useful_data(
                os_family) and 'os_family' not in device_args:
            device_args['os_family'] = os_family

        if 'os_version' not in device_args:
            version = ComplementaryUAAnalyzers.get_version_from_ua_parser(
                parsed_string['os'])

            if version:
                device_args['os_version'] = version

    def has_useful_data(data):
        return data != 'Other' and data != 'Generic'

    def get_version_from_ua_parser(ua_parser_os):
        ret = ''

        major = ua_parser_os.get('major')
        if major:
            ret += major
        else:
            return ret
        minor = ua_parser_os.get('minor')
        if minor:
            ret += '.' + minor
        else:
            return ret
        patch = ua_parser_os.get('patch')
        if patch:
            ret += '.' + patch
        else:
            return ret
        patch_minor = ua_parser_os.get('patch_minor')
        if patch:
            ret += '.' + patch_minor
        else:
            return ret

        return ret

    def run_mobile_detector(self, user_agent, device_args, app_args):
        response = self.mobile_detector.parse(user_agent)
        if response.get('model') and 'model' not in device_args:
            device_args['model'] = response['model']
        if response.get('os_family') and 'os_family' not in device_args:
            device_args['os_family'] = response['os_family']
        if response.get('app_name') and 'name' not in app_args:
            app_args['name'] = response['app_name']


class UserAgentAnalyzer(object):
    def __init__(self, user_patterns_file):
        self.user_agents = self.get_config(user_patterns_file)
        self.complement = ComplementaryUAAnalyzers()

    def get_config(self, user_patterns_file):
        user_agent_patterns = []

        with open(paths.USER_AGENT_PATTERNS_FILE) as f:
            for each in f.read().splitlines():
                if each and each[0] != '#':
                    user_agent_patterns.append(each)

        if user_patterns_file:
            try:
                with open(user_patterns_file) as f:
                    for each in f.read().splitlines():
                        if each and each[0] != '#':
                            user_agent_patterns.append(each)
            except:
                print('Not valid pattern file')
                raise

        return user_agent_patterns

    def get_best_match(self, user_agent):
        max_size = -1
        best_match = None
        for pattern in self.user_agents:
            match = re.match(pattern, user_agent)
            if match:
                groups = match.groupdict()
                if (len(groups) > max_size):
                    max_size = len(groups)
                    best_match = groups

        device_args, app_args = {}, {}
        if best_match:
            for k in best_match:
                if best_match[k]:
                    if k.startswith('APP_'):
                        app_args[k[4:]] = best_match[k]
                    elif k.startswith('DEV_'):
                        device_args[k[4:]] = best_match[k]

        self.complement.get_additional_data(user_agent, device_args, app_args)

        return {'device_args': device_args, 'app_args': app_args}


if __name__ == '__main__':
    ie = InferenceEngine()
    c = {'cfnetwork_version': '711.0.6', 'darwin_version': '14.0.0'}
    # {'build': '12A365', 'os_version': '8.0', 'darwin_version': '14.0.0', 'model': 'iPad4,4', 'cfnetwork_version': '711.0.6', 'framework': 'GameKit-194.14'}
    ret = ie.analyze_inference(c)
    print(ret)
