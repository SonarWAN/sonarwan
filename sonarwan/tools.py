import paths
import re
import csv
from os import listdir
from os.path import isfile, join

class InferenceEngine(object):
    def __init__(self):
        self.load_inference_files()

    def load_inference_files(self):
        self.inference_list = []

        path = paths.INFERENCE_DIR
        onlycsv = [f for f in listdir(path) if isfile(join(path, f))]
        onlycsv = filter(lambda x: x[-4:] == '.csv', onlycsv)
        onlycsv = map(lambda x: path+x, onlycsv)
        for each in onlycsv:
            with open(each) as f:
                csvreader = csv.DictReader(f, delimiter=";")
                self.inference_list.extend(list(csvreader))

    def analyze_inference(self, characteristics):
        candidates = [InferenceEngine.useful_data(characteristics, x) for x in self.inference_list if InferenceEngine.match_characteristic(characteristics, x)]
        non_deterministic = set()
        ret = {}
        for each in candidates:
            for k,v in each.items():
                if k in ret.keys() and v!=ret[k]:
                    non_deterministic.add(k)
                else:
                    ret[k] = v
        for each in non_deterministic:
            del ret[each]
        
        return ret
        
    def useful_data(characteristics, base):
        return {k: v for k, v in base.items() if k not in (characteristics.keys())}

    def match_characteristic(characteristics, base):
        common = set(characteristics.keys()).intersection(set(base.keys()))
        if not common:
            return False

        for c in common:
            if characteristics[c] != base[c]:
                return False

        return True


class UserAgentAnalyzer(object):
    def __init__(self):
        self.user_agents = self.get_config()

    def get_config(self):
        user_agent_patterns = []

        with open(paths.USER_AGENT_PATTERNS_FILE) as f:
            for each in f.read().splitlines():
                if each and each[0]!='#':
                    user_agent_patterns.append(each)

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
                    if k.startswith('app_'):
                        app_args[k[4:]] = best_match[k]
                    else:
                        device_args[k] = best_match[k]
        return (device_args, app_args)

if __name__ == '__main__':
    ie = InferenceEngine()
    c = {'build': '12A365', 'os_version': '8.0', 'model': 'iPad4,4', 'cfnetwork_version': '711.0.6', 'framework': 'GameKit-194.14'}
    # {'build': '12A365', 'os_version': '8.0', 'darwin_version': '14.0.0', 'model': 'iPad4,4', 'cfnetwork_version': '711.0.6', 'framework': 'GameKit-194.14'}
    ret = ie.analyze_inference(c)
    print(ret)
