import paths
import re


class InferenceEngine(object):
    def __init__(self):
        pass


class UserAgentAnalyzer(object):
    def __init__(self):
        self.user_agents = self.get_config()

    def get_config(self):
        with open(paths.USER_AGENT_PATTERNS_FILE) as f:
            user_agent_patterns = f.read().splitlines()

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
