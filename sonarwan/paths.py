import os

BASE_DIR = os.path.dirname(os.path.dirname(__file__))

USER_AGENT_PATTERNS_FILE = os.path.join(BASE_DIR, './db/user_agents.patterns')

INFERENCE_DIR = os.path.join(BASE_DIR, './db/inference/')

MOBILE_DETECTOR_PATH = os.path.join(BASE_DIR,
                                    './db/serbanghita-Mobile-Detect-db.json')

SERVICES_DIRECTORY_PATH = os.path.join(BASE_DIR, './db/services/')

LINUX_DISTRIBUTION_FILE = os.path.join(BASE_DIR, './db/linux.distributions')
