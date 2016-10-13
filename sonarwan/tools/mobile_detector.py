"""
Modification of:

    https://github.com/anvileight/pymobiledetect

Mobile Detect - Python detection mobile phone and tablet devices

Thanks to:
    https://github.com/serbanghita/Mobile-Detect/blob/master/Mobile_Detect.php
"""
import os
import re
import json
import paths


class MobileDetectRuleFileError(Exception):
    pass

class MobileDetector(object):
    def __init__(self):
        self.load_rules()

    def load_rules(self):
        self.rules = json.load(open(paths.MOBILE_DETECTOR_PATH))
        if not "version" in self.rules:
            raise MobileDetectRuleFileError(
                "version not found in rule file: %s" % filename)
        if not "headerMatch" in self.rules:
            raise MobileDetectRuleFileError(
                "section 'headerMatch' not found in rule file: %s" % filename)
        if not "uaHttpHeaders" in self.rules:
            raise MobileDetectRuleFileError(
                "section 'uaHttpHeaders' not found in rule file: %s" % filename)
        if not "uaMatch" in self.rules:
            raise MobileDetectRuleFileError(
                "section 'uaMatch' not found in rule file: %s" % filename)

        self.OPERATINGSYSTEMS = dict(
            (name, re.compile(match, re.IGNORECASE|re.DOTALL))
            for name, match in self.rules['uaMatch']['os'].items())
        self.DEVICE_PHONES = dict(
            (name, re.compile(match, re.IGNORECASE|re.DOTALL))
            for name, match in self.rules['uaMatch']['phones'].items())
        self.DEVICE_TABLETS = dict(
            (name, re.compile(match, re.IGNORECASE|re.DOTALL))
            for name, match in self.rules['uaMatch']['tablets'].items())
        self.DEVICE_BROWSERS = dict(
            (name, re.compile(match, re.IGNORECASE|re.DOTALL))
            for name, match in self.rules['uaMatch']['browsers'].items())

    def parse(self, useragent):
        ret = {}
        for name, rule in self.DEVICE_PHONES.items():
            if rule.search(useragent):
                ret['model']=str(name)
        for name, rule in self.DEVICE_TABLETS.items():
            if rule.search(useragent):
                ret['model']=str(name)
        for name, rule in self.OPERATINGSYSTEMS.items():
            if rule.search(useragent):
                if name!='iOS':
                    ret ['os_family']=str(name[:-2])
                else:
                    ret['os_family']=str(name)
        for name, rule in self.DEVICE_BROWSERS.items():
            if rule.search(useragent):
                ret['app_name']=str(name)
        return ret

if __name__ == '__main__':
    from os import sys, path
    sys.path.append(path.dirname(path.dirname(path.abspath(__file__))))
    detector = MobileDetector()
    ret = detector.parse('Mozilla/5.0 (iPad; CPU OS 8_0 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12A365 Safari/600.1.4')
    print(ret)
