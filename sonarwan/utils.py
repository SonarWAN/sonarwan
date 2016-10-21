import sys
import time
from tabulate import tabulate
import datetime


def show_progress(pkg_index):
    sys.stdout.write('\rProcessed packets {}'.format(pkg_index))
    sys.stdout.flush()


def pretty_print(sonarwan):
    print()
    print_title("Summary")
    print("SonarWAN found {} devices in {} capture files.".format(
        len(sonarwan.environment.devices), sonarwan.file_count))
    print("{} packets were analyzed.".format(sonarwan.i))
    print("Execution time: {}".format((time.time() - sonarwan.start_time)))
    print_title("Details")
    print_title("Devices")
    for i, d in enumerate(sonarwan.environment.devices):
        print_subtitle("Device {}".format(i + 1))
        aux = []
        print('\nCharacteristics:')
        for k, v in d.characteristics.items():
            aux.append([k, v.replace("%20", " ")])
        aux.append(['Associated services', len(d.services)])
        time_list = common_times(d.activity)
        aux.append(['Activity', " | ".join(time_list)])
        print(tabulate(aux))
        for j, s in enumerate(d.services):
            print()
            print("Service {}:".format(j + 1))
            time_list = common_times(s.activity)
            aux = []
            for k, v in s.characteristics.items():
                aux.append([k, v.replace("%20", " ")])
            time_list = common_times(s.activity)
            aux.append(['Activity', " | ".join(time_list)])
            print(tabulate(aux))
        print()
    print_title("Authorless Services")
    for i, s in enumerate(sonarwan.environment.authorless_services):
        print_subtitle("Service {}".format(i + 1))
        aux = []
        print('\nCharacteristics:')
        for k, v in s.characteristics.items():
            aux.append([k, v.replace("%20", " ")])
            print(tabulate(aux))
        print()


def print_title(string):
    aux = '*' * len(string)
    print("\n{}".format(aux))
    print(string)
    print("{}\n".format(aux))


def print_subtitle(string):
    aux = '=' * len(string)
    print(string)
    print("{}".format(aux))


def common_times(datetimes):
    ret = set()
    for each in datetimes:
        ret.add(each.strftime("%Y-%m-%d %H:%M:%S"))
    return list(ret)
