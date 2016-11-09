import sys
import time
from tabulate import tabulate
import datetime
import json


def show_progress(pkg_index):
    sys.stdout.write('\rProcessed packets {}'.format(pkg_index))
    sys.stdout.flush()


def inform_json_progress(number, path):
    update = {'Packets': number, 'Current File': path}
    print(json.dumps({'update': update}))


def pretty_print(sonarwan):
    print()
    print_title("SUMMARY")
    print(
        "SonarWAN found {} devices and {} authorless services in {} capture files.".
        format(
            len(sonarwan.environment.devices), len(
                sonarwan.environment.authorless_services),
            sonarwan.file_count))
    print("{} packets were analyzed.".format(sonarwan.i))
    print("Execution time: {}".format((time.time() - sonarwan.start_time)))
    print_title("DETAILS")
    print_title("Devices")
    for i, d in enumerate(sonarwan.environment.devices):
        print_device(i, d)
        print()
    print_title("Authorless Services")
    for i, s in enumerate(sonarwan.environment.authorless_services):
        print_service(i, s)
        print()


def print_device(number, device):
    print_subtitle("Device {}".format(number + 1))
    aux = []
    print('\nCharacteristics:')
    for k, v in device.characteristics.items():
        aux.append([k, v.replace("%20", " ")])
    aux.append(['Associated Apps', len(device.apps)])
    print(tabulate(aux))
    # print('\nActivity:')
    # aux = []
    # for k, v in d.activity.items():
    #     aux.append([k, v])
    # print(tabulate(aux))
    for j, a in enumerate(device.apps):
        print()
        print("App {}:".format(j + 1))
        aux = []
        for k, v in a.characteristics.items():
            aux.append([k, v.replace("%20", " ")])
        aux.append(['Associated Services', len(a.services)])
        print(tabulate(aux))
        print()
        for x, s in enumerate(a.services):
            print_service(x, s)
            print()


def print_service(number, service):
    aux = []
    print("Service {}:".format(number + 1))
    aux.append(['name', service.name])
    aux.append(['type', service.type or 'Unknown URL'])
    if len(service.ips) > 0:
        aux.append(['ips', service.ips])
    if len(service.hosts) > 0:
        aux.append(['hosts', service.hosts])
    print(tabulate(aux))
    print('\nActivity:')
    aux = []
    for k, v in service.activity.items():
        aux.append([k, v])
    print(tabulate(aux))


def print_title(string):
    aux = '*' * len(string)
    print("\n{}".format(aux))
    print(string)
    print("{}\n".format(aux))


def print_subtitle(string):
    aux = '=' * len(string)
    print(string)
    print("{}".format(aux))
