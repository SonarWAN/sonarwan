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
    print_title("Summary")
    print(
        "SonarWAN found {} devices and {} authorless services in {} capture files.".
        format(
            len(sonarwan.environment.devices), len(
                sonarwan.environment.authorless_services),
            sonarwan.file_count))
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
        aux.append(['Associated Apps', len(d.apps)])
        print(tabulate(aux))
        print('\nActivity:')
        aux = []
        for k, v in d.activity.items():
            aux.append([k, v])
        print(tabulate(aux))
        for j, a in enumerate(d.apps):
            print()
            print("App {}:".format(j + 1))
            aux = []
            for k, v in a.characteristics.items():
                aux.append([k, v.replace("%20", " ")])
            aux.append(['Associated Services', len(a.services)])
            print(tabulate(aux))

            for x, s in enumerate(a.services):
                print_service(x, s)
        print()
    print_title("Authorless Services")
    for i, s in enumerate(sonarwan.environment.authorless_services):
        print_service(i, s)


def print_service(number, service):
    aux = []
    print("Service {}:".format(number + 1))
    aux.append(['name', service.name])
    aux.append(['type', service.type or 'Unknown URL'])
    aux.append(['ips', service.ips])
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
