import sys
import time
from tabulate import tabulate
import datetime
import json
import sys

FRAMES_TO_INFORM = 10


def show_progress(pkg_index):
    # Write on error so that user can redirect stdout
    sys.stdout.write('\rProcessed packets {}'.format(pkg_index))
    sys.stdout.flush()


def report_error(msg, json_output):
    if json_output:
        print(json.dumps({'Error': msg}))
    else:
        print("ERROR: {}. See sonarwan.log file for more details.".format(msg))


def inform_json_progress(number, path):
    update = {'Packets': number, 'Current File': path}
    print(json.dumps({'Update': update}))


def pretty_print(sonarwan, file_output=None):
    if file_output:
        print(
            "\n\nFinished proccesing {} frames across {} files. Report is available in {}\n".
            format(sonarwan.i, sonarwan.file_count, file_output))
        fd = open(file_output, 'w')
    else:
        fd = sys.stdout

    fd.write("\n")
    print_title("SUMMARY", fd)
    fd.write(
        "SonarWAN found {} devices and {} authorless services in {} capture files.\n".
        format(
            len(sonarwan.environment.devices), len(
                sonarwan.environment.authorless_services),
            sonarwan.file_count))
    fd.write("{} packets were analyzed.\n".format(sonarwan.i))
    fd.write("Execution time: {}\n".format((time.time() - sonarwan.start_time
                                            )))
    print_title("DETAILS", fd)
    print_title("Devices", fd)
    for i, d in enumerate(sonarwan.environment.devices):
        print_device(i, d, fd)
    print_title("Authorless Services", fd)
    for i, s in enumerate(sonarwan.environment.authorless_services):
        print_service(i, s, fd)


def print_device(number, device, fd):
    print_subtitle("Device {}".format(number + 1), fd)
    aux = []
    fd.write('\nCharacteristics:\n')
    for k, v in device.characteristics.items():
        aux.append([k, v.replace("%20", " ")])
    aux.append(['Associated Apps', len(device.apps)])
    aux.append(['Unasigned Services', len(device.unasigned_services)])
    fd.write("{}\n".format(tabulate(aux)))
    fd.write("\n")
    for x, s in enumerate(device.unasigned_services):
        print_unassigned_service(x, s, fd)
        fd.write("\n")
    for j, a in enumerate(device.apps):
        fd.write("\n")
        fd.write("App {}:\n".format(j + 1))
        aux = []
        for k, v in a.characteristics.items():
            aux.append([k, v.replace("%20", " ")])
        aux.append(['Associated Services', len(a.services)])
        fd.write("{}\n".format(tabulate(aux)))
        fd.write("\n")
        for x, s in enumerate(a.services):
            print_service(x, s, fd)
            fd.write("\n")


def print_unassigned_service(number, service, fd):
    _print_service(number, service, fd, True)


def print_service(number, service, fd):
    _print_service(number, service, fd, False)


def _print_service(number, service, fd, unassigned):
    aux = []
    fd.write("{}Service {}:\n".format("Unassigned "
                                      if unassigned else "", number + 1))
    aux.append(['name', service.name])
    aux.append(['type', service.type or 'Unknown URL'])
    if len(service.ips) > 0:
        aux.append(['ips', service.ips])
    if len(service.hosts) > 0:
        aux.append(['hosts', service.hosts])
    fd.write("{}\n".format(tabulate(aux)))
    fd.write('\nActivity:\n')
    aux = []
    for k, v in service.activity.items():
        aux.append([k, v])
    fd.write("{}\n".format(tabulate(aux)))


def print_title(string, fd):
    """Prints like 

        *****
        Title
        *****
    """
    aux = '*' * len(string)
    fd.write("\n{}\n".format(aux))
    fd.write("{}\n".format(string))
    fd.write("{}\n\n".format(aux))


def print_subtitle(string, fd):
    """Prints like 

        Subtitle
        =======
    """
    aux = '=' * len(string)
    fd.write("{}\n".format(string))
    fd.write("{}\n\n".format(aux))
