import sys


def show_progress(pkg_index):
    sys.stdout.write('\rProcessed packets {}'.format(pkg_index))
    sys.stdout.flush()
