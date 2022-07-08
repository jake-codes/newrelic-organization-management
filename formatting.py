import pprint

pp = pprint.PrettyPrinter(indent=2)

class BColors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def bold_str(str):
    return BColors.BOLD + str + BColors.ENDC

def alternate_color(str, i):
    if i % 2 == 0:
        return BColors.OKGREEN + str + BColors.ENDC
    return BColors.OKBLUE + str + BColors.ENDC

def print_error(str):
    print(BColors.FAIL + str + BColors.ENDC)

def print_warning(str, verbose=True):
    if verbose:
        print(BColors.WARNING + str + BColors.ENDC)

def print_success(str, verbose=True):
    if verbose:
        print(BColors.OKBLUE + str + BColors.ENDC)

def print_(str, verbose=True):
    if verbose:
        print(str)

def print_json(json_, prefix=None):
    if prefix:
        print_(prefix)
    pp.pprint(json_)