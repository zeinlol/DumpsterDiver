#!/usr/bin/env python3

import os
import sys

import colorama

from core import arguments, core
from core.title import opening

colorama.init()

if __name__ == '__main__':

    opening()
    if arguments.local_path:

        if os.path.isdir(arguments.local_path) or os.path.isfile(arguments.local_path):
            arguments.local_path = os.path.abspath(arguments.local_path)

        else:
            print("The specified path '" + arguments.local_path
                  + "' doesn't exist.")
            sys.exit()

    core.start_the_hunt(settings=arguments)
