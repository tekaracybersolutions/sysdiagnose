#! /usr/bin/env python3

# For Python3
# Script to print the values from /logs/SystemVersion/SystemVersion.plist
# Author: cheeky4n6monkey@gmail.com
#
# Change log: David DURVAUX - add function are more granular approach

import os
import glob
import utils.misc as misc
from utils.base import BaseParserInterface


class SystemVersionParser(BaseParserInterface):
    description = "Parsing SystemVersion plist file"

    def __init__(self, config: dict, case_id: str):
        super().__init__(__file__, config, case_id)

    def get_log_files(self) -> list:
        log_files_globs = [
            'logs/SystemVersion/SystemVersion.plist'
        ]
        log_files = []
        for log_files_glob in log_files_globs:
            log_files.extend(glob.glob(os.path.join(self.case_data_subfolder, log_files_glob)))

        return log_files

    def execute(self) -> list | dict:
        try:
            return SystemVersionParser.parse_file(self.get_log_files()[0])
        except IndexError:
            return {'error': 'No SystemVersion.plist file present'}

    def parse_file(path: str) -> list | dict:
        return misc.load_plist_file_as_json(path)

    '''
    old code to print the values
        if options.inputfile:
            pl = getProductInfo(options.inputfile)
            print(f"ProductName = {pl['ProductName']}")       # XXX #9 TODO: should that return the structure instead of print() ing it?
            print(f"ProductVersion = {pl['ProductVersion']}")
            print(f"ProductBuildVersion = {pl['ProductBuildVersion']}")
        else:
            print("WARNING -i option is mandatory!", file=sys.stderr)
    '''
