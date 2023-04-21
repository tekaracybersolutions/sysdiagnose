#! /usr/bin/env python

# For Python3
# Initializing sysdiagnose Analysis
# Extract archive and create a json file containing information necessary for Analysis
# version, path_to_extracted_files, etc...

"""sysdiagnose initialize.

Usage:
  initialyze.py file <sysdiagnose_file>
  initialyze.py (-h | --help)
  initialyze.py --version

Options:
  -h --help     Show this screen.
  -v --version     Show version.
"""

import config

import sys
import os
import tarfile
import json
import hashlib
import glob
from docopt import docopt

"""
    Init function
"""
def init(sysdiagnose_file):
    # open case json file
    try:
        with open(config.cases_file, 'r') as f:
            cases = json.load(f)
    except:
        print('error opening cases json file - check config.py')
        exit()

    # calculate sha256 of sysdiagnose file and compare with past cases
    try:
        with open(sysdiagnose_file, 'rb') as f:
            bytes = f.read() # read entire file as bytes
            readable_hash = hashlib.sha256(bytes).hexdigest();
            print(readable_hash)
    except:
        print('error calculating sha256')
    case_id = 0
    for case in cases['cases']:
        # Take the opportunity to find the highest case_id
        case_id = max(case_id, case['case_id'])
        if readable_hash == case['source_sha256']:
            print('this sysdiagnose has already been extracted : caseID:' + str(case['case_id']))
            exit()


    # test sysdiagnose file
    try:
        tf = tarfile.open(sysdiagnose_file)
    except:
        print('error opening sysdiagnose file')
        exit()

    # if sysdiagnose file is new and legit, create new case and extract files
    # create case dictionnary
    new_case = {
        "case_id":case_id +1,
        "source_file":sysdiagnose_file,
        "source_sha256":readable_hash,
        "case_file":config.data_folder+str(case_id +1)+".json"
    }
    # create case folder
    new_folder = config.data_folder+str(new_case['case_id'])
    if not os.path.exists(new_folder):
        os.makedirs(new_folder)

    # create parsed_data folder
    new_parsed_folder = config.parsed_data_folder+str(new_case['case_id'])
    if not os.path.exists(new_parsed_folder):
        os.makedirs(new_parsed_folder)

    # extract sysdiagnose files
    os.chdir(new_folder)
    try:
        tf.extractall()
    except:
        print('Error while decompressing sysdiagnose file')

    # create case json file
    new_case_json = {
        "sysdiagnose.log":new_folder+glob.glob('./*/sysdiagnose.log')[0][1:]
    }

    try:
        new_case_json["ps"] = new_folder+glob.glob('./*/ps.txt')[0][1:]
    except:
        pass

    try:
        new_case_json["swcutil_show"] = new_folder+glob.glob('./*/swcutil_show.txt')[0][1:]
    except:
        pass

    try:
        new_case_json["ps_thread"] = new_folder+glob.glob('./*/ps_thread.txt')[0][1:]
    except:
        pass

    try:
        new_case_json["appupdate_db"] = new_folder+glob.glob('./*/logs/appinstallation/AppUpdates.sqlitedb')[0][1:]
    except:
        pass

    try:
        new_case_json["brctl"] = new_folder+glob.glob('./*/brctl/')[0][1:]
    except:
        pass

    try:
        new_case_json["networkextensioncache"] = new_folder+glob.glob('./*/logs/Networking/com.apple.networkextension.cache.plist')[0][1:]
    except:
        pass

    try:
        new_case_json["networkextension"] = new_folder+glob.glob('./*/logs/Networking/com.apple.networkextension.plist')[0][1:]
    except:
        pass

    try:
        new_case_json["powerlogs"] = new_folder+glob.glob('./*/logs/powerlogs/powerlog_*')[0][1:]
    except:
        pass

    try:
        new_case_json["systemversion"] = new_folder+glob.glob('./*/logs/SystemVersion/SystemVersion.plist')[0][1:]
    except:
        pass

    try:
        new_case_json["UUIDToBinaryLocations"] = new_folder+glob.glob('./*/logs/tailspindb/UUIDToBinaryLocations')[0][1:]
    except:
        pass

    try:
        new_case_json["logarchive_folder"] = new_folder+glob.glob('./*/system_logs.logarchive/')[0][1:]
    except:
        pass

    try:
        new_case_json["taskinfo"] = new_folder+glob.glob('./*/taskinfo.txt')[0][1:]
    except:
        pass

    try:
        new_case_json["spindump-nosymbols"] = new_folder+glob.glob('./*/spindump-nosymbols.txt')[0][1:]
    except:
        pass

    try:
        new_case_json["Accessibility-TCC"] = new_folder+glob.glob('./*/logs/Accessibility/TCC.db')[0][1:]
    except:
        pass

    try:
        new_case_json["appinstallation"] = new_folder+glob.glob('./*/logs/appinstallation/appstored.sqlitedb')[0][1:]
    except:
        pass

    try:
        new_case_json["itunesstore"] = new_folder+glob.glob('./*/./logs/itunesstored/downloads.*.sqlitedb')[0][1:]
    except:
        pass


    ## ips files
    try:
        ips_files = glob.glob('./*/crashes_and_spins/*.ips')
        ips_files_fullpath = []
        for ips in ips_files:
            ips = new_folder+ips[1:]
            ips_files_fullpath.append(ips)
        new_case_json["ips_files"] = ips_files_fullpath
    except:
        pass

    ## mobile activation logs
    try:
        mobile_activation = glob.glob('./*/logs/MobileActivation/mobileactivationd.log*')
        mobile_activation_fullpath = []
        for log in mobile_activation:
            log = new_folder+log[1:]
            mobile_activation_fullpath.append(log)
        new_case_json["mobile_activation"] = mobile_activation_fullpath
    except:
        pass

    ## container manager
    try:
        container_manager = glob.glob('./*/logs/MobileContainerManager/containermanagerd.log*')
        container_manager_fullpath = []
        for log in container_manager:
            log = new_folder+log[1:]
            container_manager_fullpath.append(log)
        new_case_json["container_manager"] = container_manager_fullpath
    except:
        pass

    ## mobile installation
    try:
        mobile_installation = glob.glob('./*/logs/MobileInstallation/mobile_installation.log*')
        mobile_installation_fullpath = []
        for log in mobile_installation:
            log = new_folder+log[1:]
            mobile_installation_fullpath.append(log)
        new_case_json["mobile_installation"] = mobile_installation_fullpath
    except:
        pass

    #print(json.dumps(new_case_json, indent=4))

    # Get iOS version
    os.chdir('../..')
    with open(new_case_json['sysdiagnose.log'], 'r') as f:
        line_version=[line for line in f if 'iPhone OS' in line][0]
        version=line_version.split()[4]
    new_case_json['ios_version']=version



    # Save JSON file
    with open(new_case['case_file'], 'w') as data_file:
        data_file.write(json.dumps(new_case_json, indent=4))


    #update cases list file
    cases['cases'].append(new_case)

    with open(config.cases_file, 'w') as data_file:
        data_file.write(json.dumps(cases, indent=4))

    print('Sysdiagnose file has been processed')
    print('New case ID: ' + str(new_case['case_id']))


"""
    Integrity Checking (cases files and folders)
"""

def integrity_check():
    if not os.path.exists(config.data_folder):
        os.makedirs(config.data_folder)
    if not os.path.exists(config.parsed_data_folder):
        os.makedirs(config.parsed_data_folder)
    if not os.path.exists(config.cases_file):
        cases = {'cases':[]}
        with open(config.cases_file, 'w') as data_file:
            data_file.write(json.dumps(cases, indent=4))



"""
    Main function
"""
def main():

    if sys.version_info[0] < 3:
        print("Still using Python 2 ?!?")
        exit(-1)

    arguments = docopt(__doc__, version='Sysdiagnose initialize script v0.1')

    integrity_check()

    if arguments['file'] == True:
        if os.path.isfile(arguments['<sysdiagnose_file>']):
            init(arguments['<sysdiagnose_file>'])
        else:
            print('file not found')
            exit()


"""
   Call main function
"""
if __name__ == "__main__":

    # Create an instance of the Analysis class (called "base") and run main
    main()
