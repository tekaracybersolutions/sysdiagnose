import json
import glob
import os
from sysdiagnose.utils.base import BaseParserInterface, logger
from datetime import datetime
import re


class TransparencyParser(BaseParserInterface):

    description = "Parsing transparency.log json file as timeline"
    format = 'jsonl'

    def __init__(self, config: dict, case_id: str):
        super().__init__(__file__, config, case_id)

    def get_log_files(self) -> list:
        log_files_globs = [
            'transparency.log',
        ]
        log_files = []
        for log_files_glob in log_files_globs:
            for item in glob.glob(os.path.join(self.case_data_subfolder, log_files_glob)):
                if os.path.getsize(item) > 0:
                    log_files.append(item)

        return log_files

    def execute(self) -> list:
        result = []

        files = self.get_log_files()
        if not files:
            logger.info("No known transparency.log file found.")
            return result

        for file in files:
            with open(file, 'r') as f:
                try:
                    json_data = json.load(f)
                    result.extend(self.extract_events(json_data))
                except json.decoder.JSONDecodeError:
                    logger.warning(f"Error parsing {file}")

        return result

    def extract_events(self, json_data: dict) -> list:
        events = []
        for item in json_data.get('registration', []):
            for key in item.keys():
                if 'At' in key:
                    # parse the time in this format "2023-04-11 09:38:27 +0000"
                    timestamp = datetime.strptime(item[key], "%Y-%m-%d %H:%M:%S %z")
                    events.append({
                        'message': f"Transparency: registration app {item.get('app')} {key}",
                        'timestamp': timestamp.timestamp(),
                        'datetime': timestamp.isoformat(timespec='microseconds'),
                    })
        sm = json_data.get('stateMachine')
        if sm:
            try:
                key = 'accountFirstSeen'
                timestamp = datetime.strptime(sm[key], "%Y-%m-%d %H:%M:%S %z")
                events.append({
                    'message': f"Transparency: stateMachine {key}",
                    'timestamp': timestamp.timestamp(),
                    'datetime': timestamp.isoformat(timespec='microseconds'),
                })
            except KeyError:
                pass
            try:
                key = 'backgroundOp lastDutyCycle'
                timestamp = datetime.strptime(sm['backgroundOp']['lastDutyCycle'], "%Y-%m-%dT%H:%M:%SZ")
                events.append({
                    'message': f"Transparency: stateMachine {key}",
                    'timestamp': timestamp.timestamp(),
                    'datetime': timestamp.isoformat(timespec='microseconds'),
                })
            except KeyError:
                pass
            try:
                key = 'backgroundOp lastSuccess'
                timestamp = datetime.strptime(sm['backgroundOp']['lastSuccess'], "%Y-%m-%dT%H:%M:%SZ")
                events.append({
                    'message': f"Transparency: stateMachine {key}",
                    'timestamp': timestamp.timestamp(),
                    'datetime': timestamp.isoformat(timespec='microseconds'),
                })
            except KeyError:
                pass

            for key, t in sm.get('lasts', {}).items():
                timestamp = datetime.strptime(t, "%Y-%m-%d %H:%M:%S %z")
                events.append({
                    'message': f"Transparency: stateMachine last {key}",
                    'timestamp': timestamp.timestamp(),
                    'datetime': timestamp.isoformat(timespec='microseconds'),
                })

            for launch in sm.get('launch', []):
                t, key = launch.split(' - ')
                # parse the time in this format 2024-08-19T09:00:28.946+0200
                timestamp = datetime.strptime(t, "%Y-%m-%dT%H:%M:%S.%f%z")
                events.append({
                    'message': f"Transparency: stateMachine last {key}",
                    'timestamp': timestamp.timestamp(),
                    'datetime': timestamp.isoformat(timespec='microseconds'),
                })

            try:
                key = 'lockState'
                # extract the time from the string using regex "foobar 2024-08-19 09:00:28 +0200"
                time_str = re.search(r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} [+-]\d{4}', sm[key]).group(0)
                timestamp = datetime.strptime(time_str, "%Y-%m-%d %H:%M:%S %z")
                events.append({
                    'message': f"Transparency: stateMachine {key}",
                    'timestamp': timestamp.timestamp(),
                    'datetime': timestamp.isoformat(timespec='microseconds'),
                    'data': sm[key],
                })
            except KeyError:
                pass

            for key, val in sm.get('ops', {}).items():
                try:
                    time_str = re.search(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} [+-]\d{4})', val).group(0)
                    timestamp = datetime.strptime(time_str, "%Y-%m-%d %H:%M:%S %z")
                    events.append({
                        'message': f"Transparency: stateMachine op {val}",
                        'timestamp': timestamp.timestamp(),
                        'datetime': timestamp.isoformat(timespec='microseconds'),
                    })
                except KeyError:
                    pass
        return events
