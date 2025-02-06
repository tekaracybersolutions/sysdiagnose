#! /usr/bin/env python3
from typing import Generator

from sysdiagnose.utils.base import BaseAnalyserInterface, logger
from sysdiagnose.parsers.ps import PsParser
from sysdiagnose.parsers.psthread import PsThreadParser
from sysdiagnose.parsers.spindumpnosymbols import SpindumpNoSymbolsParser
from sysdiagnose.parsers.shutdownlogs import ShutdownLogsParser
from sysdiagnose.parsers.logarchive import LogarchiveParser
from sysdiagnose.parsers.uuid2path import UUID2PathParser
from sysdiagnose.parsers.taskinfo import TaskinfoParser
from sysdiagnose.parsers.remotectl_dumpstate import RemotectlDumpstateParser


class PsEverywhereAnalyser(BaseAnalyserInterface):
    description = "List all processes we can find a bit everywhere."
    format = "jsonl"

    def __init__(self, config: dict, case_id: str):
        super().__init__(__file__, config, case_id)

    def execute(self):
        """
        Execute method that dynamically calls all extraction methods and yields structured process data.
        This ensures unique processes are yielded without overriding previous data.
        """
        seen_processes = set()

        for func in dir(self):
            if func.startswith(f"_{self.__class__.__name__}__extract_ps_"):
                for event in getattr(self, func)():  # Dynamically call extract methods
                    if self.add_if_full_command_is_not_in_set(event['process'], seen_processes):
                        yield event  # Only yield unique events

    # TODO powerlogs - bundleID, ProcessName

    def __extract_ps_base_file(self) -> Generator[dict, None, None]:
        try:
            seen_processes = set()
            for p in PsParser(self.config, self.case_id).get_result():
                ps_event = {
                    'process': p['command'],
                    'timestamp': p['timestamp'],
                    'datetime': p['datetime'],
                    'source': 'ps.txt'
                }
                if self.add_if_full_command_is_not_in_set(ps_event['process'], seen_processes):
                    yield ps_event
        except Exception as e:
            logger.exception("ERROR while extracting ps.txt file.")

    def __extract_ps_thread_file(self) -> Generator[dict, None, None]:
        try:
            seen_processes = set()
            for p in PsThreadParser(self.config, self.case_id).get_result():
                ps_event = {
                    'process': p['command'],
                    'timestamp': p['timestamp'],
                    'datetime': p['datetime'],
                    'source': 'psthread.txt'
                }
                if self.add_if_full_command_is_not_in_set(ps_event['process'], seen_processes):
                    yield ps_event
        except Exception as e:
            logger.exception("ERROR while extracting psthread.txt file.")

    def __extract_ps_spindumpnosymbols_file(self) -> Generator[dict, None, None]:
        try:
            seen_processes = set()
            for p in SpindumpNoSymbolsParser(self.config, self.case_id).get_result():
                if 'process' not in p:
                    continue
                process_name = p.get('path', '/kernel' if p['process'] == 'kernel_task [0]' else p['process'])

                if self.add_if_full_command_is_not_in_set(process_name, seen_processes):
                    yield {
                        'process': process_name,
                        'timestamp': p['timestamp'],
                        'datetime': p['datetime'],
                        'source': 'spindumpnosymbols.txt'
                    }

                for t in p['threads']:
                    try:
                        thread_name = f"{process_name}::{t['thread_name']}"
                        if self.add_if_full_command_is_not_in_set(thread_name, seen_processes):
                            yield {
                                'process': thread_name,
                                'timestamp': p['timestamp'],
                                'datetime': p['datetime'],
                                'source': 'spindumpnosymbols.txt'
                            }
                    except KeyError:
                        pass
        except Exception as e:
            logger.exception("ERROR while extracting spindumpnosymbols.txt file.")

    def __extract_ps_shutdownlogs(self) -> Generator[dict, None, None]:
        try:
            seen_processes = set()
            for p in ShutdownLogsParser(self.config, self.case_id).get_result():
                if self.add_if_full_command_is_not_in_set(p['command'], seen_processes):
                    yield {
                        'process': p['command'],
                        'timestamp': p['timestamp'],
                        'datetime': p['datetime'],
                        'source': 'shutdown.logs'
                    }
        except Exception as e:
            logger.exception("ERROR while extracting shutdown logs.")

    def __extract_ps_logarchive(self) -> Generator[dict, None, None]:
        try:
            seen_processes = set()
            for p in LogarchiveParser(self.config, self.case_id).get_result():
                if self.add_if_full_command_is_not_in_set(p['process'], seen_processes):
                    yield {
                        'process': p['process'],
                        'timestamp': p['timestamp'],
                        'datetime': p['datetime'],
                        'source': 'logarchive'
                    }
        except Exception as e:
            logger.exception("ERROR while extracting logarchive.")

    def __extract_ps_uuid2path(self) -> Generator[dict, None, None]:
        try:
            seen_processes = set()
            for p in UUID2PathParser(self.config, self.case_id).get_result().values():
                if self.add_if_full_command_is_not_in_set(p, seen_processes):
                    yield {
                        'process': p,
                        'timestamp': None,
                        'datetime': None,
                        'source': 'uuid2path'
                    }
        except Exception as e:
            logger.exception("ERROR while extracting uuid2path.")

    def __extract_ps_taskinfo(self) -> Generator[dict, None, None]:
        try:
            seen_processes = set()
            for p in TaskinfoParser(self.config, self.case_id).get_result():
                if 'name' not in p:
                    continue
                if self.add_if_full_path_is_not_in_set(p['name'], seen_processes):
                    yield {
                        'process': p['name'],
                        'timestamp': p['timestamp'],
                        'datetime': p['datetime'],
                        'source': 'taskinfo'
                    }
                for t in p['threads']:
                    try:
                        thread_name = f"{p['name']}::{t['thread name']}"
                        if self.add_if_full_path_is_not_in_set(thread_name, seen_processes):
                            yield {
                                'process': thread_name,
                                'timestamp': p['timestamp'],
                                'datetime': p['datetime'],
                                'source': 'taskinfo'
                            }
                    except KeyError:
                        pass
        except Exception as e:
            logger.exception("ERROR while extracting taskinfo.")

    def __extract_ps_remotectl_dumpstate(self) -> Generator[dict, None, None]:
        try:
            seen_processes = set()
            remotectl_dumpstate_json = RemotectlDumpstateParser(self.config, self.case_id).get_result()
            if remotectl_dumpstate_json:
                for p in remotectl_dumpstate_json['Local device']['Services']:
                    if self.add_if_full_path_is_not_in_set(p, seen_processes):
                        yield {
                            'process': p,
                            'timestamp': None,
                            'datetime': None,
                            'source': 'remotectl_dumpstate'
                        }
        except Exception as e:
            logger.exception("ERROR while extracting remotectl_dumpstate.")

    def add_if_full_path_is_not_in_set(self, name: str, seen_processes: set) -> bool:
        """Ensure uniqueness based on full path."""
        for item in seen_processes:
            # no need to add it in the following cases
            if item.endswith(name):
                return False
            if item.split('::').pop(0).endswith(name):
                return False
            if '::' not in item and item.split(' ').pop(0).endswith(name):
                # this will but with commands that have a space, but looking at data this should not happend often
                return False
        seen_processes.add(name)
        return True

    def add_if_full_command_is_not_in_set(self, name: str, seen_processes: set) -> bool:
        """Ensure uniqueness based on command."""
        for item in seen_processes:
            if item.startswith(name):
                # no need to add it
                return False
        seen_processes.add(name)
        return True

