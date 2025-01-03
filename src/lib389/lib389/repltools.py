# --- BEGIN COPYRIGHT BLOCK ---
# Copyright (C) 2025 Red Hat, Inc.
# All rights reserved.
#
# License: GPL (version 3 or any later version).
# See LICENSE for details.
# --- END COPYRIGHT BLOCK ---

import os
import os.path
import re
import subprocess
import ldap
import logging
import json
import datetime
from lib389._constants import *
from lib389.properties import *
from typing import List, Dict, Optional, Union, Any, Tuple

logging.getLogger(__name__).setLevel(logging.INFO)
log = logging.getLogger(__name__)


# Helper functions
def _alphanum_key(s):
    """Turn the string into a list of string and number parts"""

    return [int(c) if c.isdigit() else c for c in
            re.split('([0-9]+)', s)]


def smart_sort(str_list):
    """Sort the given list in the way that humans expect.

    :param str_list: A list of strings to sort
    :type str_list: list
    """

    str_list.sort(key=_alphanum_key)


def _getCSNTime(inst, csn):
    """Take a CSN and get the access log timestamp in seconds

    :param inst: An instance to check access log
    :type inst: lib389.DirSrv
    :param csn: A "csn" string that is used to find when the csn was logged in
                the access log, and what time in seconds it was logged.
    :type csn: str

    :returns: The time is seconds that the operation was logged
    """

    op_line = inst.ds_access_log.match('.*csn=%s' % csn)
    if op_line:
        #vals = inst.ds_access_log.parse_line(op_line[0])
        return inst.ds_access_log.get_time_in_secs(op_line[0])
    else:
        return None


def _getCSNandTime(inst, line):
    """Take the line and find the CSN from the inst's access logs

    :param inst: An instance to check access log
    :type inst: lib389.DirSrv
    :param line: A "RESULT" line from the access log that contains a "csn"
    :type line: str

    :returns: A tuple containing the "csn" value and the time in seconds when
              it was logged.
    """

    op_line = inst.ds_access_log.match('.*%s.*' % line)
    if op_line:
        vals = inst.ds_access_log.parse_line(op_line[0])
        op = vals['op']
        conn = vals['conn']

        # Now find the result line and CSN
        result_line = inst.ds_access_log.match_archive(
            '.*conn=%s op=%s RESULT.*' % (conn, op))

        if result_line:
            vals = inst.ds_access_log.parse_line(result_line[0])
            if 'csn' in vals:
                ts = inst.ds_access_log.get_time_in_secs(result_line[0])
                return (vals['csn'], ts)

    return (None, None)


class ReplTools(object):
    """Replication tools"""

    @staticmethod
    def checkCSNs(dirsrv_replicas, ignoreCSNs=None):
        """Gather all the CSN strings from the access and verify all of those
        CSNs exist on all the other replicas.

        :param dirsrv_replicas: A list of DirSrv objects. The list must begin
                                with supplier replicas
        :type dirsrv_replicas: list of lib389.DirSrv
        :param ignoreCSNs: An optional string of csns to be ignored if
                           the caller knows that some csns can differ eg.:
                           '57e39e72000000020000|vucsn-57e39e76000000030000'
        :type ignoreCSNs: str

        :returns: True if all the CSNs are present, otherwise False
        """

        csn_logs = []
        csn_log_count = 0

        for replica in dirsrv_replicas:
            logdir = '%s*' % replica.ds_access_log._get_log_path()
            outfile = '/tmp/csn' + str(csn_log_count)
            csn_logs.append(outfile)
            csn_log_count += 1
            if ignoreCSNs:
                cmd = ("grep csn= " + logdir +
                       " | awk '{print $10}' | egrep -v '" + ignoreCSNs + "' | sort -u > " + outfile)
            else:
                cmd = ("grep csn= " + logdir +
                       " | awk '{print $10}' | sort -u > " + outfile)
            os.system(cmd)

        # Set a side the first supplier log - we use this for our "diffing"
        main_log = csn_logs[0]
        csn_logs.pop(0)

        # Now process the remaining csn logs
        for csnlog in csn_logs:
            cmd = 'diff %s %s' % (main_log, csnlog)
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
            line = proc.stdout.readline()
            if line != "" and line != "\n":
                if not line.startswith("\\"):
                    log.fatal("We have a CSN mismatch between (%s vs %s): %s" %
                              (main_log, csnlog, line))
                    return False

        return True

    @staticmethod
    def replConvReport(suffix, ops, replica, all_replicas):
        """Find and measure the convergence of entries from a replica, and
        print a report on how fast all the "ops" replicated to the other
        replicas.

        :param suffix: Replicated suffix
        :type suffix: str
        :param ops:  a list of "operations" to search for in the access logs
        :type ops: list
        :param replica: Instance where the entries originated
        :type replica: lib389.DirSrv
        :param all_replicas: Suppliers, hubs, consumers
        :type all_replicas: list of lib389.DirSrv

        :returns: The longest time in seconds for an operation to fully converge
        """
        highest_time = 0
        total_time = 0

        print('Convergence Report for replica: %s (%s)' %
              (replica.serverid, suffix))
        print('-' * 80)

        # Loop through each operation checking all the access logs
        for op in ops:
            csnstr, csntime = _getCSNandTime(replica, op)
            if csnstr is None and csntime is None:
                # Didn't find a csn, move on
                continue

            conv_time = []
            longest_time = 0
            for inst in all_replicas:
                replObj = inst.replicas.get(suffix)
                if replObj is None:
                    inst.log.warning('(%s) not setup for replication of (%s)' %
                                   (inst.serverid, suffix))
                    continue
                ctime = _getCSNTime(inst, csnstr)
                if ctime:
                    role = replObj.get_role()
                    if role == ReplicaRole.SUPPLIER:
                        txt = ' Supplier (%s)' % (inst.serverid)
                    elif role == ReplicaRole.HUB:
                        txt = ' Hub (%s)' % (inst.serverid)
                    elif role == ReplicaRole.CONSUMER:
                        txt = ' Consumer (%s)' % (inst.serverid)
                    else:
                        txt = '?'
                    ctime = ctime - csntime
                    conv_time.append(str(ctime) + txt)
                    if ctime > longest_time:
                        longest_time = ctime

            smart_sort(conv_time)
            print('\n    Operation: %s\n    %s' % (op, '-' * 40))
            print('\n      Convergence times:')
            for line in conv_time:
                parts = line.split(' ', 1)
                print('        %8s secs - %s' % (parts[0], parts[1]))
            print('\n      Longest Convergence Time: ' +
                  str(longest_time))
            if longest_time > highest_time:
                highest_time = longest_time
            total_time += longest_time

        print('\n    Summary for "{}"'.format(replica.serverid))
        print('    ----------------------------------------')
        print('      Highest convergence time: {} seconds'.format(highest_time))
        print('      Average longest convergence time: {} seconds\n'.format(int(total_time / len(ops))))

        return highest_time

    @staticmethod
    def replIdle(replicas, suffix=DEFAULT_SUFFIX):
        """Take a list of DirSrv Objects and check to see if all of the present
        replication agreements are idle for a particular backend

        :param replicas: Suppliers, hubs, consumers
        :type replicas: list of lib389.DirSrv
        :param suffix: Replicated suffix
        :type suffix: str

        :raises: LDAPError: if unable to search for the replication agreements
        :returns: True if all the agreements are idle, otherwise False
        """

        IDLE_MSG = ('Replica acquired successfully: Incremental ' +
                    'update succeeded')
        STATUS_ATTR = 'nsds5replicaLastUpdateStatus'
        FILTER = ('(&(nsDS5ReplicaRoot=' + suffix +
                  ')(objectclass=nsds5replicationAgreement))')
        repl_idle = True

        for inst in replicas:
            try:
                entries = inst.search_s("cn=config",
                    ldap.SCOPE_SUBTREE, FILTER, [STATUS_ATTR])
                if entries:
                    for entry in entries:
                        if IDLE_MSG not in entry.getValue(STATUS_ATTR):
                            repl_idle = False
                            break

                if not repl_idle:
                    break

            except ldap.LDAPError as e:
                log.fatal('Failed to search the repl agmts on ' +
                          '%s - Error: %s' % (inst.serverid, str(e)))
                assert False
        return repl_idle

    @staticmethod
    def createReplManager(server, repl_manager_dn=None, repl_manager_pw=None):
        """Create an entry that will be used to bind as replication manager.

        :param server: An instance to connect to
        :type server: lib389.DirSrv
        :param repl_manager_dn: DN of the bind entry. If not provided use
                                the default one
        :type repl_manager_dn: str
        :param repl_manager_pw: Password of the entry. If not provide use
                                the default one
        :type repl_manager_pw: str

        :returns: None
        :raises: - KeyError - if can not find valid values of Bind DN and Pwd
                 - LDAPError - if we fail to add the replication manager
        """

        # check the DN and PW
        try:
            repl_manager_dn = repl_manager_dn or \
                defaultProperties[REPLICATION_BIND_DN]
            repl_manager_pw = repl_manager_pw or \
                defaultProperties[REPLICATION_BIND_PW]
            if not repl_manager_dn or not repl_manager_pw:
                raise KeyError
        except KeyError:
            if not repl_manager_pw:
                server.log.warning("replica_createReplMgr: bind DN password " +
                                   "not specified")
            if not repl_manager_dn:
                server.log.warning("replica_createReplMgr: bind DN not " +
                                   "specified")
            raise

        # If the replication manager entry already exists, just return
        try:
            entries = server.search_s(repl_manager_dn, ldap.SCOPE_BASE,
                                              "objectclass=*")
            if entries:
                # it already exist, fine
                return
        except ldap.NO_SUCH_OBJECT:
            pass

        # ok it does not exist, create it
        attrs = {'nsIdleTimeout': '0',
                 'passwordExpirationTime': '20381010000000Z'}
        server.setupBindDN(repl_manager_dn, repl_manager_pw, attrs)


class DSLogParser:
    """Base parser for Directory Server logs"""
    
    REGEX_TIMESTAMP = re.compile(
        r'\[(?P<day>\d*)\/(?P<month>\w*)\/(?P<year>\d*):(?P<hour>\d*):(?P<minute>\d*):(?P<second>\d*)(\.(?P<nanosecond>\d*))+\s(?P<tz>[\+\-]\d{2})(?P<tz_minute>\d{2})'
    )
    REGEX_LINE = re.compile(
        r'\s(?P<quoted>[^= ]+="[^"]*")|(?P<var>[^= ]+=[^\s]+)|(?P<keyword>[^\s]+)'
    )
    MONTH_LOOKUP = {
        'Jan': "01", 'Feb': "02", 'Mar': "03", 'Apr': "04", 'May': "05", 'Jun': "06",
        'Jul': "07", 'Aug': "08", 'Sep': "09", 'Oct': "10", 'Nov': "11", 'Dec': "12"
    }

    class ParserResult:
        """Container for parsed log line results"""
        def __init__(self):
            self.keywords: List[str] = []
            self.vars: Dict[str, str] = {}
            self.raw: Any = None
            self.timestamp: Optional[str] = None
            self.target_dn: Optional[str] = None

    def __init__(self, logname: str):
        """Initialize the parser
        
        :param logname: Path to the log file
        :type logname: str
        """
        self.logname = logname
        self.lineno = 0
        self.line: Optional[str] = None
        self._logger = logging.getLogger(__name__)
        self.op_context: Dict[Tuple[str, str], str] = {}  # (conn, op) -> dn

    def parse_timestamp(self, ts: str) -> datetime.datetime:
        """Parse a log's timestamp and convert it to a datetime object
        
        :param ts: Timestamp string from log
        :type ts: str
        :returns: Parsed datetime object
        :raises: ValueError if timestamp format is invalid
        """
        try:
            timedata = self.REGEX_TIMESTAMP.match(ts).groupdict()
        except AttributeError as e:
            raise ValueError(f'Failed to parse timestamp {ts}: {e}')

        iso_ts = '{YEAR}-{MONTH}-{DAY}T{HOUR}:{MINUTE}:{SECOND}{TZH}:{TZM}'.format(
            YEAR=timedata['year'], 
            MONTH=self.MONTH_LOOKUP[timedata['month']],
            DAY=timedata['day'], 
            HOUR=timedata['hour'], 
            MINUTE=timedata['minute'],
            SECOND=timedata['second'], 
            TZH=timedata['tz'], 
            TZM=timedata['tz_minute']
        )
        dt = datetime.datetime.fromisoformat(iso_ts)
        if timedata['nanosecond']:
            dt = dt.replace(microsecond=int(timedata['nanosecond']) // 1000)
        return dt

    def parse_line(self) -> Optional['DSLogParser.ParserResult']:
        """Parse a single log line
        
        :returns: ParserResult object or None if line cannot be parsed
        """
        l = self.line.split(']', 1)
        if len(l) != 2:
            return None
            
        result = self.REGEX_LINE.findall(l[1])
        if not result:
            return None

        r = self.ParserResult()
        r.timestamp = l[0] + "]"
        r.raw = result
        
        for (quoted, var, keyword) in result:
            if quoted:
                key, value = quoted.split('=', 1)
                r.vars[key] = value.strip('"')
            if var:
                key, value = var.split('=', 1)
                r.vars[key] = value
            if keyword:
                r.keywords.append(keyword)

        # Track operation context
        if 'conn' in r.vars and 'op' in r.vars:
            conn_op = (r.vars['conn'], r.vars['op'])
            
            # Store DN if present
            if 'dn' in r.vars:
                self.op_context[conn_op] = r.vars['dn']
                
            # Associate DN with CSN on result
            if 'csn' in r.vars and conn_op in self.op_context:
                r.target_dn = self.op_context[conn_op]

        return r

    def parse_file(self) -> None:
        """Parse the entire log file"""
        try:
            with open(self.logname, 'r') as f:
                for self.line in f:
                    self.lineno += 1
                    try:
                        r = self.parse_line()
                        if r:
                            self.action(r)
                    except Exception as e:
                        self._logger.error(f"Error parsing line {self.lineno}: {e}")
                        self._logger.debug(f"Line content: {self.line}")
                        raise
        except Exception as e:
            raise IOError(f"Failed to process log file {self.logname}: {e}")

    def action(self, result: 'DSLogParser.ParserResult') -> None:
        """Action to take on each parsed line - override in subclasses
        
        :param result: Parsed log line result
        :type result: DSLogParser.ParserResult
        """
        print(f'{result.timestamp} {result.keywords} {result.vars}')


class ReplLag:
    """Manages replication lag analysis across multiple log files"""

    def __init__(self, args: Dict[str, Any]):
        """Initialize replication lag analyzer
        
        :param args: Configuration dictionary containing:
                    - server_name: Name of the server
                    - logfiles: List of log files to parse
                    - anonymous: Whether to anonymize server names
        :type args: dict
        """
        self.server_name = args['server_name']
        self.logfiles = args['logfiles']
        self.anonymous = args['anonymous']
        self.nbfiles = len(args['logfiles'])
        self.csns: Dict[str, Dict[int, Dict[str, Any]]] = {}
        self.start_udt: Optional[float] = None
        self.start_dt: Optional[datetime.datetime] = None
        self._logger = logging.getLogger(__name__)

    class Parser(DSLogParser):
        """Nested parser class for handling individual log files"""
        
        def __init__(self, server_name: str, idx: int, logfile: str, result: 'ReplLag'):
            """Initialize the parser
            
            :param server_name: Name of the server
            :param idx: Index of the current log file
            :param logfile: Path to the log file
            :param result: Parent ReplLag instance
            """
            super().__init__(logfile)
            self.result = result
            self.idx = idx
            self.srv_name = server_name
            self._logger = logging.getLogger(__name__)

        def action(self, r: DSLogParser.ParserResult) -> None:
            """Process each parsed log line
            
            :param r: Parsed log line result
            """
            try:
                csn = r.vars['csn']
                dt = self.parse_timestamp(r.timestamp)
                udt = dt.astimezone(datetime.timezone.utc).timestamp()
                
                # Update parent's start time if needed
                if self.result.start_udt is None or self.result.start_udt > udt:
                    self.result.start_udt = udt
                    self.result.start_dt = dt
                
                # Create CSN entry if it doesn't exist
                if csn not in self.result.csns:
                    self.result.csns[csn] = {}
                
                # Create record for this occurrence
                record = {
                    "logtime": udt,
                    "etime": r.vars['etime'],
                    "server_name": self.srv_name
                }
                self.result.csns[csn][self.idx] = record
                
            except KeyError:
                # Skip lines without CSN information
                pass
            except Exception as e:
                self._logger.debug(f"Error processing line: {e}")
                raise

    def parse_files(self) -> None:
        """Parse all log files in the collection"""
        for idx, logfile in enumerate(self.logfiles):
            try:
                parser = self.Parser(self.server_name, idx, logfile, self)
                parser.parse_file()
            except Exception as e:
                self._logger.error(f"Failed to parse file {logfile}: {e}")
                raise

    def build_result(self) -> Dict[str, Any]:
        """Build the final result dictionary
        
        :returns: Dictionary containing parsed replication data
        :raises: ValueError if no data was parsed
        """
        if self.start_dt is None:
            raise ValueError("No valid replication data was parsed")
            
        obj = {
            "start-time": str(self.start_dt),
            "utc-start-time": self.start_udt,
            "utc-offset": self.start_dt.utcoffset().total_seconds(),
            "lag": self.csns
        }
        
        if self.anonymous:
            obj['log-files'] = list(range(len(self.logfiles)))
        else:
            obj['log-files'] = self.logfiles
            
        return obj


class CsnInfo:
    """Represents CSN information for replication analysis"""
    
    def __init__(self, csn: str, tz: datetime.timezone):
        """Initialize CSN tracking
        
        :param csn: Change Sequence Number
        :type csn: str
        :param tz: Timezone for timestamp conversions
        :type tz: datetime.timezone
        """
        self.csn = csn
        self.tz = tz
        self.oldest_time = None  # [timestamp, server_idx]
        self.lag_time = None     # [duration, server_idx]
        self.etime = None        # [duration, server_idx]
        self.replicated_on = {}  # {server_idx: record}
        self.csn_history = []    # [(server_name, timestamp)]
        self.suffix = None       # Matched suffix
        self.target_dn = None    # Target DN from operation

    def add_replication_data(self, server_idx: int, server_name: str, 
                           logtime: float, etime: str, target_dn: Optional[str] = None) -> None:
        """Add replication data from a server
        
        :param server_idx: Index identifying the server
        :param server_name: Name of the server
        :param logtime: Unix timestamp of the log entry
        :param etime: Elapsed time as string
        :param target_dn: Target DN from operation
        """
        record = {
            "logtime": logtime,
            "etime": float(etime),
            "server_name": server_name
        }
        self.replicated_on[server_idx] = record
        self._update_times(logtime, float(etime), server_idx)
        self.csn_history.append((server_name, logtime))
        if target_dn:
            self.target_dn = target_dn

    def _update_times(self, logtime: float, etime: float, idx: int) -> None:
        """Update timing information
        
        :param logtime: Unix timestamp of the log entry
        :param etime: Elapsed time in seconds
        :param idx: Server index
        """
        if self.oldest_time is None or self.oldest_time[0] > logtime:
            self.oldest_time = [logtime, idx]
        if self.lag_time is None or self.lag_time[0] < logtime:
            self.lag_time = [logtime, idx]
        if self.etime is None or self.etime[0] < etime:
            self.etime = [etime, idx]

    def resolve(self) -> None:
        """Calculate final lag time relative to oldest entry"""
        if self.oldest_time is not None and self.lag_time is not None:
            self.lag_time[0] -= self.oldest_time[0]

    def to_dict(self) -> Dict:
        """Convert CSN info to dictionary format
        
        :returns: Dictionary containing CSN data
        """
        return {
            'csn': self.csn,
            'description': self.describe_csn(),
            'lag_time': self.lag_time[0] if self.lag_time else None,
            'etime': self.etime[0] if self.etime else None,
            'replicated_on': self.replicated_on,
            'history': self.csn_history,
            'suffix': self.suffix,
            'target_dn': self.target_dn
        }

    def describe_csn(self) -> str:
        """Return human-readable CSN description
        
        :returns: Formatted CSN description string
        """
        try:
            timestamp_hex = self.csn[:8]
            timestamp = datetime.datetime.fromtimestamp(
                int(timestamp_hex, 16), 
                tz=self.tz
            ).strftime('%Y-%m-%d %H:%M:%S')
            sequence_number = int(self.csn[8:12], 16)
            identifier = int(self.csn[12:16], 16)
            sub_sequence_number = int(self.csn[16:20], 16)
            return (f"{timestamp} | Sequence: {sequence_number} | "
                   f"ID: {identifier} | Sub-sequence: {sub_sequence_number}")
        except Exception as e:
            return f"Failed to describe CSN: {e}"


class LagInfo:
    """Analyzes replication lag across multiple servers"""
    
    def __init__(self, config: Dict):
        """Initialize lag analysis
        
        :param config: Configuration dictionary containing:
                      - start_time: Optional start time filter
                      - end_time: Optional end time filter
                      - suffixes: List of suffixes to track
                      - utc_offset: UTC offset in seconds
        :type config: dict
        """
        self.utc_offset = config.get('utc_offset')
        self.tz = (datetime.timezone(datetime.timedelta(seconds=self.utc_offset))
                  if self.utc_offset is not None else datetime.timezone.utc)
        self.start_time = self._parse_time(config.get('start_time'))
        self.end_time = self._parse_time(config.get('end_time'))
        self.lag = []  # List[CsnInfo]
        self.servers = set()
        self.suffix_processor = SuffixProcessor(config.get('suffixes', []))
        self._logger = logging.getLogger(__name__)

    def _parse_time(self, time_str: Optional[str]) -> Optional[datetime.datetime]:
        """Parse time string to datetime
        
        :param time_str: Time string in format 'YYYY-MM-DD HH:MM:SS'
        :returns: Datetime object or None
        """
        if not time_str:
            return None
        try:
            return datetime.datetime.strptime(
                time_str, 
                '%Y-%m-%d %H:%M:%S'
            ).replace(tzinfo=self.tz)
        except ValueError as e:
            self._logger.warning(f"Invalid time format: {e}")
            return None

    def add_csn_data(self, csn_info: CsnInfo) -> None:
        """Add CSN data with suffix matching
        
        :param csn_info: CSN information object
        :type csn_info: CsnInfo
        """
        if csn_info.target_dn:
            csn_info.suffix = self.suffix_processor.match_suffix(csn_info.target_dn)
        self.lag.append(csn_info)

    def get_statistics(self) -> Dict[str, Union[float, int]]:
        """Calculate replication lag statistics
        
        :returns: Dictionary containing lag statistics
        """
        self.resolve_all()
        lag_times = [info.lag_time[0] for info in self.lag 
                    if info.lag_time is not None]
        
        if not lag_times:
            return {
                'min_lag': 0.0,
                'max_lag': 0.0,
                'avg_lag': 0.0,
                'total_updates': 0,
                'updates_by_suffix': {}
            }
            
        # Group updates by suffix
        suffix_updates = {}
        for info in self.lag:
            suffix = info.suffix or 'unknown'
            suffix_updates[suffix] = suffix_updates.get(suffix, 0) + 1
            
        return {
            'min_lag': min(lag_times),
            'max_lag': max(lag_times),
            'avg_lag': sum(lag_times) / len(lag_times),
            'total_updates': len(lag_times),
            'updates_by_suffix': suffix_updates
        }

    def resolve_all(self) -> None:
        """Resolve lag times for all CSNs"""
        for csn_info in self.lag:
            csn_info.resolve()


class SuffixProcessor:
    """Handles suffix normalization and matching for replication analysis"""
    
    def __init__(self, suffixes: List[str]):
        """Initialize suffix processor
        
        :param suffixes: List of suffix DNs
        :type suffixes: list
        """
        self.suffixes = self._normalize_suffixes(suffixes)
        self._logger = logging.getLogger(__name__)
        
    def _normalize_suffixes(self, suffixes: List[str]) -> List[str]:
        """Normalize and sort suffixes by length (longest first)
        
        :param suffixes: List of suffix DNs
        :returns: Normalized and sorted suffix list
        """
        normalized = [dn.lower().replace(' ', '') for dn in suffixes if dn]
        return sorted(normalized, key=len, reverse=True)
        
    def match_suffix(self, dn: str) -> Optional[str]:
        """Find matching suffix for given DN
        
        :param dn: Entry DN to match
        :returns: Matching suffix or None
        """
        if not dn:
            return None
            
        try:
            normalized_dn = dn.lower().replace(' ', '')
            for suffix in self.suffixes:
                if normalized_dn.endswith(suffix):
                    return suffix
        except Exception as e:
            self._logger.warning(f"Error matching suffix for DN {dn}: {e}")
        return None



class ReplicationLogAnalyzer:
    """Analyzes replication logs across multiple servers"""
    
    def __init__(self, log_dirs: List[str], suffixes: Optional[List[str]] = None,
                 anonymous: bool = False):
        """Initialize the replication log analyzer
        
        :param log_dirs: List of directories containing server logs
        :type log_dirs: list
        :param suffixes: Optional list of suffixes to track
        :type suffixes: list
        :param anonymous: Whether to anonymize server names
        :type anonymous: bool
        """
        if not log_dirs:
            raise ValueError("No log directories provided")
            
        self.log_dirs = log_dirs
        self.anonymous = anonymous
        self.suffixes = suffixes or []
        self.servers_data = {}
        self._logger = logging.getLogger(__name__)

    def _validate_formats(self, formats: List[str]) -> None:
        """Validate output format specifications
        
        :param formats: List of output formats
        :raises: ValueError if invalid format specified
        """
        valid_formats = {'csv', 'html'}
        invalid_formats = set(formats) - valid_formats
        if invalid_formats:
            raise ValueError(f"Invalid output format(s): {', '.join(invalid_formats)}")

    def process_logs(self) -> Dict:
        """Process all logs from provided directories
        
        :returns: Dictionary containing processed replication data
        :raises: ValueError if no valid logs found
                OSError if log files cannot be accessed
        """
        for log_dir in self.log_dirs:
            if not os.path.exists(log_dir):
                raise OSError(f"Log directory not found: {log_dir}")
                
            server_name = os.path.basename(log_dir.rstrip('/'))
            log_files = self._get_log_files(log_dir)
            
            if not log_files:
                self._logger.warning(f"No valid log files found in {log_dir}")
                continue

            try:
                parser = ReplLag({
                    'server_name': server_name,
                    'logfiles': log_files,
                    'anonymous': self.anonymous
                })
                parser.parse_files()
                self.servers_data[server_name] = parser.build_result()
            except Exception as e:
                self._logger.error(f"Failed to process logs for {server_name}: {e}")
                raise

        if not self.servers_data:
            raise ValueError("No valid replication data found in any log directory")

        return self._merge_results()

    def _get_log_files(self, log_dir: str) -> List[str]:
        """Get all relevant log files from directory
        
        :param log_dir: Directory containing log files
        :type log_dir: str
        :returns: List of log file paths sorted by name
        :raises: OSError if directory cannot be accessed
        """
        if not os.path.exists(log_dir):
            raise OSError(f"Log directory does not exist: {log_dir}")
            
        log_files = []
        for file in os.listdir(log_dir):
            if file.startswith('access'):
                full_path = os.path.join(log_dir, file)
                if os.path.isfile(full_path) and os.access(full_path, os.R_OK):
                    log_files.append(full_path)
                else:
                    self._logger.warning(f"Cannot access log file: {full_path}")
        
        return sorted(log_files)

    def _merge_results(self) -> Dict:
        """Merge results from all servers into a consolidated report
        
        :returns: Merged replication data dictionary
        :raises: ValueError if no data to merge
        """
        if not self.servers_data:
            raise ValueError("No replication data available")

        merged = {
            'start-time': min(data['start-time'] for data in self.servers_data.values()),
            'servers': list(self.servers_data.keys()),
            'lag': {},
            'metadata': {
                'analyzed_at': datetime.datetime.now().isoformat(),
                'server_count': len(self.servers_data),
                'anonymous': self.anonymous,
                'suffixes': self.suffixes
            }
        }

        for server_name, server_data in self.servers_data.items():
            for csn, lag_data in server_data['lag'].items():
                if csn not in merged['lag']:
                    merged['lag'][csn] = {}
                merged['lag'][csn].update({
                    server_name: lag_data
                })

        return merged

    def generate_report(self, 
                       output_dir: str, 
                       formats: List[str] = ['html'],
                       start_time: Optional[str] = None,
                       end_time: Optional[str] = None,
                       repl_lag_threshold: float = 0,
                       report_name: str = 'replication_analysis') -> Dict[str, str]:
        """Generate replication analysis report in specified formats
        
        :param output_dir: Directory for output files
        :type output_dir: str
        :param formats: List of output formats ('csv', 'html')
        :type formats: list
        :param start_time: Start time filter (YYYY-MM-DD HH:MM:SS)
        :type start_time: str
        :param end_time: End time filter (YYYY-MM-DD HH:MM:SS)
        :type end_time: str
        :param repl_lag_threshold: Replication lag threshold in seconds
        :type repl_lag_threshold: float
        :param report_name: Base name for report files
        :type report_name: str
        :returns: Dictionary mapping formats to generated file paths
        """
        # Validate output directory
        if not os.path.exists(output_dir):
            try:
                os.makedirs(output_dir)
                self._logger.info(f"Created output directory: {output_dir}")
            except OSError as e:
                raise OSError(f"Failed to create output directory: {e}")
        elif not os.path.isdir(output_dir):
            raise ValueError(f"Output path exists but is not a directory: {output_dir}")
        elif not os.access(output_dir, os.W_OK):
            raise ValueError(f"Output directory is not writable: {output_dir}")

        # Initialize lag analysis
        lag_info = LagInfo({
            'start_time': start_time,
            'end_time': end_time,
            'repl_lag_threshold': repl_lag_threshold,
            'suffixes': self.suffixes,
            'utc_offset': None
        })

        # Process data with suffix matching
        data = self.process_logs()
        for csn, server_data in data['lag'].items():
            for _, records in server_data.items():
                for record_idx, record in records.items():
                    csn_info = CsnInfo(csn, lag_info.tz)
                    csn_info.add_replication_data(
                        int(record_idx),
                        record['server_name'],
                        record['logtime'],
                        record['etime'],
                        record.get('target_dn')
                    )
                    lag_info.add_csn_data(csn_info)
                    lag_info.servers.add(record['server_name'].lower())

        # Generate reports
        generated_files = {}
        self._validate_formats(formats)

        for fmt in formats:
            output_path = os.path.join(output_dir, f'{report_name}.{fmt}')
            try:
                if fmt == 'csv':
                    self._generate_csv_report(lag_info, output_path)
                elif fmt == 'html':
                    self._generate_html_report(lag_info, output_path)
                generated_files[fmt] = output_path
            except Exception as e:
                self._logger.error(f"Failed to generate {fmt} report: {e}")
                raise

        # Generate summary JSON
        summary_path = os.path.join(output_dir, f'{report_name}_summary.json')
        try:
            stats = lag_info.get_statistics()
            with open(summary_path, 'w') as f:
                json.dump({
                    'analysis_summary': {
                        'total_servers': len(data['servers']),
                        'analyzed_logs': len(data['lag']),
                        'total_updates': stats['total_updates'],
                        'average_lag': stats['avg_lag'],
                        'maximum_lag': stats['max_lag'],
                        'minimum_lag': stats['min_lag'],
                        'updates_by_suffix': stats['updates_by_suffix'],
                        'time_range': {
                            'start': data.get('start-time'),
                            'end': end_time or 'current'
                        },
                        'lag_threshold': repl_lag_threshold,
                        'generated_files': generated_files,
                        'servers': data['servers'],
                        'suffixes': self.suffixes
                    }
                }, f, indent=2)
            generated_files['summary'] = summary_path
        except Exception as e:
            self._logger.error(f"Failed to write summary JSON: {e}")
            raise

        return generated_files

    def _generate_csv_report(self, lag_info: LagInfo, output_path: str) -> None:
        """Generate CSV report of replication lag
        
        :param lag_info: Lag analysis information
        :param output_path: Output file path
        """
        with open(output_path, "w", encoding="utf-8") as csv_file:
            csv_file.write("timestamp,server_name,csn,lag_time,etime,suffix,target_dn,description\n")
            for csn_info in sorted(lag_info.lag, 
                                 key=lambda x: x.oldest_time[0] if x.oldest_time else 0):
                base_time = csn_info.oldest_time[0] if csn_info.oldest_time else 0
                desc = csn_info.describe_csn()
                
                for server_name, timestamp in csn_info.csn_history:
                    lag_time = timestamp - base_time if base_time else 0
                    record = csn_info.replicated_on.get(
                        list(lag_info.servers).index(server_name), {}
                    )
                    etime = record.get('etime', 0)
                    
                    csv_file.write(
                        f"{datetime.datetime.fromtimestamp(timestamp, lag_info.tz).strftime('%Y-%m-%d %H:%M:%S')},"
                        f"{server_name},{csn_info.csn},{lag_time},{etime},"
                        f"{csn_info.suffix or ''},"
                        f"{csn_info.target_dn or ''},"
                        f"{desc}\n"
                    )

    def _generate_html_report(self, lag_info: LagInfo, output_path: str) -> None:
        """Generate interactive HTML report of replication lag
        
        :param lag_info: Lag analysis information
        :param output_path: Output file path
        :raises: ImportError if plotly not available
        """
        try:
            import plotly.graph_objs as go
            import plotly.io as pio
        except ImportError:
            raise ImportError("plotly is required for interactive HTML plot generation")

        # Prepare data by suffix
        data = []
        for suffix in lag_info.suffix_processor.suffixes + ['unknown']:
            for server in lag_info.servers:
                suffix_times = []
                suffix_lags = []
                suffix_etimes = []
                hover_texts = []
                
                for csn_info in sorted(
                    [info for info in lag_info.lag 
                     if (info.suffix or 'unknown') == suffix],
                    key=lambda x: x.oldest_time[0] if x.oldest_time else 0
                ):
                    server_idx = list(lag_info.servers).index(server)
                    if server_idx in csn_info.replicated_on:
                        record = csn_info.replicated_on[server_idx]
                        timestamp = datetime.datetime.fromtimestamp(
                            record['logtime'], 
                            lag_info.tz
                        )
                        lag_time = (record['logtime'] - csn_info.oldest_time[0] 
                                  if csn_info.oldest_time else 0)
                        
                        suffix_times.append(timestamp)
                        suffix_lags.append(lag_time)
                        suffix_etimes.append(record['etime'])
                        hover_texts.append(
                            f"CSN: {csn_info.csn}<br>"
                            f"Description: {csn_info.describe_csn()}<br>"
                            f"Lag Time: {lag_time:.2f}s<br>"
                            f"Elapsed Time: {record['etime']:.2f}s<br>"
                            f"Target DN: {csn_info.target_dn or 'unknown'}"
                        )

                if suffix_times:  # Only add traces if we have data
                    suffix_name = suffix or 'unknown'
                    data.extend([
                        go.Scatter(
                            x=suffix_times,
                            y=suffix_lags,
                            name=f'{suffix_name} - {server} - Lag',
                            mode='lines+markers',
                            text=hover_texts,
                            hoverinfo='text+x+y'
                        ),
                        go.Scatter(
                            x=suffix_times,
                            y=suffix_etimes,
                            name=f'{suffix_name} - {server} - Elapsed Time',
                            mode='lines+markers',
                            text=hover_texts,
                            hoverinfo='text+x+y'
                        )
                    ])

        # Create layout with suffix filtering buttons
        suffix_buttons = [
            dict(
                args=[{"visible": [True] * len(data)}],
                label="All Suffixes",
                method="restyle"
            )
        ]

        for suffix in lag_info.suffix_processor.suffixes + ['unknown']:
            visible = [
                suffix in trace.name 
                for trace in data
            ]
            suffix_buttons.append(
                dict(
                    args=[{"visible": visible}],
                    label=suffix or "Unknown",
                    method="restyle"
                )
            )

        layout = go.Layout(
            title='Replication Lag Analysis by Suffix',
            xaxis=dict(title='Time'),
            yaxis=dict(title='Seconds'),
            hovermode='closest',
            showlegend=True,
            updatemenus=[
                dict(
                    buttons=suffix_buttons,
                    direction="down",
                    showactive=True,
                    x=0.1,
                    y=1.1,
                    xanchor="left",
                    yanchor="top"
                )
            ]
        )

        # Create figure and save
        fig = go.Figure(data=data, layout=layout)
        try:
            pio.write_html(fig, output_path)
        except Exception as e:
            raise IOError(f"Failed to write HTML file: {e}")

    def get_lag_statistics(self) -> Dict[str, Union[float, int]]:
        """Calculate replication lag statistics across all servers
        
        :returns: Dictionary containing lag statistics
        """
        if not self.servers_data:
            return {
                'min_lag': 0.0,
                'max_lag': 0.0,
                'avg_lag': 0.0,
                'total_updates': 0
            }
            
        lag_times = []
        for server_data in self.servers_data.values():
            for csn_data in server_data.get('lag', {}).values():
                for record in csn_data.values():
                    if 'logtime' in record:
                        lag_times.append(float(record['logtime']))
                        
        if not lag_times:
            return {
                'min_lag': 0.0,
                'max_lag': 0.0,
                'avg_lag': 0.0,
                'total_updates': 0
            }
            
        return {
            'min_lag': min(lag_times),
            'max_lag': max(lag_times),
            'avg_lag': sum(lag_times) / len(lag_times),
            'total_updates': len(lag_times)
        }
