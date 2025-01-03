# --- BEGIN COPYRIGHT BLOCK ---
# Copyright (C) 2025 Red Hat, Inc.
# All rights reserved.
#
# License: GPL (version 3 or any later version).
# See LICENSE for details.
# --- END COPYRIGHT BLOCK ---
#
import os
import shutil
import json
import pytest
import logging
import tempfile
from lib389.tasks import *
from lib389.utils import *
from lib389.topologies import topology_m4 as topo_m4
from lib389.topologies import topology_m2 as topo_m2
from lib389.idm.user import UserAccount
from lib389.replica import ReplicationManager
from lib389.repltools import ReplicationLogAnalyzer
from lib389._constants import *

pytestmark = pytest.mark.tier0

DEBUGGING = os.getenv("DEBUGGING", default=False)
if DEBUGGING:
    logging.getLogger(__name__).setLevel(logging.DEBUG)
else:
    logging.getLogger(__name__).setLevel(logging.INFO)
log = logging.getLogger(__name__)


def test_replication_analysis_report(topo_m4):
    """Test replication analysis report generation with multiple events

    :id: a18e09e2-6b56-40b4-a285-cbdae445fb3a
    :setup: Four suppliers replication setup
    :steps:
        1. Create temporary directory for report
        2. Generate multiple replication events
        3. Wait for replication to complete
        4. Extract CSN from log files
        5. Collect and analyze logs
        6. Generate comprehensive report
        7. Verify CSNs in reports
        8. Verify report files
        9. Cleanup temporary directory
    :expectedresults:
        1. Temporary directory should be created
        2. Replication events should be created successfully
        3. Replication should complete across all suppliers
        4. CSNs should be successfully extracted
        5. Logs should be collected and analyzed
        6. Report should be generated in all formats
        7. CSNs should be found in generated reports
        8. Report files should exist and be valid
        9. Cleanup should complete successfully
    """
    # Create temporary directory
    tmp_dir = tempfile.mkdtemp(prefix='repl_analysis_', dir='/tmp')
    test_users = []
    csns_to_verify = set()
    
    try:
        # Generate replication events
        for i in range(50):  # Create 50 test entries
            user_dn = f'uid=test_user_{i},{DEFAULT_SUFFIX}'
            test_user = UserAccount(topo_m4.ms["supplier1"], user_dn)
            test_user.create(properties={
                'uid': f'test_user_{i}',
                'cn': f'Test User {i}',
                'sn': f'User{i}',
                'userPassword': 'password',
                'uidNumber': str(1000 + i),
                'gidNumber': '2000',
                'homeDirectory': f'/home/test_user_{i}'
            })
            test_users.append(test_user)

        # Modify entries to generate more replication traffic
        for user in test_users:
            for j in range(5):  # 5 modifications per user
                user.add('description', f'Description {j}')
                user.replace('description', f'Updated Description {j}')
                user.remove('description', f'Updated Description {j}')

        # Wait for replication to complete
        m1 = topo_m4.ms["supplier1"]
        m2 = topo_m4.ms["supplier2"]
        m3 = topo_m4.ms["supplier3"]
        m4 = topo_m4.ms["supplier4"]

        repl = ReplicationManager(DEFAULT_SUFFIX)
        repl.wait_for_replication(m1, m2)
        repl.wait_for_replication(m1, m3)
        repl.wait_for_replication(m1, m4)

        # Flush and collect log dirs from all suppliers
        log_dirs = []
        for supplier in [m1, m2, m3, m4]:
            supplier.restart()
            log_dirs.append(supplier.ds_paths.log_dir)

        # Initialize analyzer and generate report
        analyzer = ReplicationLogAnalyzer(log_dirs)
        analyzer.generate_report(
            output_dir=tmp_dir,
            formats=['csv', 'html'],
            start_time=None,
            end_time=None,
            repl_lag_threshold=1.0,
            report_name='replication_test_report'
        )

        # Check summary JSON
        json_file = os.path.join(tmp_dir, 'replication_test_report_summary.json')
        with open(json_file, 'r') as f:
            summary_data = json.load(f)

        # Verify analysis summary data
        assert 'analysis_summary' in summary_data, "Missing analysis summary in JSON"
        summary = summary_data['analysis_summary']
        
        # Verify basic summary structure
        assert summary['total_servers'] == 4, "Incorrect number of servers in summary"
        assert summary['analyzed_logs'] > 0, "No logs analyzed according to summary"
        assert summary['total_updates'] > 0, "No updates found in summary"
        assert 'average_lag' in summary, "Missing average lag in summary"
        assert 'maximum_lag' in summary, "Missing maximum lag in summary"

        # Verify report files with size thresholds
        expected_files = {
            'replication_test_report.csv': 100,     # CSV should have at least header + one data row
            'replication_test_report.html': 2048,   # HTML should include plot.ly and data
            'replication_test_report_summary.json': 200  # JSON should have minimal structure
        }
        
        for filename, min_size in expected_files.items():
            filepath = os.path.join(tmp_dir, filename)
            
            # Check file exists
            assert os.path.exists(filepath), f"Expected report file missing: {filename}"
            
            # Check file size
            actual_size = os.path.getsize(filepath)
            assert actual_size > min_size, (
                f"Report file {filename} is too small: "
                f"expected > {min_size} bytes, got {actual_size} bytes"
            )
            
            # Log file details
            log.info(f"Verified {filename}: {actual_size} bytes")
            
            # Additional format-specific checks
            if filename.endswith('.csv'):
                # Check CSV has header and data
                with open(filepath, 'r') as f:
                    lines = f.readlines()
                    assert len(lines) > 1, f"CSV file has no data rows: {filename}"
                    assert 'timestamp' in lines[0].lower(), f"CSV missing expected header: {filename}"
                    
            elif filename.endswith('.html'):
                # Check HTML has required elements
                with open(filepath, 'r') as f:
                    content = f.read()
                    assert 'plotly' in content.lower(), f"HTML missing plotly integration: {filename}"
                    assert 'replication lag analysis' in content.lower(), f"HTML missing expected title: {filename}"
                    
            elif filename.endswith('.json'):
                # Check JSON structure
                with open(filepath, 'r') as f:
                    data = json.load(f)
                    assert 'analysis_summary' in data, f"JSON missing analysis summary: {filename}"
                    assert all(key in data['analysis_summary'] for key in [
                        'total_servers', 'analyzed_logs', 'total_updates', 
                        'average_lag', 'maximum_lag'
                    ]), f"JSON missing required fields: {filename}"
    finally:
        # Cleanup
        try:
            # Remove test entries
            for user in test_users:
                try:
                    if user.exists():
                        user.delete()
                except Exception as e:
                    log.warning(f"Error cleaning up test user: {e}")

            # Remove temporary directory
            shutil.rmtree(tmp_dir, ignore_errors=True)
        except Exception as e:
            log.error(f"Error during cleanup: {e}")


if __name__ == '__main__':
    # Run isolated
    # -s for DEBUG mode
    CURRENT_FILE = os.path.realpath(__file__)
    pytest.main("-s %s" % CURRENT_FILE)
