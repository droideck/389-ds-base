# --- BEGIN COPYRIGHT BLOCK ---
# Copyright (C) 2025 Red Hat, Inc.
# All rights reserved.
#
# License: GPL (version 3 or any later version).
# See LICENSE for details.
# --- END COPYRIGHT BLOCK ---
#
import os
import time
import random
import pytest
import logging
import threading
from datetime import datetime
from random import choice, randint, shuffle

from lib389.utils import *
from lib389.topologies import topology_m4
from lib389.idm.user import UserAccount, UserAccounts
from lib389.idm.group import Group, Groups
from lib389.idm.organizationalunit import OrganizationalUnits
from lib389.plugins import MemberOfPlugin
from lib389.replica import ReplicationManager
from lib389._constants import *

pytestmark = pytest.mark.tier1

DEBUGGING = os.getenv("DEBUGGING", default=False)
if DEBUGGING:
    logging.getLogger(__name__).setLevel(logging.DEBUG)
else:
    logging.getLogger(__name__).setLevel(logging.INFO)
log = logging.getLogger(__name__)

# Configuration for the simulation
NUM_USERS = 500          # Number of users to create
NUM_GROUPS = 50          # Number of groups to create
NUM_OU = 10              # Number of organizational units
SIMULATION_DURATION = 3600  # Run for 1 hour (3600 seconds) - adjust as needed
MIN_DELAY = 0.1          # Minimum delay between operations (seconds)
MAX_DELAY = 2.0          # Maximum delay between operations (seconds)
BATCH_SIZE = 20          # Operations per batch before sync check

# User and group name patterns
USER_PREFIX = "sim_user"
GROUP_PREFIX = "sim_group"
OU_PREFIX = "sim_ou"


def setup_memberof_plugin(suppliers):
    """Enable and configure memberof plugin on all suppliers"""
    log.info("Setting up MemberOf plugin on all suppliers")

    for supplier in suppliers:
        memberof = MemberOfPlugin(supplier)
        memberof.enable()
        memberof.set('memberOfAutoAddOC', 'nsMemberOf')
        memberof.set('memberOfAllBackends', 'on')
        supplier.restart()

    # Wait for all suppliers to come back up
    time.sleep(5)


def create_organizational_structure(suppliers):
    """Create organizational units for better structure"""
    log.info(f"Creating {NUM_OU} organizational units")

    supplier = suppliers[0]
    ous = OrganizationalUnits(supplier, DEFAULT_SUFFIX)
    created_ous = []

    for i in range(NUM_OU):
        ou_name = f"{OU_PREFIX}_{i:03d}"
        try:
            ou = ous.create(properties={
                'ou': ou_name,
                'description': f'Organizational Unit {i} for simulation'
            })
            created_ous.append(ou)
            log.debug(f"Created OU: {ou.dn}")
        except Exception as e:
            log.warning(f"Failed to create OU {ou_name}: {e}")

    return created_ous


def create_user_accounts(suppliers, ous):
    """Create user accounts distributed across OUs"""
    log.info(f"Creating {NUM_USERS} user accounts")

    supplier = suppliers[0]
    created_users = []

    for i in range(NUM_USERS):
        # Distribute users across OUs and default suffix
        if ous and i % 3 == 0:  # 1/3 of users in OUs
            base_dn = choice(ous).dn
        else:
            base_dn = DEFAULT_SUFFIX

        user_id = f"{USER_PREFIX}_{i:04d}"
        user_dn = f"uid={user_id},{base_dn}"

        try:
            user = UserAccount(supplier, user_dn)
            user.create(properties={
                'uid': user_id,
                'cn': f'Simulation User {i}',
                'sn': f'User{i:04d}',
                'givenName': f'Sim{i:04d}',
                'displayName': f'Simulation User {i:04d}',
                'mail': f'{user_id}@simulation.example.com',
                'userPassword': f'password{i:04d}',
                'uidNumber': str(10000 + i),
                'gidNumber': str(20000 + (i % 10)),
                'homeDirectory': f'/home/{user_id}',
                'loginShell': '/bin/bash',
                'description': f'Test user {i} for access log simulation',
                'telephoneNumber': f'+1-555-{1000 + i:04d}',
                'employeeNumber': str(100000 + i),
                'title': choice(['Engineer', 'Manager', 'Analyst', 'Developer', 'Administrator']),
                'departmentNumber': str(1000 + (i % 20))
            })
            created_users.append(user)

            if i % 50 == 0:
                log.info(f"Created {i+1}/{NUM_USERS} users")

        except Exception as e:
            log.warning(f"Failed to create user {user_id}: {e}")

    log.info(f"Successfully created {len(created_users)} users")
    return created_users


def create_groups_with_members(suppliers, users, ous):
    """Create groups and add members to them"""
    log.info(f"Creating {NUM_GROUPS} groups with members")

    supplier = suppliers[0]
    created_groups = []

    for i in range(NUM_GROUPS):
        # Distribute groups across OUs and default suffix
        if ous and i % 4 == 0:  # 1/4 of groups in OUs
            base_dn = choice(ous).dn
        else:
            base_dn = DEFAULT_SUFFIX

        group_name = f"{GROUP_PREFIX}_{i:03d}"
        group_dn = f"cn={group_name},{base_dn}"

        try:
            group = Group(supplier, group_dn)
            group.create(properties={
                'cn': group_name,
                'description': f'Simulation group {i} with random members',
                'ou': choice(['Engineering', 'Marketing', 'Sales', 'Support', 'Administration'])
            })

            # Add random users to this group
            num_members = randint(5, 25)  # Each group gets 5-25 members
            group_members = random.sample(users, min(num_members, len(users)))

            for member in group_members:
                try:
                    group.add_member(member.dn)
                except Exception as e:
                    log.debug(f"Failed to add member {member.dn} to group {group_name}: {e}")

            created_groups.append(group)
            log.debug(f"Created group: {group.dn} with {num_members} members")

        except Exception as e:
            log.warning(f"Failed to create group {group_name}: {e}")

    log.info(f"Successfully created {len(created_groups)} groups")
    return created_groups


def wait_for_replication_sync(suppliers):
    """Wait for replication to sync across all suppliers"""
    log.debug("Waiting for replication sync...")
    repl = ReplicationManager(DEFAULT_SUFFIX)

    # Wait for replication between all supplier pairs
    for i, s1 in enumerate(suppliers):
        for j, s2 in enumerate(suppliers):
            if i != j:
                try:
                    repl.wait_for_replication(s1, s2, timeout=30)
                except Exception as e:
                    log.warning(f"Replication sync timeout between supplier{i+1} and supplier{j+1}: {e}")


class AccessLogSimulator:
    """Class to simulate realistic LDAP operations and generate access logs"""

    def __init__(self, suppliers, users, groups, ous):
        self.suppliers = suppliers
        self.users = users
        self.groups = groups
        self.ous = ous
        self.running = True
        self.operation_count = 0

    def stop(self):
        """Stop the simulation"""
        self.running = False

    def random_delay(self):
        """Add a random delay to simulate realistic timing"""
        delay = random.uniform(MIN_DELAY, MAX_DELAY)
        time.sleep(delay)

    def perform_search_operations(self):
        """Perform various search operations"""
        supplier = choice(self.suppliers)

        search_operations = [
            # Basic user searches
            lambda: supplier.search_s(DEFAULT_SUFFIX, ldap.SCOPE_SUBTREE, f"(uid={choice(self.users).get_attr_val('uid')})"),
            lambda: supplier.search_s(DEFAULT_SUFFIX, ldap.SCOPE_SUBTREE, f"(cn=*User*)", ['cn', 'mail', 'telephoneNumber']),
            lambda: supplier.search_s(DEFAULT_SUFFIX, ldap.SCOPE_SUBTREE, f"(sn=User{randint(0, NUM_USERS-1):04d})"),
            lambda: supplier.search_s(DEFAULT_SUFFIX, ldap.SCOPE_SUBTREE, f"(mail=*@simulation.example.com)", ['uid', 'cn', 'mail']),

            # Group searches
            lambda: supplier.search_s(DEFAULT_SUFFIX, ldap.SCOPE_SUBTREE, f"(cn={choice(self.groups).get_attr_val('cn')})"),
            lambda: supplier.search_s(DEFAULT_SUFFIX, ldap.SCOPE_SUBTREE, "(objectClass=groupOfNames)", ['cn', 'member']),
            lambda: supplier.search_s(DEFAULT_SUFFIX, ldap.SCOPE_SUBTREE, "(objectClass=posixGroup)", ['cn', 'memberUid']),

            # MemberOf searches
            lambda: supplier.search_s(DEFAULT_SUFFIX, ldap.SCOPE_SUBTREE, "(memberOf=*)", ['uid', 'cn', 'memberOf']),
            lambda: supplier.search_s(choice(self.users).dn, ldap.SCOPE_BASE, "(objectClass=*)", ['memberOf']),

            # Complex searches
            lambda: supplier.search_s(DEFAULT_SUFFIX, ldap.SCOPE_SUBTREE, f"(&(objectClass=inetOrgPerson)(title=Engineer))", ['cn', 'title', 'mail']),
            lambda: supplier.search_s(DEFAULT_SUFFIX, ldap.SCOPE_SUBTREE, f"(&(objectClass=inetOrgPerson)(departmentNumber={1000 + randint(0, 19)}))", ['cn', 'departmentNumber']),

            # Organizational unit searches
            lambda: supplier.search_s(DEFAULT_SUFFIX, ldap.SCOPE_SUBTREE, "(objectClass=organizationalUnit)", ['ou', 'description']) if self.ous else None,
        ]

        # Filter out None operations and execute random one
        valid_operations = [op for op in search_operations if op is not None]
        if valid_operations:
            try:
                operation = choice(valid_operations)
                result = operation()
                log.debug(f"Search returned {len(result)} entries")
                return True
            except Exception as e:
                log.debug(f"Search operation failed: {e}")

        return False

    def perform_modify_operations(self):
        """Perform various modify operations"""
        supplier = choice(self.suppliers)

        modify_operations = [
            # Modify user attributes
            self.modify_user_description,
            self.modify_user_telephone,
            self.modify_user_title,
            self.modify_user_mail,

            # Group membership changes
            self.modify_group_membership,
            self.modify_group_description,

            # Password changes
            self.change_user_password,
        ]

        try:
            operation = choice(modify_operations)
            return operation(supplier)
        except Exception as e:
            log.debug(f"Modify operation failed: {e}")
            return False

    def modify_user_description(self, supplier):
        """Modify a user's description"""
        user = choice(self.users)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        new_description = f"Updated description at {timestamp}"

        supplier.modify_s(user.dn, [(ldap.MOD_REPLACE, 'description', [new_description.encode('utf-8')])])
        return True

    def modify_user_telephone(self, supplier):
        """Modify a user's telephone number"""
        user = choice(self.users)
        new_phone = f"+1-555-{randint(2000, 9999)}"

        supplier.modify_s(user.dn, [(ldap.MOD_REPLACE, 'telephoneNumber', [new_phone.encode('utf-8')])])
        return True

    def modify_user_title(self, supplier):
        """Modify a user's job title"""
        user = choice(self.users)
        titles = ['Senior Engineer', 'Lead Developer', 'Project Manager', 'Technical Lead', 'Architect']
        new_title = choice(titles)

        supplier.modify_s(user.dn, [(ldap.MOD_REPLACE, 'title', [new_title.encode('utf-8')])])
        return True

    def modify_user_mail(self, supplier):
        """Modify a user's email address"""
        user = choice(self.users)
        uid = user.get_attr_val('uid')
        domains = ['simulation.example.com', 'test.example.org', 'demo.example.net']
        new_mail = f"{uid}@{choice(domains)}"

        supplier.modify_s(user.dn, [(ldap.MOD_REPLACE, 'mail', [new_mail.encode('utf-8')])])
        return True

    def modify_group_membership(self, supplier):
        """Add or remove users from groups"""
        group = choice(self.groups)
        user = choice(self.users)

        # Randomly decide to add or remove
        if randint(0, 1):
            # Add member
            try:
                supplier.modify_s(group.dn, [(ldap.MOD_ADD, 'member', [user.dn.encode('utf-8')])])
                log.debug(f"Added {user.dn} to {group.dn}")
                return True
            except ldap.TYPE_OR_VALUE_EXISTS:
                # Member already exists, try to remove instead
                pass

        # Remove member
        try:
            supplier.modify_s(group.dn, [(ldap.MOD_DELETE, 'member', [user.dn.encode('utf-8')])])
            log.debug(f"Removed {user.dn} from {group.dn}")
            return True
        except (ldap.NO_SUCH_ATTRIBUTE, ldap.NO_SUCH_OBJECT):
            log.debug(f"Member {user.dn} not in group {group.dn}")

        return False

    def modify_group_description(self, supplier):
        """Modify a group's description"""
        group = choice(self.groups)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        new_description = f"Group updated at {timestamp}"

        supplier.modify_s(group.dn, [(ldap.MOD_REPLACE, 'description', [new_description.encode('utf-8')])])
        return True

    def change_user_password(self, supplier):
        """Change a user's password"""
        user = choice(self.users)
        new_password = f"newpass{randint(10000, 99999)}"

        supplier.modify_s(user.dn, [(ldap.MOD_REPLACE, 'userPassword', [new_password.encode('utf-8')])])
        return True

    def perform_bind_operations(self):
        """Perform bind operations with different users"""
        supplier = choice(self.suppliers)
        user = choice(self.users)

        try:
            # Try to bind as the user (most will fail since we don't know the current password)
            uid = user.get_attr_val('uid')
            user_dn = user.dn

            # Create a new connection for the bind test
            test_conn = ldap.initialize(f"ldap://{supplier.host}:{supplier.port}")
            try:
                # This will likely fail, but it generates access log entries
                test_conn.simple_bind_s(user_dn, f"password{uid[-4:]}")
                log.debug(f"Successfully bound as {user_dn}")
                test_conn.unbind_s()
                return True
            except ldap.INVALID_CREDENTIALS:
                log.debug(f"Bind failed for {user_dn} (expected)")
                test_conn.unbind_s()
                return True
            except Exception as e:
                log.debug(f"Bind error for {user_dn}: {e}")
                test_conn.unbind_s()

        except Exception as e:
            log.debug(f"Bind operation setup failed: {e}")

        return False

    def run_simulation_cycle(self):
        """Run one cycle of mixed operations"""
        operations_this_cycle = 0

        # Define operation weights (higher number = more likely)
        operation_types = [
            (self.perform_search_operations, 60),    # 60% searches
            (self.perform_modify_operations, 25),    # 25% modifications
            (self.perform_bind_operations, 15),      # 15% bind attempts
        ]

        # Create weighted list
        weighted_operations = []
        for operation, weight in operation_types:
            weighted_operations.extend([operation] * weight)

        # Perform operations in this cycle
        for _ in range(BATCH_SIZE):
            if not self.running:
                break

            operation = choice(weighted_operations)
            try:
                if operation():
                    self.operation_count += 1
                    operations_this_cycle += 1
            except Exception as e:
                log.debug(f"Operation failed: {e}")

            self.random_delay()

        # Periodically sync replication
        if operations_this_cycle > 0 and self.operation_count % (BATCH_SIZE * 5) == 0:
            log.info(f"Completed {self.operation_count} operations, syncing replication...")
            wait_for_replication_sync(self.suppliers)

        return operations_this_cycle


def test_access_log_simulation_long_running(topology_m4):
    """Generate realistic access logs with a 4-master topology

    This test creates a realistic LDAP environment with:
    - 4-master replication topology
    - Hundreds of users and groups
    - MemberOf plugin enabled
    - Mixed read/write operations with realistic delays
    - Continuous operation to generate clean access logs

    The test is designed to run for an extended period to generate
    substantial access log data for analysis and monitoring.

    :id: a1b2c3d4-e5f6-7890-1234-567890abcdef
    :setup: Four suppliers replication setup
    :steps:
        1. Enable MemberOf plugin on all suppliers
        2. Create organizational structure
        3. Create user accounts across OUs
        4. Create groups with random members
        5. Wait for initial replication sync
        6. Clear all access logs to start fresh
        7. Start continuous simulation of mixed operations
        8. Run simulation for specified duration
        9. Generate final statistics
    :expectedresults:
        1. MemberOf plugin enabled successfully
        2. Organizational structure created
        3. User accounts created successfully
        4. Groups created with members
        5. Replication synced
        6. Access logs cleared
        7. Simulation runs continuously
        8. Operations perform without major errors
        9. Access logs contain realistic data patterns
    """

    suppliers = [topology_m4.ms[f"supplier{i}"] for i in range(1, 5)]

    try:
        log.info("=== Starting Access Log Simulation Test ===")
        log.info(f"Configuration: {NUM_USERS} users, {NUM_GROUPS} groups, {NUM_OU} OUs")
        log.info(f"Simulation duration: {SIMULATION_DURATION} seconds")

        # Step 1: Setup MemberOf plugin
        setup_memberof_plugin(suppliers)

        # Step 2: Create organizational structure
        ous = create_organizational_structure(suppliers)

        # Step 3: Create user accounts
        users = create_user_accounts(suppliers, ous)

        # Step 4: Create groups with members
        groups = create_groups_with_members(suppliers, users, ous)

        # Step 5: Wait for initial replication sync
        log.info("Waiting for initial replication sync...")
        wait_for_replication_sync(suppliers)

        # Step 6: Clear access logs to start fresh
        log.info("Clearing access logs to start fresh simulation...")
        for supplier in suppliers:
            supplier.deleteAccessLogs(restart=True)

        # Allow time for servers to restart and settle
        time.sleep(10)

        # Step 7 & 8: Start simulation
        log.info("=== Starting Continuous Access Log Simulation ===")
        log.info("The simulation will run continuously generating realistic access patterns.")
        log.info("You can stop the test manually when you have collected enough data.")
        log.info("Monitor the access logs in real-time to observe the generated patterns.")

        simulator = AccessLogSimulator(suppliers, users, groups, ous)

        start_time = time.time()
        last_report_time = start_time

        # Main simulation loop
        while simulator.running and (time.time() - start_time) < SIMULATION_DURATION:
            cycle_operations = simulator.run_simulation_cycle()

            # Progress reporting every 60 seconds
            current_time = time.time()
            if current_time - last_report_time >= 60:
                elapsed_time = current_time - start_time
                ops_per_second = simulator.operation_count / elapsed_time

                log.info(f"=== Simulation Progress Report ===")
                log.info(f"Elapsed time: {elapsed_time:.1f} seconds")
                log.info(f"Total operations: {simulator.operation_count}")
                log.info(f"Average ops/second: {ops_per_second:.2f}")
                log.info(f"Recent cycle operations: {cycle_operations}")
                log.info(f"Time remaining: {SIMULATION_DURATION - elapsed_time:.1f} seconds")

                # Log current access log sizes for monitoring
                for i, supplier in enumerate(suppliers, 1):
                    try:
                        log_size = os.path.getsize(supplier.accesslog) if os.path.exists(supplier.accesslog) else 0
                        log.info(f"Supplier{i} access log size: {log_size:,} bytes")
                    except Exception as e:
                        log.debug(f"Could not get log size for supplier{i}: {e}")

                last_report_time = current_time

        # Step 9: Final statistics and cleanup
        final_time = time.time()
        total_elapsed = final_time - start_time
        final_ops_per_second = simulator.operation_count / total_elapsed

        log.info("=== Final Simulation Statistics ===")
        log.info(f"Total simulation time: {total_elapsed:.1f} seconds")
        log.info(f"Total operations performed: {simulator.operation_count}")
        log.info(f"Average operations per second: {final_ops_per_second:.2f}")
        log.info(f"Created data: {len(users)} users, {len(groups)} groups, {len(ous)} OUs")

        # Final log sizes
        log.info("=== Access Log Information ===")
        for i, supplier in enumerate(suppliers, 1):
            try:
                if os.path.exists(supplier.accesslog):
                    log_size = os.path.getsize(supplier.accesslog)
                    log.info(f"Supplier{i} access log: {supplier.accesslog}")
                    log.info(f"Supplier{i} access log size: {log_size:,} bytes ({log_size/1024/1024:.2f} MB)")
                else:
                    log.info(f"Supplier{i} access log not found: {supplier.accesslog}")
            except Exception as e:
                log.warning(f"Could not get final log size for supplier{i}: {e}")

        log.info("=== Access Log Simulation Complete ===")
        log.info("You can now analyze the generated access logs for patterns and monitoring.")

        # Verify we actually generated some operations
        assert simulator.operation_count > 0, "No operations were performed during simulation"
        assert len(users) > 0, "No users were created"
        assert len(groups) > 0, "No groups were created"

        log.info("Test completed successfully!")

    except Exception as e:
        log.error(f"Simulation failed with error: {e}")
        raise


if __name__ == '__main__':
    # Run isolated
    # Use -s for DEBUG mode and -v for verbose output
    CURRENT_FILE = os.path.realpath(__file__)
    pytest.main("-s -v %s" % CURRENT_FILE)