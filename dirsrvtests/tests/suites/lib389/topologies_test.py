# --- BEGIN COPYRIGHT BLOCK ---
# Copyright (C) 2026 Red Hat, Inc.
# All rights reserved.
#
# License: GPL (version 3 or any later version).
# See LICENSE for details.
# --- END COPYRIGHT BLOCK ---
#
import logging
from unittest.mock import MagicMock

import pytest

from lib389._constants import DEFAULT_SUFFIX, ReplicaRole
import test389.topologies as topologies


pytestmark = pytest.mark.tier0


@pytest.mark.parametrize('debugging', [False, '1'], ids=['cleanup', 'preserve'])
def test_create_instances_cleans_up_partial_allocation(monkeypatch, caplog, debugging):
    """A topology creation failure cleans every instance and preserves its exception

    :id: b0c6491b-065e-4d9a-bbe8-71b5859e4554
    :setup: Two mocked standalone instances
    :steps:
        1. Allow the first instance to be created
        2. Log the pre-creation state and fail while creating the second allocated instance
        3. Also fail diagnostics, stop, unbind, and delete cleanup operations
        4. Inspect the propagated exception and cleanup calls
    :expectedresults:
        1. The first instance reaches the created state
        2. Both pre-creation states are logged and topology creation fails with its original exception
        3. Cleanup continues for every instance
        4. The original exception is unchanged, all instances are stopped, and deletion honors debugging mode
    """
    instances = [MagicMock(name='standalone1'), MagicMock(name='standalone2')]
    for inst_num, instance in enumerate(instances, start=1):
        instance.serverid = f'standalone{inst_num}'
        instance.exists.return_value = False

    create_error = RuntimeError('standalone2 creation failed')
    instances[1].create.side_effect = create_error
    cleanup_order = []

    def fail_diagnostics():
        cleanup_order.append('diagnostics')
        raise RuntimeError('standalone2 diagnostics failed')

    def fail_stop():
        cleanup_order.append('stop')
        raise RuntimeError('standalone2 stop failed')

    def fail_unbind(**kwargs):
        cleanup_order.append('unbind')
        raise RuntimeError('standalone2 unbind failed')

    def fail_delete():
        cleanup_order.append('delete')
        raise RuntimeError('standalone2 delete failed')

    instances[1]._log_start_failure_diagnostics.side_effect = fail_diagnostics
    instances[1].stop.side_effect = fail_stop
    instances[1].unbind_s.side_effect = fail_unbind
    if not debugging:
        instances[1].delete.side_effect = fail_delete

    monkeypatch.setattr(topologies, 'DirSrv', MagicMock(side_effect=instances))
    monkeypatch.setattr(topologies, 'get_default_db_lib', lambda: 'bdb')
    monkeypatch.setattr(topologies, 'is_fips', lambda: False)
    monkeypatch.setattr(topologies, 'DEBUGGING', debugging)
    monkeypatch.setattr(topologies, 'TLS_HOSTNAME_CHECK', True)
    monkeypatch.setattr(topologies, 'HAPROXY_TRUSTED_IP', '')
    caplog.set_level(logging.INFO, logger=topologies.log.name)

    with pytest.raises(RuntimeError) as exc_info:
        topologies._create_instances({ReplicaRole.STANDALONE: 2}, DEFAULT_SUFFIX)

    assert exc_info.value is create_error
    assert 'Instance standalone1 exists before creation: False' in caplog.text
    assert 'Instance standalone2 exists before creation: False' in caplog.text
    expected_order = ['diagnostics', 'stop', 'unbind']
    if not debugging:
        expected_order.append('delete')
    assert cleanup_order == expected_order
    instances[1]._log_start_failure_diagnostics.assert_called_once_with()
    instances[0].create.assert_called_once_with()
    for instance in instances:
        instance.stop.assert_called_once_with()
        instance.unbind_s.assert_called_once_with(escapehatch='i am sure')
        if debugging:
            instance.delete.assert_not_called()
        else:
            instance.delete.assert_called_once_with()


def test_create_instances_does_not_clean_unowned_instance(monkeypatch):
    """An existence-check failure does not delete an instance this attempt did not create

    :id: 49b1c7d0-4a80-41bd-bead-a7569f0d51a8
    :setup: Two mocked standalone instances in non-debug mode
    :steps:
        1. Create the first instance and make the second existence check fail
        2. Run topology creation and inspect the propagated exception
        3. Inspect cleanup calls for both instance objects
    :expectedresults:
        1. The second instance never enters its creation attempt
        2. The original existence-check exception is propagated
        3. The first instance is cleaned up and the unowned second instance is untouched
    """
    instances = [MagicMock(name='standalone1'), MagicMock(name='standalone2')]
    for inst_num, instance in enumerate(instances, start=1):
        instance.serverid = f'standalone{inst_num}'
        instance.exists.return_value = False

    exists_error = RuntimeError('standalone2 existence check failed')
    instances[1].exists.side_effect = exists_error

    monkeypatch.setattr(topologies, 'DirSrv', MagicMock(side_effect=instances))
    monkeypatch.setattr(topologies, 'get_default_db_lib', lambda: 'bdb')
    monkeypatch.setattr(topologies, 'is_fips', lambda: False)
    monkeypatch.setattr(topologies, 'DEBUGGING', False)
    monkeypatch.setattr(topologies, 'TLS_HOSTNAME_CHECK', True)
    monkeypatch.setattr(topologies, 'HAPROXY_TRUSTED_IP', '')

    with pytest.raises(RuntimeError) as exc_info:
        topologies._create_instances({ReplicaRole.STANDALONE: 2}, DEFAULT_SUFFIX)

    assert exc_info.value is exists_error
    instances[0].create.assert_called_once_with()
    instances[0].stop.assert_called_once_with()
    instances[0].unbind_s.assert_called_once_with(escapehatch='i am sure')
    instances[0].delete.assert_called_once_with()
    instances[1].create.assert_not_called()
    instances[1].stop.assert_not_called()
    instances[1].unbind_s.assert_not_called()
    instances[1].delete.assert_not_called()


@pytest.mark.parametrize('debugging', [False, '1'], ids=['cleanup', 'preserve'])
def test_topology_finalizer_honors_debugging(monkeypatch, debugging):
    """The normal topology finalizer stops instances and honors debugging mode

    :id: 97c6f646-71a5-4aa7-848a-ee0e099db2af
    :setup: A mocked standalone topology with a pytest request
    :steps:
        1. Create a topology with a cleanup callback
        2. Run the finalizer registered on the pytest request
        3. Inspect the callback and instance cleanup calls
    :expectedresults:
        1. The topology finalizer is registered
        2. One unbind failure does not interrupt remaining cleanup
        3. Non-debug mode calls the callback then deletes; debug mode stops and unbinds without deleting
    """
    instances = {
        'standalone1': MagicMock(name='standalone1'),
        'standalone2': MagicMock(name='standalone2'),
    }
    for serverid, instance in instances.items():
        instance.serverid = serverid
        instance.exists.return_value = True
    instances['standalone1'].unbind_s.side_effect = RuntimeError('standalone1 unbind failed')
    topology = topologies.TopologyMain(standalones=instances)

    finalizers = []
    request = MagicMock()
    request.addfinalizer.side_effect = finalizers.append
    cleanup_calls = []

    def cleanup_cb(cleanup_topology):
        for instance in instances.values():
            instance.delete.assert_not_called()
        cleanup_calls.append(cleanup_topology)

    remove_ssca_db = MagicMock(return_value=True)
    monkeypatch.setattr(topologies, '_create_instances', lambda topo_dict, suffix: topology)
    monkeypatch.setattr(topologies, '_remove_ssca_db', remove_ssca_db)
    monkeypatch.setattr(topologies, 'ReplicationManager', MagicMock())
    monkeypatch.setattr(topologies, 'DEBUGGING', debugging)
    monkeypatch.setattr(topologies, 'signal', MagicMock())
    monkeypatch.setattr(topologies, 'alarm', MagicMock())

    result = topologies.create_topology(
        {ReplicaRole.STANDALONE: 1}, request=request, cleanup_cb=cleanup_cb
    )

    assert result is topology
    assert len(finalizers) == 1
    finalizers[0]()

    for instance in instances.values():
        instance.stop.assert_called_once_with()
        instance.unbind_s.assert_called_once_with(escapehatch='i am sure')
        if debugging:
            instance.delete.assert_not_called()
        else:
            instance.delete.assert_called_once_with()
    if debugging:
        remove_ssca_db.assert_not_called()
        assert cleanup_calls == []
    else:
        remove_ssca_db.assert_called_once_with(topology)
        assert cleanup_calls == [topology]


@pytest.mark.parametrize('debugging', [False, '1'], ids=['cleanup', 'preserve'])
def test_topology_finalizer_propagates_first_stop_failure(monkeypatch, debugging):
    """The finalizer reports stop failures after attempting all cleanup

    :id: 2696fd4d-037f-417b-a1a4-55b1b1d0a7da
    :setup: Three mocked standalone instances with two stop failures
    :steps:
        1. Make the first two instance stops fail with distinct errors
        2. Create a topology and run its registered finalizer
        3. Inspect all cleanup calls and the propagated exception
    :expectedresults:
        1. Both selected stops raise their sentinel exceptions
        2. Finalization continues through every instance and honors debugging mode
        3. The first stop exception is propagated after cleanup finishes
    :parametrized: yes
    """
    instances = {
        'standalone1': MagicMock(name='standalone1'),
        'standalone2': MagicMock(name='standalone2'),
        'standalone3': MagicMock(name='standalone3'),
    }
    for serverid, instance in instances.items():
        instance.serverid = serverid
        instance.exists.return_value = True

    first_error = RuntimeError('standalone1 stop failed')
    second_error = RuntimeError('standalone2 stop failed')
    instances['standalone1'].stop.side_effect = first_error
    instances['standalone2'].stop.side_effect = second_error

    topology = topologies.TopologyMain(standalones=instances)
    finalizers = []
    request = MagicMock()
    request.addfinalizer.side_effect = finalizers.append
    remove_ssca_db = MagicMock(return_value=True)

    monkeypatch.setattr(topologies, '_create_instances', lambda topo_dict, suffix: topology)
    monkeypatch.setattr(topologies, '_remove_ssca_db', remove_ssca_db)
    monkeypatch.setattr(topologies, 'ReplicationManager', MagicMock())
    monkeypatch.setattr(topologies, 'DEBUGGING', debugging)
    monkeypatch.setattr(topologies, 'signal', MagicMock())
    monkeypatch.setattr(topologies, 'alarm', MagicMock())

    result = topologies.create_topology({ReplicaRole.STANDALONE: 1}, request=request)

    assert result is topology
    assert len(finalizers) == 1
    with pytest.raises(RuntimeError) as exc_info:
        finalizers[0]()

    assert exc_info.value is first_error
    for instance in instances.values():
        instance.stop.assert_called_once_with()
        instance.unbind_s.assert_called_once_with(escapehatch='i am sure')
        if debugging:
            instance.exists.assert_not_called()
            instance.delete.assert_not_called()
        else:
            instance.exists.assert_called_once_with()
            instance.delete.assert_called_once_with()
    if debugging:
        remove_ssca_db.assert_not_called()
    else:
        remove_ssca_db.assert_called_once_with(topology)


@pytest.mark.parametrize('failing_operation', ['exists', 'delete'])
def test_topology_finalizer_propagates_first_instance_cleanup_failure(monkeypatch,
                                                                      failing_operation):
    """The normal finalizer reports instance cleanup failures after all attempts

    :id: a8ec236b-2817-464c-bc68-161b3d77683e
    :setup: Three mocked standalone instances with two failing cleanup operations
    :steps:
        1. Make the first two existence checks or deletions fail with distinct errors
        2. Create a topology and run its registered finalizer
        3. Inspect every instance cleanup call and the propagated exception
    :expectedresults:
        1. The two selected operations raise their sentinel exceptions
        2. Finalization continues through every instance
        3. Every eligible deletion is attempted and the first sentinel is propagated
    :parametrized: yes
    """
    instances = {
        'standalone1': MagicMock(name='standalone1'),
        'standalone2': MagicMock(name='standalone2'),
        'standalone3': MagicMock(name='standalone3'),
    }
    for serverid, instance in instances.items():
        instance.serverid = serverid
        instance.exists.return_value = True

    first_error = RuntimeError(f'standalone1 {failing_operation} failed')
    second_error = RuntimeError(f'standalone2 {failing_operation} failed')
    failing_instances = list(instances.values())[:2]
    for instance, error in zip(failing_instances, (first_error, second_error)):
        getattr(instance, failing_operation).side_effect = error

    topology = topologies.TopologyMain(standalones=instances)
    finalizers = []
    request = MagicMock()
    request.addfinalizer.side_effect = finalizers.append

    monkeypatch.setattr(topologies, '_create_instances', lambda topo_dict, suffix: topology)
    monkeypatch.setattr(topologies, '_remove_ssca_db', MagicMock(return_value=True))
    monkeypatch.setattr(topologies, 'ReplicationManager', MagicMock())
    monkeypatch.setattr(topologies, 'DEBUGGING', False)
    monkeypatch.setattr(topologies, 'signal', MagicMock())
    monkeypatch.setattr(topologies, 'alarm', MagicMock())

    result = topologies.create_topology({ReplicaRole.STANDALONE: 1}, request=request)

    assert result is topology
    assert len(finalizers) == 1
    with pytest.raises(RuntimeError) as exc_info:
        finalizers[0]()

    assert exc_info.value is first_error
    for instance in instances.values():
        instance.stop.assert_called_once_with()
        instance.unbind_s.assert_called_once_with(escapehatch='i am sure')
        instance.exists.assert_called_once_with()
    if failing_operation == 'exists':
        for instance in failing_instances:
            instance.delete.assert_not_called()
        instances['standalone3'].delete.assert_called_once_with()
    else:
        for instance in instances.values():
            instance.delete.assert_called_once_with()


@pytest.mark.parametrize('failing_cleanup', ['callback', 'ssca'])
def test_topology_finalizer_deletes_after_auxiliary_cleanup_failure(monkeypatch,
                                                                    failing_cleanup):
    """Auxiliary finalizer failures do not prevent instance deletion

    :id: e8728d8e-ee3c-436a-bdfb-3c8ced5378aa
    :setup: A mocked standalone topology with auxiliary and deletion failures
    :steps:
        1. Make either the cleanup callback or CA database removal fail
        2. Also make the first instance deletion fail
        3. Create the topology and run its registered finalizer
        4. Inspect the other auxiliary cleanup, instance cleanup, and propagated exception
    :expectedresults:
        1. The selected auxiliary operation raises its sentinel exception
        2. The first deletion raises a separate sentinel exception
        3. Finalization continues through both auxiliary operations and every instance
        4. The earlier auxiliary exception is propagated instead of the deletion exception
    :parametrized: yes
    """
    instances = {
        'standalone1': MagicMock(name='standalone1'),
        'standalone2': MagicMock(name='standalone2'),
    }
    for serverid, instance in instances.items():
        instance.serverid = serverid
        instance.exists.return_value = True
    topology = topologies.TopologyMain(standalones=instances)

    finalizers = []
    request = MagicMock()
    request.addfinalizer.side_effect = finalizers.append
    cleanup_error = RuntimeError(f'{failing_cleanup} cleanup failed')
    delete_error = RuntimeError('standalone1 delete failed')
    instances['standalone1'].delete.side_effect = delete_error
    cleanup_cb = MagicMock()
    remove_ssca_db = MagicMock(return_value=True)
    if failing_cleanup == 'callback':
        cleanup_cb.side_effect = cleanup_error
    else:
        remove_ssca_db.side_effect = cleanup_error

    monkeypatch.setattr(topologies, '_create_instances', lambda topo_dict, suffix: topology)
    monkeypatch.setattr(topologies, '_remove_ssca_db', remove_ssca_db)
    monkeypatch.setattr(topologies, 'ReplicationManager', MagicMock())
    monkeypatch.setattr(topologies, 'DEBUGGING', False)
    monkeypatch.setattr(topologies, 'signal', MagicMock())
    monkeypatch.setattr(topologies, 'alarm', MagicMock())

    result = topologies.create_topology(
        {ReplicaRole.STANDALONE: 1}, request=request, cleanup_cb=cleanup_cb
    )

    assert result is topology
    assert len(finalizers) == 1
    with pytest.raises(RuntimeError) as exc_info:
        finalizers[0]()

    assert exc_info.value is cleanup_error
    cleanup_cb.assert_called_once_with(topology)
    remove_ssca_db.assert_called_once_with(topology)
    for instance in instances.values():
        instance.stop.assert_called_once_with()
        instance.unbind_s.assert_called_once_with(escapehatch='i am sure')
        instance.delete.assert_called_once_with()
