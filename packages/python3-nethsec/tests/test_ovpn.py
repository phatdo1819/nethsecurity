import pytest
import ipaddress
from nethsec import ovpn
from euci import EUci

openvpn_db = """
config openvpn 'custom_config'
    option port '1194'

config openvpn 'custom_config2'
    option port '1300'
    option server '10.10.10.0 255.255.255.0'

config openvpn 'custom_config3'
    option port '1301'
    option server_bridge '10.8.0.4 255.255.255.0 10.8.0.128 10.8.0.254'

config openvpn 'custom_config4'
    option lport '1302'

config openvpn 'custom_config5'
    option lport '1303'
    option ifconfig '10.7.0.1 10.7.0.2'
"""

def _setup_db(tmp_path):
     # setup fake db
    with tmp_path.joinpath('openvpn').open('w') as fp:
        fp.write(openvpn_db)
    return EUci(confdir=tmp_path.as_posix())

def test_to_cidr():
    assert ovpn.to_cidr("255.255.255.0") == 24
    
def test_to_netmask():
    assert ovpn.to_netmask(24) == "255.255.255.0"

def test_is_used_network(tmp_path):
    u = _setup_db(tmp_path)
    assert ovpn.is_used_network(u, "10.10.10.0/24") == True
    assert ovpn.is_used_network(u, "10.8.0.0/24") == True
    assert ovpn.is_used_network(u, "10.7.0.0/24") == True
    assert ovpn.is_used_network(u, "192.168.1.0/24") == False

def test_generate_random_network(tmp_path):
    u = _setup_db(tmp_path)
    assert ipaddress.ip_network(ovpn.generate_random_network(u)).is_private

def test_opt2cidr():
    assert ovpn.opt2cidr("192.168.1.0 255.255.255.0") == "192.168.1.0/24"

def test_is_used_port(tmp_path):
    u = _setup_db(tmp_path)
    assert ovpn.is_used_port(u, 1194) == True
    assert ovpn.is_used_port(u, 1300) == True
    assert ovpn.is_used_port(u, 1301) == True
    assert ovpn.is_used_port(u, 1302) == True
    assert ovpn.is_used_port(u, 1303) == True
    assert ovpn.is_used_port(u, 1200) == False

def test_generate_random_port(tmp_path):
    u = _setup_db(tmp_path)
    assert type(ovpn.generate_random_port(u, 1200, 1210)) == type(1)

def test_is_used_port_exclude(tmp_path):
    u = _setup_db(tmp_path)
    assert ovpn.is_used_port(u, 1194) == True
    assert ovpn.is_used_port(u, 1194, exclude='custom_config') == False
    assert ovpn.is_used_port(u, 1300, exclude='custom_config') == True

def test_find_overlapping_network(tmp_path):
    u = _setup_db(tmp_path)
    assert ovpn.find_overlapping_network(u, "10.10.10.0/24") == 'custom_config2'
    # a bigger network containing the server one overlaps too
    assert ovpn.find_overlapping_network(u, "10.10.0.0/16") == 'custom_config2'
    assert ovpn.find_overlapping_network(u, "10.10.10.0/24", exclude='custom_config2') is None
    assert ovpn.find_overlapping_network(u, "192.168.1.0/24") is None

rw_db = """
config openvpn 'ns_roadwarrior1'
    option server '10.20.0.0 255.255.255.0 nopool'
    option ns_user_db 'main'
    list ns_tag 'automated'

config openvpn 'ns_roadwarrior3'
    option server '10.30.0.0 255.255.255.0 nopool'
    option ns_user_db 'main'
    list ns_tag 'automated'

config openvpn 'ns_roadwarrior4'
    option server '10.40.0.0 255.255.255.0 nopool'
    option ns_user_db 'other'
    list ns_tag 'automated'

config openvpn 'tunnel1'
    option server '10.50.0.0 255.255.255.0'
"""

users_db = """
config database 'main'
    option type 'local'

config user 'ns_legacy'
    option name 'legacy'
    option database 'main'
    option openvpn_enabled '1'
    option openvpn_ipaddr '10.20.0.10'
    option openvpn_2fa 'SECRET'

config user 'ns_legacy_off'
    option name 'legacyoff'
    option database 'main'
    option openvpn_enabled '0'

config user 'ns_noovpn'
    option name 'noovpn'
    option database 'main'

config user 'ns_new'
    option name 'newuser'
    option database 'main'
    option openvpn_enabled '1'
    list openvpn_instances 'ns_roadwarrior1'
    list openvpn_instances 'ns_roadwarrior3'
    list openvpn_disabled 'ns_roadwarrior3'
"""

def _setup_rw(tmp_path):
    tmp_path.joinpath('openvpn').write_text(rw_db)
    tmp_path.joinpath('users').write_text(users_db)
    return EUci(confdir=tmp_path.as_posix())

def _user(u, user_id):
    ret = {opt: u.get_all('users', user_id, opt) for opt in u.get_all('users', user_id)}
    ret = {k: list(v) if isinstance(v, tuple) else v for k, v in ret.items()}
    ret['id'] = user_id
    return ret

def test_list_roadwarrior_instances(tmp_path):
    u = _setup_rw(tmp_path)
    assert sorted(ovpn.list_roadwarrior_instances(u)) == ['ns_roadwarrior1', 'ns_roadwarrior3', 'ns_roadwarrior4']

def test_next_instance_number(tmp_path):
    u = _setup_rw(tmp_path)
    # roadwarrior2 has been removed in the past: its number is reused, there are no collisions
    assert ovpn.next_instance_number(u) == 2
    u.set('openvpn', 'ns_roadwarrior2', 'openvpn')
    assert ovpn.next_instance_number(u) == 5

def test_is_user_enabled(tmp_path):
    u = _setup_rw(tmp_path)
    # legacy users follow openvpn_enabled
    assert ovpn.is_user_enabled(_user(u, 'ns_legacy'), 'ns_roadwarrior1') == True
    assert ovpn.is_user_enabled(_user(u, 'ns_legacy_off'), 'ns_roadwarrior1') == False
    assert ovpn.is_user_enabled(_user(u, 'ns_noovpn'), 'ns_roadwarrior1') == False
    # explicit membership
    new = _user(u, 'ns_new')
    assert ovpn.is_user_enabled(new, 'ns_roadwarrior1') == True
    assert ovpn.is_user_enabled(new, 'ns_roadwarrior3') == False
    assert ovpn.is_user_enabled(new, 'ns_roadwarrior4') == False
    assert ovpn.is_user_member(new, 'ns_roadwarrior3') == True
    assert ovpn.is_user_member(new, 'ns_roadwarrior4') == False
    assert ovpn.is_user_member(_user(u, 'ns_noovpn'), 'ns_roadwarrior1') == False

def test_add_user_instance(tmp_path):
    u = _setup_rw(tmp_path)
    # a legacy user is converted to explicit membership: it keeps the instances using its database
    ovpn.add_user_instance(u, _user(u, 'ns_legacy'), 'ns_roadwarrior4')
    user = _user(u, 'ns_legacy')
    assert user['openvpn_instances'] == ['ns_roadwarrior1', 'ns_roadwarrior3', 'ns_roadwarrior4']
    assert user['openvpn_enabled'] == '1'
    assert user['openvpn_ipaddr'] == '10.20.0.10'
    assert 'openvpn_disabled' not in user
    # a user without OpenVPN access starts with the new instance only
    ovpn.add_user_instance(u, _user(u, 'ns_noovpn'), 'ns_roadwarrior1', enabled=False)
    user = _user(u, 'ns_noovpn')
    assert user['openvpn_instances'] == ['ns_roadwarrior1']
    assert user['openvpn_disabled'] == ['ns_roadwarrior1']
    assert user['openvpn_enabled'] == '0'

def test_set_user_instance_enabled(tmp_path):
    u = _setup_rw(tmp_path)
    ovpn.set_user_instance_enabled(u, _user(u, 'ns_new'), 'ns_roadwarrior1', False)
    user = _user(u, 'ns_new')
    assert sorted(user['openvpn_disabled']) == ['ns_roadwarrior1', 'ns_roadwarrior3']
    assert user['openvpn_enabled'] == '0'
    ovpn.set_user_instance_enabled(u, user, 'ns_roadwarrior3', True)
    user = _user(u, 'ns_new')
    assert user['openvpn_disabled'] == ['ns_roadwarrior1']
    assert user['openvpn_enabled'] == '1'

def test_remove_user_instance(tmp_path):
    u = _setup_rw(tmp_path)
    assert ovpn.remove_user_instance(u, _user(u, 'ns_new'), 'ns_roadwarrior1') == False
    user = _user(u, 'ns_new')
    assert user['openvpn_instances'] == ['ns_roadwarrior3']
    # the remaining instance is disabled
    assert user['openvpn_enabled'] == '0'
    assert ovpn.remove_user_instance(u, user, 'ns_roadwarrior3') == True
    user = _user(u, 'ns_new')
    for opt in ['openvpn_instances', 'openvpn_disabled', 'openvpn_enabled', 'openvpn_ipaddr', 'openvpn_2fa']:
        assert opt not in user

def test_remove_legacy_user_instance(tmp_path):
    u = _setup_rw(tmp_path)
    # removing a legacy user from one instance must not affect the other ones using the same database
    assert ovpn.remove_user_instance(u, _user(u, 'ns_legacy'), 'ns_roadwarrior1') == False
    user = _user(u, 'ns_legacy')
    assert user['openvpn_instances'] == ['ns_roadwarrior3']
    assert user['openvpn_enabled'] == '1'
    assert user['openvpn_2fa'] == 'SECRET'

def test_find_conflicting_port(tmp_path):
    u = _setup_rw(tmp_path)
    u.set('openvpn', 'ns_roadwarrior1', 'port', '1194')
    u.set('openvpn', 'ns_roadwarrior1', 'proto', 'udp')
    u.set('openvpn', 'ns_roadwarrior3', 'port', '1300')
    u.set('openvpn', 'ns_roadwarrior3', 'proto', 'tcp')
    u.set('openvpn', 'ns_roadwarrior4', 'port', '1500')
    u.set('openvpn', 'tunnel1', 'port', '1600')
    assert ovpn.find_conflicting_port(u, 1194, 'udp') == 'ns_roadwarrior1'
    assert ovpn.find_conflicting_port(u, 1194, 'udp', exclude='ns_roadwarrior1') is None
    # same port, different protocol
    assert ovpn.find_conflicting_port(u, 1194, 'tcp') is None
    assert ovpn.find_conflicting_port(u, '1300', 'tcp-server') == 'ns_roadwarrior3'
    # tunnel clients (no server option) are ignored
    u.set('openvpn', 'client1', 'openvpn')
    u.set('openvpn', 'client1', 'port', '1400')
    assert ovpn.find_conflicting_port(u, 1400, 'udp') is None

def test_remove_not_member_user_instance(tmp_path):
    u = _setup_rw(tmp_path)
    # the user belongs to other instances: nothing changes
    assert ovpn.remove_user_instance(u, _user(u, 'ns_new'), 'ns_roadwarrior4') == False
    assert _user(u, 'ns_new')['openvpn_instances'] == ['ns_roadwarrior1', 'ns_roadwarrior3']
    # dangling legacy user: it has no instances, so its options are cleaned up
    u.set('users', 'ns_dangling', 'user')
    u.set('users', 'ns_dangling', 'name', 'dangling')
    u.set('users', 'ns_dangling', 'database', 'nodb')
    u.set('users', 'ns_dangling', 'openvpn_enabled', '1')
    assert ovpn.remove_user_instance(u, _user(u, 'ns_dangling'), 'ns_roadwarrior1') == True
    assert 'openvpn_enabled' not in _user(u, 'ns_dangling')

def test_get_instance_network(tmp_path):
    u = _setup_rw(tmp_path)
    assert str(ovpn.get_instance_network(u, 'ns_roadwarrior1')) == '10.20.0.0/24'
    u.set('openvpn', 'ns_roadwarrior5', 'openvpn')
    assert ovpn.get_instance_network(u, 'ns_roadwarrior5') is None
    u.set('openvpn', 'ns_roadwarrior5', 'server_bridge', '10.8.0.1 255.255.255.0 10.8.0.10 10.8.0.20')
    assert str(ovpn.get_instance_network(u, 'ns_roadwarrior5')) == '10.8.0.0/24'

def test_get_reserved_ip(tmp_path):
    u = _setup_rw(tmp_path)
    user = _user(u, 'ns_legacy')
    assert ovpn.get_reserved_ip(u, user, 'ns_roadwarrior1') == '10.20.0.10'
    # the address does not belong to the network of the other instance
    assert ovpn.get_reserved_ip(u, user, 'ns_roadwarrior3') == ''
    assert ovpn.get_reserved_ip(u, _user(u, 'ns_new'), 'ns_roadwarrior1') == ''
    user['openvpn_ipaddr'] = 'invalid'
    assert ovpn.get_reserved_ip(u, user, 'ns_roadwarrior1') == ''

def test_migrate_user_memberships(tmp_path):
    u = _setup_rw(tmp_path)
    assert ovpn.migrate_user_memberships(u) == 2
    user = _user(u, 'ns_legacy')
    assert user['openvpn_instances'] == ['ns_roadwarrior1', 'ns_roadwarrior3']
    assert 'openvpn_disabled' not in user
    user = _user(u, 'ns_legacy_off')
    assert user['openvpn_instances'] == ['ns_roadwarrior1', 'ns_roadwarrior3']
    assert user['openvpn_disabled'] == ['ns_roadwarrior1', 'ns_roadwarrior3']
    assert user['openvpn_enabled'] == '0'
    assert 'openvpn_instances' not in _user(u, 'ns_noovpn')
    # idempotent
    assert ovpn.migrate_user_memberships(u) == 0

def test_revoke_user_certificate(mocker):
    exists = mocker.patch('nethsec.ovpn.os.path.exists', return_value=True)
    run = mocker.patch('nethsec.ovpn.subprocess.run')
    assert ovpn.revoke_user_certificate('ns_roadwarrior1', 'alice') == True
    exists.assert_called_once_with('/etc/openvpn/ns_roadwarrior1/pki/issued/alice.crt')
    commands = [call.args[0] for call in run.call_args_list]
    assert commands == [['/usr/bin/easyrsa', 'revoke', 'alice'], ['/usr/bin/easyrsa', 'gen-crl']]
    assert run.call_args_list[0].kwargs['env']['EASYRSA_PKI'] == '/etc/openvpn/ns_roadwarrior1/pki'

def test_revoke_user_certificate_without_certificate(mocker):
    mocker.patch('nethsec.ovpn.os.path.exists', return_value=False)
    run = mocker.patch('nethsec.ovpn.subprocess.run')
    assert ovpn.revoke_user_certificate('ns_roadwarrior1', 'alice') == False
    run.assert_not_called()

@pytest.mark.parametrize('username', ['', '../server', 'a/b', '.hidden'])
def test_revoke_user_certificate_invalid_name(mocker, username):
    run = mocker.patch('nethsec.ovpn.subprocess.run')
    with pytest.raises(ValueError):
        ovpn.revoke_user_certificate('ns_roadwarrior1', username)
    run.assert_not_called()

def test_remove_user_access(tmp_path, mocker):
    u = _setup_rw(tmp_path)
    disconnect = mocker.patch('nethsec.ovpn.disconnect_client')
    revoke = mocker.patch('nethsec.ovpn.revoke_user_certificate')
    # the user is disconnected and revoked on all its instances, including the disabled ones
    assert ovpn.remove_user_access(u, _user(u, 'ns_new')) == []
    assert [c.args for c in disconnect.call_args_list] == [('ns_roadwarrior1', 'newuser'), ('ns_roadwarrior3', 'newuser')]
    assert [c.args for c in revoke.call_args_list] == [('ns_roadwarrior1', 'newuser'), ('ns_roadwarrior3', 'newuser')]
    # legacy users belong to all the instances using their database
    revoke.reset_mock()
    ovpn.remove_user_access(u, _user(u, 'ns_legacy'))
    assert [c.args[0] for c in revoke.call_args_list] == ['ns_roadwarrior1', 'ns_roadwarrior3']
    # users without OpenVPN access are not touched
    revoke.reset_mock()
    disconnect.reset_mock()
    ovpn.remove_user_access(u, _user(u, 'ns_noovpn'))
    revoke.assert_not_called()
    disconnect.assert_not_called()

def test_remove_user_access_errors(tmp_path, mocker):
    u = _setup_rw(tmp_path)
    mocker.patch('nethsec.ovpn.disconnect_client')
    mocker.patch('nethsec.ovpn.revoke_user_certificate', side_effect=[Exception('easyrsa failed'), True])
    # a failure on one instance does not stop the others
    assert ovpn.remove_user_access(u, _user(u, 'ns_new')) == ['ns_roadwarrior1']