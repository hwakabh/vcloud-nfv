import requests
import json
import ssl
import atexit
import urllib3
from urllib3.exceptions import InsecureRequestWarning
urllib3.disable_warnings(InsecureRequestWarning)

from pyVim.connect import SmartConnect, Disconnect
from pyVmomi import vim


class VCenter():
    def __init__(self, ipaddress, username, password):
        self.ipaddress = ipaddress
        self.username = username
        self.password = password
        self.headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
        }
        self.baseuri = 'https://{}'.format(self.ipaddress)
        self.set_token()

    def set_token(self):
        # POST to fetch token
        token = self.post(
            urlsuffix='/rest/com/vmware/cis/session',
            headers=self.headers,
            reqbody=''
        )
        # Update headers
        self.headers['vmware-api-session-id'] = token.get('value')
    
    def get(self, urlsuffix):
        uri = '{0}{1}'.format(self.baseuri, urlsuffix)
        res = requests.get(uri, headers=self.headers, verify=False)
        return json.loads(res.text)

    def post(self, urlsuffix, headers=None, reqbody=None):
        uri = '{0}{1}'.format(self.baseuri, urlsuffix)
        res = requests.post(uri, auth=(self.username, self.password), headers=self.headers, data=reqbody, verify=False)
        return json.loads(res.text)


class VApi():
    def __init__(self, ipaddress, username, password):
        self.ipaddress = ipaddress
        self.username = username
        self.password = password
        self.context = None
    
    def _establish_session(self):
        if hasattr(ssl, '_create_unverified_context'):
            self.context = ssl._create_unverified_context()
        vc_session = SmartConnect(host=self.ipaddress, user=self.username, pwd=self.password, sslContext=self.context)
        atexit.register(Disconnect, vc_session)
        return vc_session.content

    def get_host_objects(self):
        ret = self._establish_session()
        host_view = ret.viewManager.CreateContainerView(ret.rootFolder,[vim.HostSystem], True)
        hostlist = [host for host in host_view.view]
        host_view.Destroy()
        return hostlist

    def get_dvs_objects(self):
        ret = self._establish_session()
        dvs_view = ret.viewManager.CreateContainerView(ret.rootFolder,[vim.DistributedVirtualSwitch], True)
        dvslist = [dvs for dvs in dvs_view.view]
        dvs_view.Destroy()
        return dvslist


class EsxiSoapParser():
    def __init__(self):
        pass

    # Member methods for specific purpose
    def get_host_pnics(self, host):
        host_pnics = []
        for pnic in host.config.network.pnic:
            pnic_info = dict()
            pnic_info.update(
                {'device': pnic.device, 'driver': pnic.driver, 'mac': pnic.mac})
            host_pnics.append(pnic_info)
        return host_pnics

    def get_host_vnics(self, host):
        host_vnics = []
        for vnic in host.config.network.vnic:
            vnic_info = dict()
            vnic_info.update(
                {'device': vnic.device, 'portgroup': vnic.portgroup,
                'dhcp': vnic.spec.ip.dhcp, 'ipAddress': vnic.spec.ip.ipAddress,
                'subnetMask': vnic.spec.ip.subnetMask,
                'mac': vnic.spec.mac, 'mtu': vnic.spec.mtu})
            host_vnics.append(vnic_info)
        return host_vnics

    def get_host_vswitches(self, host):
        host_vswitches = []
        for vswitch in host.config.network.vswitch:
            vswitch_info = dict()
            vswitch_pnics = []
            vswitch_portgroups = []
            for pnic in vswitch.pnic:
                pnic = pnic.replace('key-vim.host.PhysicalNic-', '')
                vswitch_pnics.append(pnic)
            for pg in vswitch.portgroup:
                pg = pg.replace('key-vim.host.PortGroup-', '')
                vswitch_portgroups.append(pg)
            vswitch_info.update(
                {'name': vswitch.name, 'pnics': vswitch_pnics,
                'portgroups': vswitch_portgroups, 'mtu': vswitch.mtu})
            host_vswitches.append(vswitch_info)
        return host_vswitches

    def get_host_portgroups(self, host):
        host_portgroups = []
        for portgroup in host.config.network.portgroup:
            portgroup_info = dict()
            portgroup_info.update(
                {'name': portgroup.spec.name, 'vlanId': portgroup.spec.vlanId,
                'vswitchName': portgroup.spec.vswitchName,
                'nicTeamingPolicy': portgroup.spec.policy.nicTeaming.policy,
                'allowPromiscuous': portgroup.spec.policy.security.allowPromiscuous,
                'macChanges': portgroup.spec.policy.security.macChanges,
                'forgedTransmits': portgroup.spec.policy.security.forgedTransmits})
            host_portgroups.append(portgroup_info)
        return host_portgroups

    def get_host_ssh_status(self, host):
        services = host.configManager.serviceSystem
        ssh_service = [s for s in services.serviceInfo.service if s.key == 'TSM-SSH'][0].running
        return 'Running' if ssh_service == True else 'Error'

