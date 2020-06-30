import json
import ssl
import atexit
import logging
logger = logging.getLogger(__name__)

import requests
import urllib3
from urllib3.exceptions import InsecureRequestWarning
urllib3.disable_warnings(InsecureRequestWarning)


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
        token = self.post(
            urlsuffix='/rest/com/vmware/cis/session',
            headers=self.headers,
            reqbody=''
        )
        logger.debug(token)
        self.headers['vmware-api-session-id'] = token.get('value')

    def get(self, urlsuffix):
        uri = '{0}{1}'.format(self.baseuri, urlsuffix)
        res = requests.get(uri, headers=self.headers, verify=False)
        logger.debug(json.loads(res.text))
        return json.loads(res.text)

    def post(self, urlsuffix, headers=None, reqbody=None):
        uri = '{0}{1}'.format(self.baseuri, urlsuffix)
        res = requests.post(
            uri,
            auth=(self.username, self.password),
            headers=self.headers,
            data=reqbody,
            verify=False
        )
        logger.debug(json.loads(res.text))
        return json.loads(res.text)

    def get_version(self):
        ret = self.get(urlsuffix='/rest/appliance/system/version')
        return {
            'version': ret['value']['version'],
            'build': ret['value']['build']
        }

    def _get_vcsa_hostname(self):
        ret = self.get(urlsuffix='/rest/appliance/networking/dns/hostname')
        return ret['value']

    def _get_vcsa_dns_servers(self):
        ret = self.get(urlsuffix='/rest/appliance/networking/dns/servers')
        return ret['value']['servers']

    def _get_ntp_servers(self):
        ret = self.get(urlsuffix='/rest/appliance/ntp')
        return ret['value']

    def _get_ssh_services(self):
        ret = self.get(urlsuffix='/rest/appliance/access/ssh')
        return ret['value']

    def _get_vcsa_network_configs(self):
        vcsa_network_configs = []
        ret = self.get(urlsuffix='/rest/appliance/networking/interfaces')
        for vcsa_network in ret['value']:
            vcsa_network_configs.append({
                'name': vcsa_network['name'],
                'mac_address': vcsa_network['mac'],
                'ipaddress': vcsa_network['ipv4']['address'],
                'netmask': vcsa_network['ipv4']['prefix'],
                'gateway': vcsa_network['ipv4']['default_gateway'],
            })
        return vcsa_network_configs

    def get_appliance_configs(self):
        return {
            'hostname': self._get_vcsa_hostname(),
            'networks': self._get_vcsa_network_configs(),
            'dns_servers': self._get_vcsa_dns_servers(),
            'ntp_servers': self._get_ntp_servers(),
            'ssh_enabled': self._get_ssh_services()
        }

    def get_datacenter_list(self):
        ret = self.get(urlsuffix='/rest/vcenter/datacenter')
        return ret['value']

    def get_cluster_configs(self):
        cluster_configs = []
        ret = self.get(urlsuffix='/rest/vcenter/cluster')
        for cluster in ret['value']:
            cluster_configs.append({
                'name': cluster['name'],
                'moref': cluster['cluster'],
                'drs_enabled': cluster['drs_enabled'],
                'ha_enabled': cluster['ha_enabled']
            })
        return cluster_configs

    def get_host_list(self, cluster_moref):
        ret = self.get(
            urlsuffix='/rest/vcenter/host?filter.clusters={0}'.format(cluster_moref)
        )
        return [host['name'] for host in ret['value']]

    def get_vcha_configs(self):
        ha_nodes = ['node1', 'node2', 'witness']
        ret = self.post(urlsuffix='/rest/vcenter/vcha/cluster?action=get')
        vcha_configs = {
            'states': ret['value']['config_state'],
            'ha_nodes': []
        }
        if ret['value']['config_state'] == 'CONFIGURED':
            vcha_configs['ha_mode'] = ret['value']['mode']
            for node in ha_nodes:
                vcha_configs['ha_nodes'].append({
                    'ipaddress': ret[node]['ha_ip']['ipv4']['address'],
                    'netmask': ret[node]['ha_ip']['ipv4']['subnet_mask'],
                    'vm_name': ret[node]['runtime']['placement']['vm_name']
                })
        return vcha_configs
