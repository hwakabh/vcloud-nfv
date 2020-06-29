import json
import logging
logger = logging.getLogger(__name__)

import requests
import urllib3
from urllib3.exceptions import InsecureRequestWarning
urllib3.disable_warnings(InsecureRequestWarning)
import pexpect


class VRni():
    def __init__(self, ipaddress, username, password, domain):
        self.ipaddress = ipaddress
        self.username = username
        self.password = password
        self.domain = domain
        self.headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
        }
        self.baseuri = 'https://{0}'.format(self.ipaddress)

        self.set_token()

    def set_token(self):
        body = {
            'username': self.username,
            'password': self.password,
            'domain': {
                'domain_type': self.domain
            }
        }
        # POST to fetch token
        token = self.post(
            urlsuffix='/api/ni/auth/token',
            headers=self.headers,
            reqbody=json.dumps(body)
        )
        logger.debug(token)
        # Update headers
        self.headers['Authorization'] = 'NetworkInsight {}'.format(
            token.get('token')
        )

    def get(self, urisuffix):
        uri = '{0}{1}'.format(self.baseuri, urisuffix)
        res = requests.get(
            uri,
            headers=self.headers,
            verify=False
        )
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

    def run_ssh_command(self, command):
        try:
            login_command = 'ssh consoleuser@{}'.format(self.ipaddress)
            console = pexpect.spawn(login_command)
            console.expect('^.*password:')
            console.sendline(self.password)
            console.expect(r'\(cli\)')
            console.sendline(command)
            console.expect(r'\(cli\)')
        except:
            logger.error('Failed to run commands via SSH.')
            console.sendline('logout')
        return console.before.splitlines()

    def get_base_version(self):
        ret = self.run_ssh_command(command='show-version')
        return ret[1].decode('utf-8')

    def get_api_version(self):
        endpoint = '/api/ni/info/version'
        ret = self.get(urisuffix=endpoint)
        return ret['api_version']

    def get_node_configs(self):
        node_configs = {}
        ret = self.run_ssh_command(command='show-config')
        for line in [line.decode('utf-8') for line in ret[3:]][:-1]:
            node_configs[line.split(': ')[0]] = line.split(': ')[1]
        return node_configs

    def get_node_role(self):
        node_roles = []
        ret = self.get(urisuffix='/api/ni/infra/nodes')
        node_ids = [node['id'] for node in ret['results']]
        for node_id in node_ids:
            node = self.get(
                urisuffix='/api/ni/infra/nodes/{}'.format(node_id)
            )
            node_roles.append({
                'node_ids': {
                    'id': node['id'],
                    'internal_id': node['node_id']
                },
                'deploy_role': node['node_type']
            })
        return node_roles

    def get_vcenter_source(self):
        vcenter_sources = []
        ret = self.get(urisuffix='/api/ni/data-sources/vcenters')
        vcenters = [vc['entity_id'] for vc in ret['results']]
        for vcenter in vcenters:
            res_vc = self.get('/api/ni/data-sources/vcenters/{}'.format(vcenter))
            vcenter_sources.append({
                'type': 'vcenter',
                'fqdn': res_vc['fqdn'],
                'nickname': res_vc['nickname'],
                'username': res_vc['credentials']['username'],
                'entity_id': res_vc['entity_id'],
                'proxy_id': res_vc['proxy_id'],
                'enabled': res_vc['enabled']
            })
        return vcenter_sources

    def get_nsx_source(self):
        nsx_sources = []
        ret = self.get('/api/ni/data-sources/nsxt-managers')
        nsxmgrs = [nsxmgr['entity_id'] for nsxmgr in ret['results']]
        for nsx in nsxmgrs:
            res_nsx = self.get('/api/ni/data-sources/nsxt-managers/{}'.format(nsx))
            nsx_sources.append({
                'type': 'nsx',
                'nickname': res_nsx['nickname'],
                'username': res_nsx['credentials']['username'],
                'entity_id': res_nsx['entity_id'],
                'proxy_id': res_nsx['proxy_id'],
                'enabled': res_nsx['enabled']
            })
        return nsx_sources