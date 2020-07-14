import json
import logging
logger = logging.getLogger(__name__)

import requests
import urllib3
from urllib3.exceptions import InsecureRequestWarning
urllib3.disable_warnings(InsecureRequestWarning)


class VRli():
    def __init__(self, ipaddress, username, password, provider):
        self.ipaddress = ipaddress
        self.username = username
        self.password = password
        self.provider = provider
        self.headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
        }
        self.rest_port = 9543
        self.baseuri = 'https://{0}:{1}'.format(self.ipaddress, self.rest_port)

        self.set_token()

    def set_token(self):
        body = {
            'username': self.username,
            'password': self.password,
            'provider': self.provider
        }
        token = self.post(
            urlsuffix='/api/v1/sessions',
            headers=self.headers,
            reqbody=json.dumps(body)
        )
        logger.debug(token)
        self.headers['Authorization'] = 'Bearer {}'.format(
            token.get('sessionId')
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

    def get_version(self):
        ret = self.get(urisuffix='/api/v1/version')
        version_config = {
            'version': ret['version'],
            'release_type': ret['releaseName']
        }
        return version_config

    def get_cluster_configs(self):
        ret = self.get(urisuffix='/api/v1/cluster/vips')
        cluster_configs = {
            'ipaddress': ret['vips'][0]['ipAddress'],
            'fqdn': ret['vips'][0]['fqdn']
        }
        return cluster_configs

    def get_node_configs(self):
        node_configs = []
        ret = self.get(urisuffix='/api/v1/cluster/nodes')
        for node in ret['nodes']:
            node_configs.append({
                'node_id': node['id'],
                'ipaddress': node['ip'],
                'netmask': node['netmask'],
                'gateway': node['gateway'],
                'dns': node['dnsServers'],
            })
        return  node_configs

    def get_ntp_server(self):
        ret = self.get(urisuffix='/api/v1/time/config')
        return ret['ntpConfig']['ntpServers']

    def get_contents_pack_configs(self):
        content_pack_configs = []
        ret = self.get(urisuffix='/api/v1/content/contentpack/list')
        for cp in ret['contentPackMetadataList']:
            content_pack_configs.append({
                'name': cp['name'],
                # 'format_version': cp['formatVersion'],
                'content_version': cp['contentVersion']
            })
        return content_pack_configs