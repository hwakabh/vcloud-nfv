import json
import logging
logger = logging.getLogger(__name__)

import requests
import urllib3
from urllib3.exceptions import InsecureRequestWarning
urllib3.disable_warnings(InsecureRequestWarning)


class VROps():
    def __init__(self, ipaddress, username, password):
        self.ipaddress = ipaddress
        self.username = username
        self.password = password
        self.headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
        }
        self.baseuri = 'https://{}'.format(self.ipaddress)

        self.set_suite_api_token()

    def set_suite_api_token(self):
        body = {
            'username': self.username,
            'password': self.password,
        }
        token = self.post(
            urlsuffix='/suite-api/api/auth/token/acquire',
            headers=self.headers,
            reqbody=json.dumps(body)
        )
        logger.debug(token)
        self.headers['Authorization'] = 'vRealizeOpsToken {}'.format(
            token.get('token')
        )

    def casa_get(self, urisuffix):
        header = {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
        }
        uri = '{0}{1}'.format(self.baseuri, urisuffix)
        res = requests.get(
            uri,
            headers=header,
            auth=(self.username, self.password),
            verify=False
        )
        logger.debug(json.loads(res.text))
        return json.loads(res.text)

    def get(self, urisuffix):
        uri = '{0}{1}'.format(self.baseuri, urisuffix)
        res = requests.get(
            uri,
            headers=self.headers,
            verify=False
        )
        logger.debug(json.loads(res.text))
        return json.loads(res.text)

    # POST for fetch suite-api token
    def post(self, urlsuffix, headers=None, reqbody=None):
        uri = '{0}{1}'.format(self.baseuri, urlsuffix)
        res = requests.post(
            uri,
            headers=self.headers,
            data=reqbody,
            verify=False
        )
        logger.debug(json.loads(res.text))
        return json.loads(res.text)

    def get_version(self):
        ret = self.get(urisuffix='/suite-api/api/versions/current')
        version_config = {
            'version': ret['releaseName'],
            'release_date': ret['humanlyReadableReleaseDate']
        }
        return version_config

    def get_cluster_configs(self):
        cluster_config = []
        ret = self.casa_get(urisuffix='/casa/cluster/config')
        # TODO: Fetch IP address from separate API endpoints
        # ipaddr = self.casa_get(urisuffix='/casa/node/status')
        for cluster in ret['slices']:
            cluster_config.append({
                'nodename': cluster['node_name'],
                'deploy_role': cluster['node_type'],
                # 'ipaddress': ipaddr['address'],
                'netmask': cluster['network_properties']['network1_netmask'],
                'gateway': cluster['network_properties']['default_gateway'],
                'dns': {
                    'nameservers': cluster['network_properties']['domain_name_servers'],
                    'domain_name': cluster['network_properties']['domain_name']
                },
                'ntp': cluster['ntp_servers']
            })
        return cluster_config

    def get_management_pack_configs(self):
        mp_configs = []
        ret = self.get(urisuffix='/suite-api/api/solutions')
        for mp in ret['solution']:
            mp_configs.append({
                'name': mp['name'],
                'version': mp['version']
            })
        return mp_configs

    def get_adpater_configs(self):
        adapter_configs = []
        ret = self.get(urisuffix='/suite-api/api/adapters')
        for adapter in ret['adapterInstancesInfoDto']:
            adapter_configs.append({
                'name': adapter['resourceKey']['name'],
                'id': adapter['id']
            })
        return adapter_configs