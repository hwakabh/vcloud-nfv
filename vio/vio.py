import requests
import json
import logging
logger = logging.getLogger(__name__)

import urllib3
from urllib3.exceptions import InsecureRequestWarning
urllib3.disable_warnings(InsecureRequestWarning)


class Vio():
    def __init__(self, ipaddress, username, password):
        self.ipaddress = ipaddress
        self.username = username
        self.password = password
        self.headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
        }
        self.baseuri = 'https://{}'.format(self.ipaddress)

    def get(self, urisuffix):
        uri = '{0}{1}'.format(self.baseuri, urisuffix)
        res = requests.get(
            uri,
            headers=self.headers,
            auth=(self.username, self.password),
            verify=False
        )
        logger.debug(json.loads(res.text))
        return json.loads(res.text)

    def get_network_configs(self):
        network_configs = []
        ret = self.get(
            urisuffix='/apis/vio.vmware.com/v1alpha1/namespaces/openstack/vioclusters/viocluster1'
        )
        for network in ret['spec']['cluster']['network_info']:
            network_configs.append({
                'network_type': network['type'],
                'portgroup': network['networkName'],
                'ipaddress': network['static_config']['ip_ranges'],
                'netmask': network['static_config']['netmask'],
                'gateway': network['static_config']['gateway'],
                'dns': network['static_config']['dns'],
            })
        return network_configs

    def get_ntp_servers(self):
        ret = self.get(
            urisuffix='/apis/cluster.k8s.io/v1alpha1/namespaces/openstack/machines'
        )
        # NTP config is stored within cluster-api
        viomgr_conf = ret['items'][-1]['spec']['providerSpec']['value']
        return viomgr_conf['machineSpec']['ntpServers']

    def get_node_configs(self):
        node_configs = []
        ret = self.get(
            urisuffix='/api/v1/nodes'
        )
        for node in ret['items']:
            node_configs.append({
                'name': node['metadata']['name'],
                'pod_cidr': node['spec']['podCIDR'],
                'internal_ip': node['status']['addresses'][0]['address'],
                'external_ip': node['status']['addresses'][1]['address'],
            })
        return node_configs

    def get_osdeployment_configs(self):
        osdeployment_configs = []
        ret = self.get(
            urisuffix='/apis/vio.vmware.com/v1alpha1/namespaces/openstack/osdeployments'
        )
        for osd in ret['items']:
            osdeployment_configs.append({
                'private_vip': osd['spec']['openstack_endpoints']['private_vip'],
                'public_vip': osd['spec']['openstack_endpoints']['public_vip'],
                'ha_enabled': osd['spec']['ha-enabled'],
                'region_name': osd['spec']['region_name'],
                'admin_domain': osd['spec']['admin_domain_name'],
                'os_services': [svc['service'] for svc in osd['spec']['services']]
            })
        return osdeployment_configs

    def get_backends_configs(self):
        backends_configs = {}
        backends = ['vcenter', 'nsx']
        for backend in backends:
            uri = '/apis/vio.vmware.com/v1alpha1/namespaces/openstack/{0}s/{1}1'.format(
                backend, backend
            )
            ret = self.get(urisuffix=uri)
            backends_configs[backend] = ret['spec']['hostname']
        return backends_configs
