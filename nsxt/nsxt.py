import json
import logging
logger = logging.getLogger(__name__)

import requests
import urllib3
from urllib3.exceptions import InsecureRequestWarning
urllib3.disable_warnings(InsecureRequestWarning)


class Nsxt():
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

    def get_version(self):
        ret = self.get(urisuffix='/api/v1/node')
        return {
            'product_version': ret['product_version'],
            'kernel_version': ret['kernel_version']
        }

    def get_mgmt_network_configs(self):
        mgmt_network_configs = []
        ret = self.get(urisuffix='/api/v1/node/network/interfaces')
        for mgmt_network in ret['results']:
            mgmt_network_configs.append({
                'interface_id': mgmt_network['interface_id'],
                'physical_addr': mgmt_network['physical_address'],
                'ipaddress': mgmt_network['ip_addresses'][0]['ip_address'],
                'netmask': mgmt_network['ip_addresses'][0]['netmask'],
                'gateway': mgmt_network.get('default_gateway', None),
                'mtu': mgmt_network['mtu']
            })
        return mgmt_network_configs

    def _get_cluster_vip(self):
        ret = self.get(urisuffix='/api/v1/cluster/api-virtual-ip')
        return ret['ip_address']

    def _get_cluster_uuid(self):
        ret = self.get(urisuffix='/api/v1/cluster')
        return ret['cluster_id']

    def _get_dns_servers(self):
        ret = self.get(urisuffix='/api/v1/node/network/name-servers')
        return ret['name_servers']

    def _get_dns_domains(self):
        ret = self.get(urisuffix='/api/v1/node/network/search-domains')
        return ret['search_domains']

    def _get_ntp_servers(self):
        ret = self.get(urisuffix='/api/v1/node/services/ntp')
        return ret['service_properties']['servers']

    def _get_ssh_service(self):
        ret = self.get(urisuffix='/api/v1/node/services/ssh')
        return ret['service_properties']['start_on_boot']

    def get_cluster_wide_configs(self):
        return {
            'vip': self._get_cluster_vip(),
            'cluster_uuid': self._get_cluster_uuid(),
            'dns_servers': self._get_dns_servers(),
            'search_domains': self._get_dns_domains(),
            'ntp_servers': self._get_ntp_servers(),
            'ssh_auto_start': self._get_ssh_service()
        }

    def get_mgmt_nodes_configs(self):
        mgmt_nodes_configs = []
        ret = self.get(urisuffix='/api/v1/cluster')
        for mgmt_node in ret['nodes']:
            mgmt_nodes_configs.append({
                'fqdn': mgmt_node['fqdn'],
                'uuid': mgmt_node['node_uuid'],
                'ip_address': mgmt_node['entities'][0]['ip_address']
            })
        return mgmt_nodes_configs

    def _get_edge_cluster_configs(self):
        edge_cluster_configs = []
        ret = self.get(urisuffix='/api/v1/edge-clusters')
        for edge_cluster in ret['results']:
            edge_cluster_configs.append({
                'name': edge_cluster['display_name'],
                'id': edge_cluster['id'],
                'edge_nodes': []
            })
        return edge_cluster_configs

    def get_edge_configs(self):
        edge_configs = self._get_edge_cluster_configs()
        for edge in edge_configs:
            uri = '/api/v1/edge-clusters/{}/allocation-status'.format(edge['id'])
            ret = self.get(urisuffix=uri)
            for edge_node in ret['members']:
                edge['edge_nodes'].append({
                    'name': edge_node['node_display_name'],
                    'uuid': edge_node['node_id']
                })
        return edge_configs

    def get_transport_zone_configs(self):
        transport_zone_configs = []
        ret = self.get(urisuffix='/api/v1/transport-zones')
        for t_type in ['OVERLAY', 'VLAN']:
            t_zones = [tz for tz in ret['results'] if tz['transport_type'] == t_type]
            for t_zone in t_zones:
                transport_zone_configs.append({
                    'type': t_type.capitalize(),
                    'name': t_zone['display_name'],
                    'uuid': t_zone['id'],
                    'nvds_mode': t_zone['host_switch_mode']
                })
        return transport_zone_configs

    def get_host_transport_node_configs(self):
        node_types = ['HostNode', 'EdgeNode']
        transport_node_configs = []
        for node_type in node_types:
            uri = '/api/v1/transport-nodes?node_types={}'.format(node_type)
            ret = self.get(urisuffix=uri)
            for tnode in ret['results']:
                nodeconf = {
                    'type': node_type,
                    'name': tnode['display_name'],
                    'uuid': tnode['id'],
                    'ip_address': tnode['node_deployment_info']['ip_addresses'][0],
                    'nvds_name': tnode['host_switch_spec']['host_switches'][0]['host_switch_name']
                }
                if node_type == 'HostNode':
                    nodeconf['os_type'] = \
                        tnode['node_deployment_info']['os_type']
                if node_type == 'EdgeNode':
                    nodeconf['deploy_type'] = \
                        tnode['node_deployment_info']['deployment_type']
                    nodeconf['form_factor'] = \
                        tnode['node_deployment_info']['deployment_config']['form_factor']
                    nodeconf['fqdn'] = \
                        tnode['node_deployment_info']['node_settings']['hostname']
                transport_node_configs.append(nodeconf)
        return transport_node_configs

    def get_ippool_configs(self):
        ippool_configs = []
        ret = self.get(urisuffix='/api/v1/pools/ip-pools')
        for ippool in ret['results']:
            ippool_configs.append({
                'name': ippool['display_name'],
                'uuid': ippool['id'],
                'subnets': ippool['subnets']
            })
        return ippool_configs

    def get_tier0s_configs(self):
        tier0s_configs = []
        ret = self.get(
            urisuffix='/policy/api/v1/infra/tier-0s'
        )
        for tier0 in ret['results']:
            tier0s_configs.append({
                'name': tier0['display_name'],
                'uuid': tier0['unique_id'],
                'ha_mode': tier0['ha_mode'],
                'failover_mode': tier0['failover_mode']
            })
        return tier0s_configs

    def get_dhcp_server_configs(self):
        dhcp_server_configs = []
        ret = self.get(
            urisuffix='/policy/api/v1/infra/dhcp-server-configs'
        )
        for dhcp_server in ret['results']:
            edge_cluster_uri = '/policy/api/v1{}'.format(
                dhcp_server['edge_cluster_path']
            )
            edge_name = self.get(urisuffix=edge_cluster_uri)
            dhcp_server_configs.append({
                'name': dhcp_server['display_name'],
                'uuid': dhcp_server['unique_id'],
                'server_address': dhcp_server['server_address'],
                'edge_cluster': edge_name['display_name'],
            })
        return dhcp_server_configs

    def get_metadata_proxy_configs(self):
        md_proxy_configs = []
        ret = self.get(
            urisuffix='/policy/api/v1/infra/metadata-proxies'
        )
        for md_proxy in ret['results']:
            edge_cluster_uri = '/policy/api/v1{}'.format(
                md_proxy['edge_cluster_path']
            )
            edge_name = self.get(urisuffix=edge_cluster_uri)
            md_proxy_configs.append({
                'name': md_proxy['display_name'],
                'uuid': md_proxy['unique_id'],
                'server_address': md_proxy['server_address'],
                'edge_cluster': edge_name['display_name'],
            })
        return md_proxy_configs
