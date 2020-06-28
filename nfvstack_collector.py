import yaml
import sys
import os
import json
from datetime import datetime
import logging

from vcsa.vcsa import VCenter, VApi, EsxiSoapParser
from nsxt.nsxt import Nsxt
from vio.vio import Vio
from vrops.vrops import VROps
from vrli.vrli import VRli
from vrni.vrni import VRni


def read_config_from_file(conf_file_path):
    with open(conf_file_path, 'r') as f:
        data = f.read()
    return yaml.safe_load(data)


def export_config_to_file(dump_data, timestamp):
    # TODO: wrap as directory for store dump data
    # --- YYYYMMDD_nfvstack/*.json
    target_product = dump_data['product']
    dump_file_name = '{0}_{1}_config.json'.format(timestamp, target_product)
    with open(dump_file_name, 'w') as f:
        json.dump(dump_data, f, indent=3)
    return dump_file_name


def get_vcenter_configs(config):
    cfg = config['vcenter']
    IPADDRESS, USERNAME, PASSWORD = cfg['ip_address'], cfg['user_name'], cfg['sso_password']

    logger.info('------ Starting config_dump for vCSA: {}'.format(IPADDRESS))
    # Call vSphere REST-API to fetch vCSA config
    vc = VCenter(ipaddress=IPADDRESS, username=USERNAME, password=PASSWORD)
    vcsa_version = vc.get('/rest/appliance/system/version')
    vcsa_networks = vc.get('/rest/appliance/networking/interfaces')
    vcsa_hostnames = vc.get('/rest/appliance/networking/dns/hostname')
    vcsa_dns = vc.get('/rest/appliance/networking/dns/servers')
    vcsa_ntp = vc.get('/rest/appliance/ntp')
    vcsa_ssh_status = vc.get('/rest/appliance/access/ssh')

    vcsa_dc = vc.get('/rest/vcenter/datacenter')
    vcsa_clusters = vc.get('/rest/vcenter/cluster')

    vcsa_ha = vc.post('/rest/vcenter/vcha/cluster?action=get')

    # Call vAPI to get ESXi host configs
    vapi = VApi(ipaddress=IPADDRESS, username=USERNAME, password=PASSWORD)
    # Retrieve all hostdata prior to compare with response of vSphere REST-API
    esxis = vapi.get_host_objects()
    vds_configs = vapi.get_dvs_objects()

    logger.info('>>> Appliance configurations ...')
    logger.info('Version: \t{0} (Build : {1})'.format(vcsa_version['value']['version'], vcsa_version['value']['build']))
    logger.info('IP address: \t{}'.format(vcsa_networks['value'][0]['ipv4']['address']))
    logger.info('Subnet Prefix: \t{}'.format(vcsa_networks['value'][0]['ipv4']['prefix']))
    logger.info('Gateway: \t{}'.format(vcsa_networks['value'][0]['ipv4']['default_gateway']))
    logger.info('Hostname: \t{}'.format(vcsa_hostnames['value']))
    logger.info('DNS Servers: \t{}'.format(vcsa_dns['value']['servers']))
    logger.info('NTP Servers: \t{}'.format(vcsa_ntp['value']))
    logger.info('SSH Services: \t{}'.format('Running' if vcsa_ssh_status['value'] == True else 'Not Running'))
    logger.info('')

    logger.info('>>> vCHA configurations ...')
    nodes = ['node1', 'node2', 'witness']
    logger.info('Mode : {}'.format(vcsa_ha['value']['mode']))
    for node in nodes:
        logger.info('> vCHA: {}'.format(node))
        logger.info('  IP Address: {}'.format(vcsa_ha['value'][node]['ha_ip']['ipv4']['address']))
        logger.info('  Subnetk: {}'.format(vcsa_ha['value'][node]['ha_ip']['ipv4']['subnet_mask']))
        logger.info('  VM Name: {}'.format(vcsa_ha['value'][node]['runtime']['placement']['vm_name']))

    logger.info('')

    for dc in vcsa_dc['value']:
        logger.info('>>> Datacenter: {}'.format(dc['name']))
    for cluster in vcsa_clusters['value']:
        logger.info('>>> Cluster : {}'.format(cluster['name']))
        logger.info('DRS Enabled:\t{}'.format(cluster['drs_enabled']))
        logger.info('HA Enabled:\t{}'.format(cluster['ha_enabled']))
        logger.info('>>>>>> Managed ESXi Host configs')
        vcsa_hosts = vc.get('/rest/vcenter/host?filter.clusters={}'.format(cluster['cluster']))
        for host in vcsa_hosts['value']:
            esxi_parser = EsxiSoapParser()
            host_info = dict()
            logger.info('>>>>>>>>> {}'.format(host['name']))
            target_host = [esxi for esxi in esxis if esxi.name == host['name']][0]
            version, build, apiversion = esxi_parser.get_host_system_version(target_host)
            logger.info('Host Version: {0} (Build {1})'.format(version, build))
            logger.info('API Version: {}'.format(apiversion))
            host_pnics = esxi_parser.get_host_pnics(target_host)
            host_vnics = esxi_parser.get_host_vnics(target_host)
            host_vswitches = esxi_parser.get_host_vswitches(target_host)
            host_portgroups = esxi_parser.get_host_portgroups(target_host)
            host_info.update({
                'pnics': host_pnics,
                'vswitches': host_vswitches,
                'portgroups': host_portgroups,
                'vnics': host_vnics
            })
            logger.info('vmnics:')
            for vmnic in host_pnics:
                logger.info('\t[ {0} ] MAC addr= {1}, driver={2}'.format(vmnic['device'], vmnic['mac'], vmnic['driver']))
            logger.info('vmkernel ports:')
            for vmk in host_vnics:
                # TODO: merge info about vmk gateway
                logger.info('\t[ {0} ] IP Address= {1}, Subnet Mask={2}, MAC addr={3}, MTU={4}'.format(vmk['device'], vmk['ipAddress'], vmk['subnetMask'], vmk['mac'], vmk['mtu']))
            logger.info('vSwitch(vSS):')
            for vss in host_vswitches:
                logger.info('\t[ {0} ] Uplinks={1}, PortGroups={2}, MTU={3}'.format(vss['name'], vss['pnics'], vss['portgroups'], vss['mtu']))
            logger.info('portgroups:')
            for pg in host_portgroups:
                logger.info('\t[ {0} ] VLAN={1}, vSwitchName={2}'.format(pg['name'], pg['vlanId'], pg['vswitchName']))

            nameservers, searchpath = esxi_parser.get_host_dns_config(target_host)
            logger.info('DNS Servers:')
            for ns in nameservers:
                logger.info('  {}'.format(ns))
            logger.info('DNS Search Path:')
            for sp in searchpath:
                logger.info('  {}'.format(sp))
            ntp_severs = esxi_parser.get_host_ntp_config(target_host)
            logger.info('NTP servers:')
            for ntp in ntp_severs:
                logger.info('  {}'.format(ntp))
            logger.info('SSH service : {}'.format(esxi_parser.get_host_ssh_status(target_host)))
            logger.info('')

    logger.info('>>> vDS configs')
    for dvs in vds_configs:
        logger.info('Name : {}'.format(dvs.name))
        logger.info('Configured hosts: ')
        for member_host in dvs.config.host:
            logger.info('  {}'.format(member_host.config.host.name))
        logger.info('dvPortGroups: ')
        for dvportgroup in dvs.config.uplinkPortgroup:
            logger.info('  {}'.format(dvportgroup.name))
        logger.info('Uplinks configured: ')
        for uplink in dvs.config.uplinkPortPolicy.uplinkPortName:
            logger.info('  {}'.format(uplink))
        logger.info('Port Groups: ')
        for pg in dvs.portgroup:
            if type(pg.config.defaultPortConfig.vlan.vlanId) == int:
                logger.info('  {0} ( VLAN: {1} )'.format(pg.name, pg.config.defaultPortConfig.vlan.vlanId))
        logger.info('')

    logger.info('>>> vSAN Cluster configs')
    for vsan_host in esxis:
        logger.info('>>>>>> {}'.format(vsan_host.name))
        logger.info('Cluster UUID: {}'.format(vsan_host.configManager.vsanSystem.config.clusterInfo.uuid))
        logger.info('Node UUID: {}'.format(vsan_host.configManager.vsanSystem.config.clusterInfo.nodeUuid))
        disk_config = vsan_host.config.vsanHostConfig.storageInfo.diskMapping
        logger.info('Disk Group: {}'.format(disk_config[0].ssd.vsanDiskInfo.vsanUuid))
        for disk in disk_config:
            logger.info('Disk Claimed: ')
            logger.info('> Flash')
            logger.info('  {}'.format(disk.ssd.displayName))
            logger.info('> HDD')
            for non_ssd in disk.nonSsd:
                logger.info('  {}'.format(non_ssd.displayName))
        logger.info('')


    # TODO: Return JSON value with parsed
    return None


def get_nsxt_configs(config):
    cfg = config['nsxt']
    NSX_MGR, NSX_USERNAME, NSX_PASSWORD = cfg['ip_address'], cfg['admin_user_name'], cfg['admin_password']

    logger.info('------ Starting config_dump for NSX-T Manager: {}'.format(NSX_MGR))
    nsx = Nsxt(ipaddress=NSX_MGR, username=NSX_USERNAME, password=NSX_PASSWORD)
    # Call v3 API for fetching configs
    vip = nsx.get('/api/v1/cluster/api-virtual-ip')
    cluster = nsx.get('/api/v1/cluster')
    hostname = nsx.get('/api/v1/node')
    mgmt_networks = nsx.get('/api/v1/node/network/interfaces')
    dns = nsx.get('/api/v1/node/network/name-servers')
    domains = nsx.get('/api/v1/node/network/search-domains')
    ntp = nsx.get('/api/v1/node/services/ntp')
    ssh = nsx.get('/api/v1/node/services/ssh')
    edge_cluster = nsx.get('/api/v1/edge-clusters')
    edge_nodes = nsx.get('/api/v1/edge-clusters/{}/allocation-status'.format(edge_cluster['results'][0]['id']))
    transport_zones = nsx.get('/api/v1/transport-zones')
    host_transport_nodes = nsx.get('/api/v1/transport-nodes?node_types=HostNode')
    edge_transport_nodes = nsx.get('/api/v1/transport-nodes?node_types=EdgeNode')
    ip_pools = nsx.get('/api/v1/pools/ip-pools')

    # Call Policy API for retrieving configs
    tier_0s = nsx.get('/policy/api/v1/infra/tier-0s')
    dhcp_servers = nsx.get('/policy/api/v1/infra/dhcp-server-configs')
    mk_proxies = nsx.get('/policy/api/v1/infra/metadata-proxies')

    logger.info('>>> Version information')
    logger.info('Product Version: \t{}'.format(hostname['product_version']))
    logger.info('Kernel Version: \t{}'.format(hostname['kernel_version']))
    logger.info('')

    # Fetch only management network information
    logger.info('>>> Management Network information')
    for net in mgmt_networks['results']:
        logger.info('Interface: \t{0} (Physical Address: {1})'.format(net['interface_id'], net['physical_address']))
        logger.info('IP Address: \t{}'.format(net['ip_addresses'][0]['ip_address']))
        logger.info('Netmask: \t{}'.format(net['ip_addresses'][0]['netmask']))
        if 'default_gateway' in net:
            logger.info('Gateway: \t{}'.format(net['default_gateway']))
        logger.info('MTU: \t\t{}'.format(net['mtu']))
        logger.info('')

    logger.info('>>> Cluster-wide information')
    logger.info('vIP: \t\t\t{}'.format(vip['ip_address']))
    logger.info('Cluster UUID: \t\t{}'.format(cluster['cluster_id']))
    logger.info('DNS Servers: \t\t{}'.format(dns['name_servers']))
    logger.info('DNS Search Path: \t{}'.format(domains['search_domains']))
    logger.info('NTP Servers: \t\t{}'.format(ntp['service_properties']['servers']))
    logger.info('SSH auto start: \t{}'.format(ssh['service_properties']['start_on_boot']))
    logger.info('')

    logger.info('>>> Mangement Cluster')
    for i, node in enumerate(cluster['nodes']):
        logger.info('Node-{0} FQDN: \t{1}'.format(i+1, node['fqdn']))
        logger.info('UUID: \t\t{}'.format(node['node_uuid']))
        logger.info('IP Address: \t{}'.format(node['entities'][0]['ip_address']))
        logger.info('')

    logger.info('>>> Edge Cluster information')
    logger.info('Name: \t{}'.format(edge_cluster['results'][0]['display_name']))
    logger.info('ID: \t{}'.format(edge_cluster['results'][0]['id']))
    logger.info('')
    logger.info('>>> Edge Nodes')
    for edge_node in edge_nodes['members']:
        logger.info('Name: \t{}'.format(edge_node['node_display_name']))
        logger.info('UUID: \t{}'.format(edge_node['node_id']))
        logger.info('')

    logger.info('>>> Transport-Zone information')
    overlay_tzs = [otz for otz in transport_zones['results'] if otz['transport_type'] == 'OVERLAY']
    logger.info('>>>>>> Overlay transport-zones')
    for overlay_tz in overlay_tzs:
        logger.info('Name: \t\t{}'.format(overlay_tz['display_name']))
        logger.info('UUID: \t\t{}'.format(overlay_tz['id']))
        logger.info('N-vDS Mode: \t{}'.format(overlay_tz['host_switch_mode']))
        logger.info('')

    vlan_tzs = [vtz for vtz in transport_zones['results'] if vtz['transport_type'] == 'VLAN']
    logger.info('>>>>>> VLAN transport-zones')
    for vlan_tz in vlan_tzs:
        logger.info('Name: \t\t{}'.format(vlan_tz['display_name']))
        logger.info('UUID: \t\t{}'.format(vlan_tz['id']))
        logger.info('N-vDS Mode: \t{}'.format(vlan_tz['host_switch_mode']))
        logger.info('')

    logger.info('>>> Transport Nodes information')
    logger.info('>>>>> Host transport-nodes')
    for htn in host_transport_nodes['results']:
        logger.info('Name: \t\t{}'.format(htn['display_name']))
        logger.info('UUID: \t\t{}'.format(htn['id']))
        logger.info('OS Type: \t{}'.format(htn['node_deployment_info']['os_type']))
        logger.info('IP Address: \t{}'.format(htn['node_deployment_info']['ip_addresses'][0]))
        logger.info('N-vDS Name: \t{}'.format(htn['host_switch_spec']['host_switches'][0]['host_switch_name']))
        logger.info('')
    logger.info('>>>>>> Edge transport-nodes')
    for etn in edge_transport_nodes['results']:
        logger.info('Name: \t\t\t{}'.format(etn['display_name']))
        logger.info('UUID: \t\t\t{}'.format(etn['id']))
        logger.info('Deployment Type: \t{}'.format(etn['node_deployment_info']['deployment_type']))
        logger.info('Form Factor: \t\t{}'.format(etn['node_deployment_info']['deployment_config']['form_factor']))
        logger.info('IP Address: \t\t{}'.format(etn['node_deployment_info']['ip_addresses'][0]))
        logger.info('FQDN: \t\t\t{}'.format(etn['node_deployment_info']['node_settings']['hostname']))

        logger.info('N-vDS Name: \t\t{}'.format(etn['host_switch_spec']['host_switches'][0]['host_switch_name']))
        logger.info('')

    logger.info('>>> IP Pool information')
    for pool in ip_pools['results']:
        logger.info('Name: {}'.format(pool['display_name']))
        logger.info('UUID: {}'.format(pool['id']))
        logger.info('Subnets:')
        for subnet in pool['subnets']:
            logger.info('  CIDR={0}, Range=[ {1} - {2} ]'.format(subnet['cidr'], subnet['allocation_ranges'][0]['start'], subnet['allocation_ranges'][0]['end']))
        logger.info('Usage: total={0}, allocated={1}, free={2}'.format(pool['pool_usage']['total_ids'], pool['pool_usage']['allocated_ids'], pool['pool_usage']['free_ids']))
        logger.info('')

    logger.info('>>> Tier-0 Routers')
    for tier_0 in tier_0s['results']:
        logger.info('Name: \t\t{}'.format(tier_0['display_name']))
        logger.info('UUID: \t\t{}'.format(tier_0['unique_id']))
        logger.info('HA Mode: \t{}'.format(tier_0['ha_mode']))
        logger.info('Failover Mode: \t{}'.format(tier_0['failover_mode']))
        logger.info('')

    logger.info('>>> DHCP Server Profiles')
    for dhcp_server in dhcp_servers['results']:
        logger.info('Name: \t\t\t{}'.format(dhcp_server['display_name']))
        logger.info('UUID: \t\t\t{}'.format(dhcp_server['unique_id']))
        logger.info('Server Address: \t{}'.format(dhcp_server['server_address']))
        edge = nsx.get('/policy/api/v1{}'.format(dhcp_server['edge_cluster_path']))
        logger.info('Edge Cluster: \t\t{}'.format(edge['display_name']))
        logger.info('')

    logger.info('>>> Metadata Proxies')
    for mk_proxy in mk_proxies['results']:
        logger.info('Name: \t\t\t{}'.format(mk_proxy['display_name']))
        logger.info('UUID: \t\t\t{}'.format(mk_proxy['unique_id']))
        logger.info('Server Address: \t{}'.format(mk_proxy['server_address']))
        edge = nsx.get('/policy/api/v1{}'.format(dhcp_server['edge_cluster_path']))
        logger.info('Edge Cluster: \t\t{}'.format(edge['display_name']))
        logger.info('')

    # Return JSON value with parsed
    return None


def get_vio_configs(config):
    cfg = config['vio']
    VIO_MGR = cfg['management_ip']
    VIO_USERNAME = cfg['user_name']
    VIO_PASSWORD = cfg['vio_admin_password']

    logger.info('--- Collect data from VIO Manager: {}'.format(VIO_MGR))
    viomgr = Vio(
        ipaddress=VIO_MGR,
        username=VIO_USERNAME,
        password=VIO_PASSWORD
    )
    vio_networks = viomgr.get('/apis/vio.vmware.com/v1alpha1/namespaces/openstack/vioclusters/viocluster1')
    vio_nodes = viomgr.get('/api/v1/nodes')
    vio_machines = viomgr.get('/apis/cluster.k8s.io/v1alpha1/namespaces/openstack/machines')
    vio_deployments = viomgr.get('/apis/vio.vmware.com/v1alpha1/namespaces/openstack/osdeployments')
    vio_backend_vc = viomgr.get('/apis/vio.vmware.com/v1alpha1/namespaces/openstack/vcenters/vcenter1')
    vio_backend_nsx = viomgr.get('/apis/vio.vmware.com/v1alpha1/namespaces/openstack/nsxs/nsx1')

    cluster_network = vio_networks['spec']['cluster']
    ntp_server = vio_machines['items'][-1]['spec']['providerSpec']['value']['machineSpec']['ntpServers']

    logger.info('>>> Network information ...')
    network_configs = []
    for network in cluster_network['network_info']:
        netconf = {
            'network_type': network['type'],
            'portgroup': network['networkName'],
            'ipaddress': network['static_config']['ip_ranges'],
            'netmask': network['static_config']['netmask'],
            'gateway': network['static_config']['gateway'],
            'dns': network['static_config']['dns'],
        }
        network_configs.append(netconf)

        logger.info('> {} Network'.format(network['type']))
        logger.info('vSphere PortGroup: \t{}'.format(network['networkName']))
        logger.info('IP Ranges: \t\t{}'.format(network['static_config']['ip_ranges']))
        logger.info('Netmask: \t\t{}'.format(network['static_config']['netmask']))
        logger.info('Gateway: \t\t{}'.format(network['static_config']['gateway']))
        logger.info('DNS Servers: \t\t{}'.format(network['static_config']['dns']))
        logger.info('')

    logger.info('> NTP Servers: {}'.format(ntp_server))
    logger.info('')
    logger.info('> manager/controller nodes')
    node_configs = []
    for node in vio_nodes['items']:
        nodeconf = {
            'name': node['metadata']['name'],
            'pod_cidr': node['spec']['podCIDR'],
            'internal_ip': node['status']['addresses'][0]['address'],
            'external_ip': node['status']['addresses'][1]['address'],
        }
        node_configs.append(nodeconf)
        logger.info('Nodename: \t{}'.format(node['metadata']['name']))
        logger.info('  Pod CIDR: \t{}'.format(node['spec']['podCIDR']))
        logger.info('  Internal IP: \t{}'.format(node['status']['addresses'][0]['address']))
        logger.info('  External IP: \t{}'.format(node['status']['addresses'][1]['address']))

    logger.info('')

    logger.info('>>> VIO Openstack Deployment configurations')
    deployment_configs = {
        'endpoints': {
            'private': {
                'ipaddress': vio_deployments['items'][0]['spec']['openstack_endpoints']['private_vip']
                },
            'public': {
                'ipaddress': vio_deployments['items'][0]['spec']['openstack_endpoints']['public_vip'],
                'hostname': vio_deployments['items'][0]['spec']['public_hostname']
                }
            },
        'deploy_mode': vio_deployments['items'][0]['spec']['ha-enabled'],
        'region_name': vio_deployments['items'][0]['spec']['region_name'],
        'admin_domain': vio_deployments['items'][0]['spec']['admin_domain_name']
    }

    logger.info('private Endpoint: \t\t{}'.format(vio_deployments['items'][0]['spec']['openstack_endpoints']['private_vip']))
    logger.info('Public Endpoint: \t\t{}'.format(vio_deployments['items'][0]['spec']['openstack_endpoints']['public_vip']))
    logger.info('Public hostname: \t\t{}'.format(vio_deployments['items'][0]['spec']['public_hostname']))
    logger.info('HA mode: \t\t\t{}'.format(vio_deployments['items'][0]['spec']['ha-enabled']))
    logger.info('Region Name: \t\t\t{}'.format(vio_deployments['items'][0]['spec']['region_name']))
    logger.info('Admin Domain Name: \t\t{}'.format(vio_deployments['items'][0]['spec']['admin_domain_name']))

    os_services = [svc['service'] for svc in vio_deployments['items'][0]['spec']['services']]
    logger.info('Deployed OpenStack Services: \t{}'.format(os_services))
    logger.info('')

    logger.info('>>> Configured backends')
    backend_configs = {
        'vsphere': vio_backend_vc['spec']['hostname'],
        'nsx': vio_backend_nsx['spec']['hostname']
    }
    logger.info('vSphere: \t{}'.format(vio_backend_vc['spec']['hostname']))
    logger.info('NSX-T: \t\t{}'.format(vio_backend_nsx['spec']['hostname']))
    logger.info('')

    # Parse data for filedump
    config_dump = {
        'product': 'vio',
        'network': network_configs,
        'ntp': ntp_server,
        'node_networks': node_configs,
        'osdeployment': deployment_configs,
        'openstack_services': os_services,
        'vio_backends': backend_configs
    }

    return config_dump


def get_vrni_configs(config):
    cfg = config['vrni']
    VRNI_IPADDR = cfg['hostname']
    VRNI_USERNAME = cfg['user_name']
    VRNI_PASSWORD = cfg['password']
    VRNI_DOMAIN = cfg['domain']

    logger.info('--- Collect data from vRNI: {}'.format(VRNI_IPADDR))
    vrni = VRni(
        ipaddress=VRNI_IPADDR,
        username=VRNI_USERNAME,
        password=VRNI_PASSWORD,
        domain=VRNI_DOMAIN
    )
    version_info = vrni.get('/api/ni/info/version')
    nodes_info = vrni.get('/api/ni/infra/nodes')
    ds_vcenter = vrni.get('/api/ni/data-sources/vcenters')
    ds_nsxmgr = vrni.get('/api/ni/data-sources/nsxt-managers')

    logger.info('>>> Version information')
    version_configs = {
        'versions': {
            'version': None,
            'api_version': version_info['api_version']
        }
    }
    logger.info('API Version : {0}'.format(version_info['api_version']))
    logger.info('')

    logger.info('>>> Nodes information')
    node_configs = []
    # Fetch all node ids configured
    ni_node_ids = [i['id'] for i in nodes_info['results']]
    for node_id in ni_node_ids:
        node = vrni.get('/api/ni/infra/nodes/{}'.format(node_id))
        node_conf = {
            'node_ids': {
                'id': node['id'],
                'internal_id': node['node_id']
            },
            'ipaddress': node['ip_address'],
            'deploy_role': node['node_type']
        }
        node_configs.append(node_conf)

        logger.info('Node ID: {0} (internal: {1})'.format(node['id'], node['node_id']))
        logger.info('IP Address: {}'.format(node['ip_address']))
        logger.info('Deployment Role: {}'.format(node['node_type']))
    logger.info('')

    logger.info('>>> Data sources')
    data_source_configs = []
    logger.info('> vCenter Servers:')
    vcenters = [vc['entity_id'] for vc in ds_vcenter['results']]
    for vcenter in vcenters:
        res_vc = vrni.get('/api/ni/data-sources/vcenters/{}'.format(vcenter))
        vc_configs = {
            'type': 'vcenter',
            'nickname': res_vc['nickname'],
            'username': res_vc['credentials']['username'],
            'entity_id': res_vc['entity_id'],
            'proxy_id': res_vc['proxy_id'],
            'enabled': res_vc['enabled']
        }
        data_source_configs.append(vc_configs)
        logger.info('Name : \t\t{}'.format(res_vc['nickname']))
        logger.info('Username : \t{}'.format(res_vc['credentials']['username']))
        logger.info('EntityID : \t{}'.format(res_vc['entity_id']))
        logger.info('ProxyID : \t{}'.format(res_vc['proxy_id']))
        logger.info('Enabled : \t{}'.format(res_vc['enabled']))
        logger.info('')

    logger.info('> NSX-T Managers:')
    nsxmgrs = [nsxmgr['entity_id'] for nsxmgr in ds_nsxmgr['results']]
    for nsx in nsxmgrs:
        res_nsx = vrni.get('/api/ni/data-sources/nsxt-managers/{}'.format(nsx))
        nsx_configs = {
            'type': 'nsx',
            'nickname': res_nsx['nickname'],
            'username': res_nsx['credentials']['username'],
            'entity_id': res_nsx['entity_id'],
            'proxy_id': res_nsx['proxy_id'],
            'enabled': res_nsx['enabled']
        }
        data_source_configs.append(nsx_configs)
        logger.info('Name : \t\t{}'.format(res_nsx['nickname']))
        logger.info('Username : \t{}'.format(res_nsx['credentials']['username']))
        logger.info('EntityID : \t{}'.format(res_nsx['entity_id']))
        logger.info('ProxyID : \t{}'.format(res_nsx['proxy_id']))
        logger.info('Enabled : \t{}'.format(res_nsx['enabled']))
        logger.info('')

    config_dump = {
        'product': 'vrni',
        'nodes': node_configs,
        'datasources': data_source_configs,
    }

    return config_dump


def get_vrli_configs(config):
    cfg = config['vrli']
    VRLI_IPADDR = cfg['vip_address']
    VRLI_USERNAME = cfg['user_name']
    VRLI_PASSWORD = cfg['password']
    VRLI_PROVIDER = 'Local'

    logger.info('--- Collect data from vRLI: {}'.format(VRLI_IPADDR))
    vrli = VRli(
        ipaddress=VRLI_IPADDR,
        username=VRLI_USERNAME,
        password=VRLI_PASSWORD,
        provider=VRLI_PROVIDER
    )
    version_info = vrli.get('/api/v1/version')
    cluster_info = vrli.get('/api/v1/cluster/vips')
    node_info = vrli.get('/api/v1/cluster/nodes')
    ntp_info = vrli.get('/api/v1/time/config')
    cp_info = vrli.get('/api/v1/content/contentpack/list')

    logger.info('>>> Version information')
    version_configs = {
        'version': version_info['version'],
        'release_type': version_info['releaseName']
    }
    logger.info('{0} (Release Type: {1})'.format(version_info['version'], version_info['releaseName']))
    logger.info('')

    logger.info('>>> Deployment configurations ...')
    logger.info('> vIP : {0} (FQDN : {1})'.format(cluster_info['vips'][0]['ipAddress'], cluster_info['vips'][0]['fqdn']))
    logger.info('')
    logger.info('> nodes')
    cluster_configs = []
    for node in node_info['nodes']:
        node_conf = {
            'node_id': node['id'],
            'ipaddress': node['ip'],
            'netmask': node['netmask'],
            'gateway': node['gateway'],
            'dns': node['dnsServers'],
            'ntp': ntp_info['ntpConfig']['ntpServers']
        }
        cluster_configs.append(node_conf)
        logger.info('Node ID: {}'.format(node['id']))
        logger.info('IP Address: {}'.format(node['ip']))
        logger.info('Subnet: {}'.format(node['netmask']))
        logger.info('Gateway: {}'.format(node['gateway']))
        logger.info('DNS Server: {}'.format(node['dnsServers']))
    logger.info('NTP Servers : {}'.format(ntp_info['ntpConfig']['ntpServers']))
    logger.info('')

    logger.info('>>> Content Pack configured ...')
    content_packs = []
    for cp in cp_info['contentPackMetadataList']:
        content_pack = {
            'name': cp['name'],
            'format_version': cp['formatVersion'],
            'content_version': cp['contentVersion']
        }
        content_packs.append(content_pack)
        logger.info('{0} (formatVersion: {1}, contentVersion: {2})'.format(cp['name'], cp['formatVersion'], cp['contentVersion']))

    config_dump = {
        'product': 'vrli',
        'version': version_configs,
        'network': {
            'vip': {
                'ipaddress': cluster_info['vips'][0]['ipAddress'],
                'fqdn': cluster_info['vips'][0]['ipAddress']
                },
            'nodes': cluster_configs
        },
        'content_packs': content_packs
    }

    return config_dump


def get_vrops_configs(config):
    cfg = config['vrops']
    VROPS_IPADDR = cfg['master_node_ip']
    VROPS_USERNAME = cfg['node_user_name']
    VROPS_PASSWORD = cfg['node_admin_password']

    logger.info('--- Collect data from vROps: {}'.format(VROPS_IPADDR))
    vrops = VROps(
        ipaddress=VROPS_IPADDR,
        username=VROPS_USERNAME,
        password=VROPS_PASSWORD
    )

    # Fetch all info from CaSA API
    cluster_conf = vrops.casa_get('/casa/cluster/config')
    ip_conf = vrops.casa_get('/casa/node/status')
    # Fetch all info from Suite API
    versions = vrops.get('/suite-api/api/versions/current')
    mp_info = vrops.get('/suite-api/api/solutions')
    adapter_info = vrops.get('/suite-api/api/adapters')

    logger.info('>>> Version information')
    version_configs = {
        'version': versions['releaseName'],
        'release_date': versions['humanlyReadableReleaseDate']
    }
    logger.info('{}'.format(versions['releaseName']))
    logger.info('Release Date: {}'.format(versions['humanlyReadableReleaseDate']))
    logger.info('')

    logger.info('>>> Cluster configurations')
    cluster_configs = []
    for node in cluster_conf['slices']:
        node_conf = {
            'nodename': node['node_name'],
            'deploy_role': node['node_type'],
            'ipaddress': ip_conf['address'],
            'netmask': node['network_properties']['network1_netmask'],
            'gateway': node['network_properties']['default_gateway'],
            'dns': {
                'nameservers': node['network_properties']['domain_name_servers'],
                'domain_name': node['network_properties']['domain_name']
            },
            'ntp': node['ntp_servers']
        }
        cluster_configs.append(node_conf)

        logger.info('Node: {}'.format(node['node_name']))
        logger.info('Deployment Role: {}'.format(node['node_type']))
        logger.info('IP Address: \t{}'.format(ip_conf['address']))
        logger.info('Netmask: {}'.format(node['network_properties']['network1_netmask']))
        logger.info('Gateway: {}'.format(node['network_properties']['default_gateway']))
        logger.info('DNS Servers: \t{}'.format(node['network_properties']['domain_name_servers']))
        logger.info('Domain Name: \t{}'.format(node['network_properties']['domain_name']))
        logger.info('NTP Servers: \t{}'.format(node['ntp_servers']))
        logger.info('')

    logger.info('>>> Installed Management Packs')
    management_packs = []
    for mp in mp_info['solution']:
        mp = {
            'name': mp['name'],
            'version': mp['version']
        }
        management_packs.append(mp)
        logger.info('{0} (Version : {1})'.format(mp['name'], mp['version']))

    logger.info('')

    logger.info('>>> Configured Adapters')
    adapters = []
    for adapter in adapter_info['adapterInstancesInfoDto']:
        adptr = {
            'name': adapter['resourceKey']['name'],
            'id': adapter['id']
        }
        adapters.append(adptr)
        logger.info('ID: {0}, Name: {1}'.format(adapter['id'], adapter['resourceKey']['name']))

    config_dump = {
        'product': 'vrops',
        'versions': version_configs,
        'network': cluster_configs,
        'mangement_packs': management_packs,
        'adapters': adapters
    }
    return config_dump


if __name__ == "__main__":

    TIMESTAMP = datetime.now().strftime('%Y%m%d_%H%M%S')

    # Log file validations
    LOG_DIR = './logs'
    if not os.path.exists(LOG_DIR):
        os.mkdir(LOG_DIR)
    LOG_FILENAME = '{}_nfvstack_collector.log'.format(TIMESTAMP)
    LOG_FILE_PATH = os.path.join(LOG_DIR, LOG_FILENAME)

    # Basic log handler
    _detail_formatting = '%(asctime)s : %(name)s - %(levelname)s : %(message)s'
    logging.basicConfig(
        level=logging.DEBUG,
        format=_detail_formatting,
        filename=LOG_FILE_PATH)
    logging.getLogger('modules').setLevel(level=logging.DEBUG)
    console = logging.StreamHandler()
    logger = logging.getLogger(__name__)
    logging.getLogger(__name__).addHandler(console)

    logger.info('>>> Logfile : [ {} ]'.format(LOG_FILE_PATH))

    # Input file validations
    CONFIG_FILE_PATH = './InputFile-NFVStack.yaml'
    if os.path.exists(CONFIG_FILE_PATH):
        logger.info('>>> Loading input parameter file : [ {} ]'.format(CONFIG_FILE_PATH))
        configs = read_config_from_file(conf_file_path=CONFIG_FILE_PATH)
    else:
        logger.error('Provided configuration file path is wrong.')
        logger.error('Configuration file is expected to be allocated on: {} '.format(CONFIG_FILE_PATH))
        sys.exit(1)

    logger.info('>>> Start collecting configurations, this might take some time ...')
    logger.info('')
    logger.info('--------------------------------------------------------------------')
    logger.info('### M-Plane vCenter Server ')
    vcenter_configs = get_vcenter_configs(config=configs.get('management'))
    logger.info('')
    logger.info('### C-Plane vCenter Server ')
    vcenter_configs = get_vcenter_configs(config=configs.get('c_plane'))
    logger.info('')
    logger.info('--------------------------------------------------------------------')
    logger.info('### C-Plane NSX-T Manager')
    nsxt_configs = get_nsxt_configs(config=configs.get('c_plane'))
    logger.info('')
    logger.info('--------------------------------------------------------------------')
    logger.info('### C-Plane VMware Integrated OpenStack')
    vio_config_dump = export_config_to_file(
        dump_data=get_vio_configs(config=configs.get('c_plane')),
        timestamp=TIMESTAMP
    )
    logger.info('\n--- C-Plane VIO config exported : {}'.format(vio_config_dump))
    logger.info('--------------------------------------------------------------------')
    logger.info('### C-Plane vRealize Operations Manager')
    vrops_config_dump = export_config_to_file(
        dump_data=get_vrops_configs(config=configs.get('c_plane')),
        timestamp=TIMESTAMP
    )
    logger.info('\n--- C-Plane vROps config exported : {}'.format(vrops_config_dump))
    logger.info('--------------------------------------------------------------------')
    logger.info('### C-Plane vRealize Log Insight')
    vrli_config_dump = export_config_to_file(
        dump_data=get_vrli_configs(config=configs.get('c_plane')),
        timestamp=TIMESTAMP
    )
    logger.info('\n--- C-Plane vRLI config exported : {}'.format(vrli_config_dump))
    logger.info('--------------------------------------------------------------------')
    logger.info('### C-Plane vRealize Network Insight')
    vrni_config_dump = export_config_to_file(
        dump_data=get_vrni_configs(config=configs.get('c_plane')),
        timestamp=TIMESTAMP
    )
    logger.info('\n--- C-Plane vRNI config exported : {}'.format(vrni_config_dump))
    logger.info('--------------------------------------------------------------------')
    logger.info('')
    logger.info('>>> All configuration dumped !!')
    # TODO: print path of logfile and dumped file as stdout

    sys.exit(0)
