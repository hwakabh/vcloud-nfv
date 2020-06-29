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
    EXPORT_PATH = './{}_nfvconfig'.format(timestamp)
    if not os.path.exists(EXPORT_PATH):
        os.mkdir(EXPORT_PATH)
    target_product = dump_data['product']
    dump_file_name = '{0}/{1}_{2}_config.json'.format(EXPORT_PATH, timestamp, target_product)
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
    logger.info('--- Collect data from vRNI: {}'.format(cfg['hostname']))
    vrni = VRni(
        ipaddress=cfg['hostname'],
        username=cfg['user_name'],
        password=cfg['password'],
        domain=cfg['domain']
    )

    logger.info('\n>>> Version information')
    version_configs = {
        'version': vrni.get_base_version(),
        'api_version': vrni.get_api_version()
    }
    for k, v in version_configs.items():
        logger.info('{0}: \t{1}'.format(k, v))

    logger.info('\n>>> Node configurations')
    node_config = vrni.get_node_configs()
    for line in node_config:
        logger.info('{0}: \t{1}'.format(line.split(': ')[0], line.split(': ')[1]))

    logger.info('\n>>> Node roles')
    node_roles = vrni.get_node_role()
    for node in node_roles:
        for k, v in node.items():
            logger.info('{0}: \t{1}'.format(k, v))

    logger.info('\n>>> Data sources')
    data_source_vcenter = vrni.get_vcenter_source()
    data_source_nsx = vrni.get_nsx_source()
    for ds in data_source_vcenter:
        for k, v in ds.items():
            logger.info('{0}: \t{1}'.format(k, v))
    logger.info('')
    for ds in data_source_nsx:
        for k, v in ds.items():
            logger.info('{0}: \t{1}'.format(k, v))

    config_dump = {
        'product': 'vrni',
        'versions': version_configs,
        'nodes': {
            'network': node_config,
            'role': node_roles
        },
        'datasources': {
            'vcenter': data_source_vcenter,
            'nsx': data_source_nsx
        }
    }

    return config_dump


def get_vrli_configs(config):
    cfg = config['vrli']
    logger.info('--- Collect data from vRLI: {}'.format(cfg['vip_address']))
    vrli = VRli(
        ipaddress=cfg['vip_address'],
        username=cfg['user_name'],
        password=cfg['password'],
        provider='Local'
    )

    logger.info('\n>>> Version information')
    version_configs = vrli.get_version()
    for k, v in version_configs.items():
        logger.info('{0}: {1}'.format(k, v))

    logger.info('\n>>> Cluster configurations')
    cluster_configs = vrli.get_cluster_configs()
    ntp_severs = vrli.get_ntp_server()
    for k, v in cluster_configs.items():
        logger.info('{0}: {1}'.format(k, v))
    logger.info('NTP Servers: {}'.format(ntp_severs))

    logger.info('\n>>> Node configurations')
    node_configs = vrli.get_node_configs()
    for node in node_configs:
        for k, v in node.items():
            logger.info('{0}: {1}'.format(k, v))

    logger.info('\n>>> Content Pack configured ...')
    cp_configs = vrli.get_contents_pack_configs()
    for cp in cp_configs:
        logger.info('{0} (Version: {1} )'.format(cp['name'], cp['content_version']))

    config_dump = {
        'product': 'vrli',
        'version': version_configs,
        'cluster': {
            'vip': cluster_configs,
            'ntp_server': ntp_severs
        },
        'nodes': node_configs,
        'content_packs': cp_configs
    }
    return config_dump


def get_vrops_configs(config):
    cfg = config['vrops']
    logger.info('--- Collect data from vROps: {}'.format(cfg['master_node_ip']))
    vrops = VROps(
        ipaddress=cfg['master_node_ip'],
        username=cfg['node_user_name'],
        password=cfg['node_admin_password']
    )

    # Fetch all info from CaSA API
    cluster_conf = vrops.casa_get('/casa/cluster/config')
    ip_conf = vrops.casa_get('/casa/node/status')
    # Fetch all info from Suite API
    # versions = vrops.get('/suite-api/api/versions/current')
    # mp_info = vrops.get('/suite-api/api/solutions')
    adapter_info = vrops.get('/suite-api/api/adapters')

    logger.info('\n>>> Version information')
    version_configs = vrops.get_version()
    for k, v in version_configs.items():
        logger.info('{0}: {1}'.format(k, v))

    logger.info('\n>>> Cluster configurations')
    cluster_configs = vrops.get_cluster_configs()
    for node in cluster_configs:
        for k, v in node.items():
            logger.info('{0}: {1}'.format(k, v))
        logger.info('')

    logger.info('\n>>> Installed Management Packs')
    mp_configs = vrops.get_management_pack_configs()
    for mp in mp_configs:
        logger.info('{0} ( Version: {1} )'.format(mp['name'], mp['version']))

    logger.info('\n>>> Configured Adapters')
    adapter_configs = vrops.get_adpater_configs()
    for adapter in adapter_configs:
        logger.info('ID: {0} ( {1} )'.format(adapter['id'], adapter['name']))

    config_dump = {
        'product': 'vrops',
        'versions': version_configs,
        'network': cluster_configs,
        'mangement_packs': mp_configs,
        'adapters': adapter_configs
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
    logger.info('>>> All configuration dumped !!')
    logger.info('Dumped configuration files : [ ./{}_nfvconfig/*_config.json ]'.format(TIMESTAMP))

    sys.exit(0)
