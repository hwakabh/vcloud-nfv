import yaml
import sys
import os
import json

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


def get_vcenter_configs(config):
    cfg = config['vcenter']
    IPADDRESS, USERNAME, PASSWORD = cfg['ip_address'], cfg['user_name'], cfg['sso_password']

    print('------ Starting config_dump for vCSA: {}'.format(IPADDRESS))
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

    print('>>> Appliance configurations ...')
    print('Version: \t{0} (Build : {1})'.format(vcsa_version['value']['version'], vcsa_version['value']['build']))
    print('IP address: \t{}'.format(vcsa_networks['value'][0]['ipv4']['address']))
    print('Subnet Prefix: \t{}'.format(vcsa_networks['value'][0]['ipv4']['prefix']))
    print('Gateway: \t{}'.format(vcsa_networks['value'][0]['ipv4']['default_gateway']))
    print('Hostname: \t{}'.format(vcsa_hostnames['value']))
    print('DNS Servers: \t{}'.format(vcsa_dns['value']['servers']))
    print('NTP Servers: \t{}'.format(vcsa_ntp['value']))
    print('SSH Services: \t{}'.format('Running' if vcsa_ssh_status['value'] == True else 'Not Running'))

    print('>>> vCHA configurations ...')
    print('Status : {}'.format(vcsa_ha['value']))

    print()

    for dc in vcsa_dc['value']:
        print('>>> Datacenter: {}'.format(dc['name']))
    for cluster in vcsa_clusters['value']:
        print('>>> Cluster : {}'.format(cluster['name']))
        print('DRS Enabled:\t{}'.format(cluster['drs_enabled']))
        print('HA Enabled:\t{}'.format(cluster['ha_enabled']))
        print('>>>>>> Managed ESXi Host configs')
        vcsa_hosts = vc.get('/rest/vcenter/host?filter.clusters={}'.format(cluster['cluster']))
        for host in vcsa_hosts['value']:
            esxi_parser = EsxiSoapParser()
            host_info = dict()
            print('>>>>>>>>> {}'.format(host['name']))
            target_host = [esxi for esxi in esxis if esxi.name == host['name']][0]
            version, build, apiversion = esxi_parser.get_host_system_version(target_host)
            print('Host Version: {0} (Build {1})'.format(version, build))
            print('API Version: {}'.format(apiversion))
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
            print('vmnics:')
            for vmnic in host_pnics:
                print('\t[ {0} ] MAC addr= {1}, driver={2}'.format(vmnic['device'], vmnic['mac'], vmnic['driver']))
            print('vmkernel ports:')
            for vmk in host_vnics:
                # TODO: merge info about vmk gateway
                print('\t[ {0} ] IP Address= {1}, Subnet Mask={2}, MAC addr={3}, MTU={4}'.format(vmk['device'], vmk['ipAddress'], vmk['subnetMask'], vmk['mac'], vmk['mtu']))
            print('vSwitch(vSS):')
            for vss in host_vswitches:
                print('\t[ {0} ] Uplinks={1}, PortGroups={2}, MTU={3}'.format(vss['name'], vss['pnics'], vss['portgroups'], vss['mtu']))
            print('portgroups:')
            for pg in host_portgroups:
                print('\t[ {0} ] VLAN={1}, vSwitchName={2}'.format(pg['name'], pg['vlanId'], pg['vswitchName']))

            nameservers, searchpath = esxi_parser.get_host_dns_config(target_host)
            print('DNS Servers:')
            for ns in nameservers:
                print('  {}'.format(ns))
            print('DNS Search Path:')
            for sp in searchpath:
                print('  {}'.format(sp))
            ntp_severs = esxi_parser.get_host_ntp_config(target_host)
            print('NTP servers:')
            for ntp in ntp_severs:
                print('  {}'.format(ntp))
            print('SSH service : {}'.format(esxi_parser.get_host_ssh_status(target_host)))
            print()

    print('>>> vDS configs')
    for dvs in vds_configs:
        print('Name : {}'.format(dvs.name))
        print('Configured hosts: ')
        for member_host in dvs.config.host:
            print('  {}'.format(member_host.config.host.name))
        print('dvPortGroups: ')
        for dvportgroup in dvs.config.uplinkPortgroup:
            print('  {}'.format(dvportgroup.name))
        print('Uplinks configured: ')
        for uplink in dvs.config.uplinkPortPolicy.uplinkPortName:
            print('  {}'.format(uplink))
        print('Port Groups: ')
        for pg in dvs.portgroup:
            if type(pg.config.defaultPortConfig.vlan.vlanId) == int:
                print('  {0} ( VLAN: {1} )'.format(pg.name, pg.config.defaultPortConfig.vlan.vlanId))
        print()

    print('>>> vSAN Cluster configs')
    for vsan_host in esxis:
        print('>>>>>> {}'.format(vsan_host.name))
        print('Cluster UUID: {}'.format(vsan_host.configManager.vsanSystem.config.clusterInfo.uuid))
        print('Node UUID: {}'.format(vsan_host.configManager.vsanSystem.config.clusterInfo.nodeUuid))
        disk_config = vsan_host.config.vsanHostConfig.storageInfo.diskMapping
        print('Disk Group: {}'.format(disk_config[0].ssd.vsanDiskInfo.vsanUuid))
        for disk in disk_config:
            print('Disk Claimed: ')
            print('> Flash')
            print('  {}'.format(disk.ssd.displayName))
            print('> HDD')
            for non_ssd in disk.nonSsd:
                print('  {}'.format(non_ssd.displayName))
        print()


    # TODO: Return JSON value with parsed
    return None


def get_nsxt_configs(config):
    cfg = config['nsxt']
    NSX_MGR, NSX_USERNAME, NSX_PASSWORD = cfg['ip_address'], cfg['admin_user_name'], cfg['admin_password']

    print('------ Starting config_dump for NSX-T Manager: {}'.format(NSX_MGR))
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

    print('>>> Version information')
    print('Product Version: \t{}'.format(hostname['product_version']))
    print('Kernel Version: \t{}'.format(hostname['kernel_version']))
    print()

    # Fetch only management network information
    print('>>> Management Network information')
    for net in mgmt_networks['results']:
        print('Interface: \t{0} (Physical Address: {1})'.format(net['interface_id'], net['physical_address']))
        print('IP Address: \t{}'.format(net['ip_addresses'][0]['ip_address']))
        print('Netmask: \t{}'.format(net['ip_addresses'][0]['netmask']))
        if 'default_gateway' in net:
            print('Gateway: \t{}'.format(net['default_gateway']))
        print('MTU: \t\t{}'.format(net['mtu']))
        print()

    print('>>> Cluster-wide information')
    print('vIP: \t\t\t{}'.format(vip['ip_address']))
    print('Cluster UUID: \t\t{}'.format(cluster['cluster_id']))
    print('DNS Servers: \t\t{}'.format(dns['name_servers']))
    print('DNS Search Path: \t{}'.format(domains['search_domains']))
    print('NTP Servers: \t\t{}'.format(ntp['service_properties']['servers']))
    print('SSH auto start: \t{}'.format(ssh['service_properties']['start_on_boot']))
    print()

    print('>>> Mangement Cluster')
    for i, node in enumerate(cluster['nodes']):
        print('Node-{0} FQDN: \t{1}'.format(i+1, node['fqdn']))
        print('UUID: \t\t{}'.format(node['node_uuid']))
        print('IP Address: \t{}'.format(node['entities'][0]['ip_address']))
        print()

    print('>>> Edge Cluster information')
    print('Name: \t{}'.format(edge_cluster['results'][0]['display_name']))
    print('ID: \t{}'.format(edge_cluster['results'][0]['id']))
    print()
    print('>>> Edge Nodes')
    for edge_node in edge_nodes['members']:
        print('Name: \t{}'.format(edge_node['node_display_name']))
        print('UUID: \t{}'.format(edge_node['node_id']))
        print()

    print('>>> Transport-Zone information')
    overlay_tzs = [otz for otz in transport_zones['results'] if otz['transport_type'] == 'OVERLAY']
    print('>>>>>> Overlay transport-zones')
    for overlay_tz in overlay_tzs:
        print('Name: \t\t{}'.format(overlay_tz['display_name']))
        print('UUID: \t\t{}'.format(overlay_tz['id']))
        print('N-vDS Mode: \t{}'.format(overlay_tz['host_switch_mode']))
        print()

    vlan_tzs = [vtz for vtz in transport_zones['results'] if vtz['transport_type'] == 'VLAN']
    print('>>>>>> VLAN transport-zones')
    for vlan_tz in vlan_tzs:
        print('Name: \t\t{}'.format(vlan_tz['display_name']))
        print('UUID: \t\t{}'.format(vlan_tz['id']))
        print('N-vDS Mode: \t{}'.format(vlan_tz['host_switch_mode']))
        print()

    print('>>> Transport Nodes information')
    print('>>>>> Host transport-nodes')
    for htn in host_transport_nodes['results']:
        print('Name: \t\t{}'.format(htn['display_name']))
        print('UUID: \t\t{}'.format(htn['id']))
        print('OS Type: \t{}'.format(htn['node_deployment_info']['os_type']))
        print('IP Address: \t{}'.format(htn['node_deployment_info']['ip_addresses'][0]))
        print('N-vDS Name: \t{}'.format(htn['host_switch_spec']['host_switches'][0]['host_switch_name']))
        print()
    print('>>>>>> Edge transport-nodes')
    for etn in edge_transport_nodes['results']:
        print('Name: \t\t\t{}'.format(etn['display_name']))
        print('UUID: \t\t\t{}'.format(etn['id']))
        print('Deployment Type: \t{}'.format(etn['node_deployment_info']['deployment_type']))
        print('Form Factor: \t\t{}'.format(etn['node_deployment_info']['deployment_config']['form_factor']))
        print('IP Address: \t\t{}'.format(etn['node_deployment_info']['ip_addresses'][0]))
        print('FQDN: \t\t\t{}'.format(etn['node_deployment_info']['node_settings']['hostname']))

        print('N-vDS Name: \t\t{}'.format(etn['host_switch_spec']['host_switches'][0]['host_switch_name']))
        print()

    print('>>> IP Pool information')
    for pool in ip_pools['results']:
        print('Name: {}'.format(pool['display_name']))
        print('UUID: {}'.format(pool['id']))
        print('Subnets:')
        for subnet in pool['subnets']:
            print('  CIDR={0}, Range=[ {1} - {2} ]'.format(subnet['cidr'], subnet['allocation_ranges'][0]['start'], subnet['allocation_ranges'][0]['end']))
        print('Usage: total={0}, allocated={1}, free={2}'.format(pool['pool_usage']['total_ids'], pool['pool_usage']['allocated_ids'], pool['pool_usage']['free_ids']))
        print()

    print('>>> Tier-0 Routers')
    for tier_0 in tier_0s['results']:
        print('Name: \t\t{}'.format(tier_0['display_name']))
        print('UUID: \t\t{}'.format(tier_0['unique_id']))
        print('HA Mode: \t{}'.format(tier_0['ha_mode']))
        print('Failover Mode: \t{}'.format(tier_0['failover_mode']))
        print()

    print('>>> DHCP Server Profiles')
    for dhcp_server in dhcp_servers['results']:
        print('Name: \t\t\t{}'.format(dhcp_server['display_name']))
        print('UUID: \t\t\t{}'.format(dhcp_server['unique_id']))
        print('Server Address: \t{}'.format(dhcp_server['server_address']))
        edge = nsx.get('/policy/api/v1{}'.format(dhcp_server['edge_cluster_path']))
        print('Edge Cluster: \t\t{}'.format(edge['display_name']))
        print()

    print('>>> Metadata Proxies')
    for mk_proxy in mk_proxies['results']:
        print('Name: \t\t\t{}'.format(mk_proxy['display_name']))
        print('UUID: \t\t\t{}'.format(mk_proxy['unique_id']))
        print('Server Address: \t{}'.format(mk_proxy['server_address']))
        edge = nsx.get('/policy/api/v1{}'.format(dhcp_server['edge_cluster_path']))
        print('Edge Cluster: \t\t{}'.format(edge['display_name']))
        print()

    # Return JSON value with parsed
    return None


def get_vio_configs(config):
    cfg = config['vio']
    VIO_MGR, VIO_USERNAME, VIO_PASSWORD = cfg['management_ip'], cfg['user_name'], cfg['vio_admin_password']

    print('------ Starting config_dump for VIO Manager: {}'.format(VIO_MGR))
    viomgr = Vio(ipaddress=VIO_MGR, username=VIO_USERNAME, password=VIO_PASSWORD)
    vio_networks = viomgr.get('/apis/vio.vmware.com/v1alpha1/namespaces/openstack/vioclusters/viocluster1')
    vio_nodes = viomgr.get('/api/v1/nodes')

    print('>>> Network information ...')
    print('> Management Network')
    print('IP Ranges: \t{}'.format(vio_networks['spec']['cluster']['network_info'][0]['static_config']['ip_ranges']))
    print('Netmask: \t{}'.format(vio_networks['spec']['cluster']['network_info'][0]['static_config']['netmask']))
    print('Gateway: \t{}'.format(vio_networks['spec']['cluster']['network_info'][0]['static_config']['gateway']))
    print('DNS Servers: \t{}'.format(vio_networks['spec']['cluster']['network_info'][0]['static_config']['dns']))
    print()
    print('> API Network')
    print('IP Ranges: \t{}'.format(vio_networks['spec']['cluster']['network_info'][1]['static_config']['ip_ranges']))
    print('Netmask: \t{}'.format(vio_networks['spec']['cluster']['network_info'][1]['static_config']['netmask']))
    print('Gateway: \t{}'.format(vio_networks['spec']['cluster']['network_info'][1]['static_config']['gateway']))
    print('DNS Servers: \t{}'.format(vio_networks['spec']['cluster']['network_info'][1]['static_config']['dns']))
    print()
    print('> manager/controller nodes')
    for node in vio_nodes['items']:
        print('Nodename: \t{}'.format(node['metadata']['name']))
        print('  PodCIDR: \t{}'.format(node['spec']['podCIDR']))
        print('  IntIP: \t{}'.format(node['status']['addresses'][0]['address']))
        print('  ExtIP: \t{}'.format(node['status']['addresses'][1]['address']))
    # TODO: Research NTP API Endpoints for Kubernetes

    return None


def get_vrni_configs(config):
    cfg = config['vrni']
    VRNI_IPADDR, VRNI_USERNAME, VRNI_PASSWORD = cfg['hostname'], cfg['user_name'], cfg['password']
    VRNI_DOMAIN = cfg['domain']

    print('------ Starting config_dump for vRNI: {}'.format(VRNI_IPADDR))
    vrni = VRni(ipaddress=VRNI_IPADDR, username=VRNI_USERNAME, password=VRNI_PASSWORD, domain=VRNI_DOMAIN)
    version_info = vrni.get('/api/ni/info/version')
    nodes_info = vrni.get('/api/ni/infra/nodes')
    ds_vcenter = vrni.get('/api/ni/data-sources/vcenters')
    ds_nsxmgr = vrni.get('/api/ni/data-sources/nsxt-managers')

    print('>>> Version information')
    print('API Version : {0}'.format(version_info['api_version']))
    print()

    print('>>> Nodes information')
    # Fetch all node ids configured
    ni_node_ids = [i['id'] for i in nodes_info['results']]
    for node_id in ni_node_ids:
        node = vrni.get('/api/ni/infra/nodes/{}'.format(node_id))
        print('Node ID: {0} (internal: {1})'.format(node['id'], node['node_id']))
        print('IP Address: {}'.format(node['ip_address']))
        print('Deployment Role: {}'.format(node['node_type']))
    print()
    print('>>> Data sources')
    print('> vCenter Servers:')
    vcenters = [vc['entity_id'] for vc in ds_vcenter['results']]
    for vcenter in vcenters:
        res_vc = vrni.get('/api/ni/data-sources/vcenters/{}'.format(vcenter))
        print('Name : \t\t{0} (FQDN : {1})'.format(res_vc['nickname'], res_vc['fqdn']))
        print('Username : \t{}'.format(res_vc['credentials']['username']))
        print('EntityID : \t{}'.format(res_vc['entity_id']))
        print('ProxyID : \t{}'.format(res_vc['proxy_id']))
        print('Enabled : \t{}'.format(res_vc['enabled']))
        print()
    print('> NSX-T Managers:')
    nsxmgrs = [nsxmgr['entity_id'] for nsxmgr in ds_nsxmgr['results']]
    for nsx in nsxmgrs:
        res_nsx = vrni.get('/api/ni/data-sources/nsxt-managers/{}'.format(nsx))
        print('Name : \t\t{}'.format(res_nsx['nickname']))
        print('Username : \t{}'.format(res_nsx['credentials']['username']))
        print('EntityID : \t{}'.format(res_nsx['entity_id']))
        print('ProxyID : \t{}'.format(res_nsx['proxy_id']))
        print('Enabled : \t{}'.format(res_nsx['enabled']))
        print()

    # TODO: Return JSON value with parsed
    return None


def get_vrli_configs(config):
    cfg = config['vrli']
    VRLI_IPADDR, VRLI_USERNAME, VRLI_PASSWORD = cfg['vip_address'], cfg['user_name'], cfg['password']
    VRLI_PROVIDER = 'Local'

    print('------ Starting config_dump for vRLI: {}'.format(VRLI_IPADDR))
    vrli = VRli(ipaddress=VRLI_IPADDR, username=VRLI_USERNAME, password=VRLI_PASSWORD, provider=VRLI_PROVIDER)
    version_info = vrli.get('/api/v1/version')
    cluster_info = vrli.get('/api/v1/cluster/vips')
    node_info = vrli.get('/api/v1/cluster/nodes')
    ntp_info = vrli.get('/api/v1/time/config')
    cp_info = vrli.get('/api/v1/content/contentpack/list')

    print('>>> Version information')
    print('{0} (Release Type: {1})'.format(version_info['version'], version_info['releaseName']))
    print()

    print('>>> Deployment configurations ...')
    print('> vIP : {0} (FQDN : {1})'.format(cluster_info['vips'][0]['ipAddress'], cluster_info['vips'][0]['fqdn']))
    print()
    print('> nodes')
    for node in node_info['nodes']:
        print('Node ID: {}'.format(node['id']))
        print('IP Address: {}'.format(node['ip']))
        print('Subnet: {}'.format(node['netmask']))
        print('Gateway: {}'.format(node['gateway']))
        print('DNS Server: {}'.format(node['dnsServers']))
    print('NTP Servers : {}'.format(ntp_info['ntpConfig']['ntpServers']))
    print()

    print('>>> Content Pack configured ...')
    for cp in cp_info['contentPackMetadataList']:
        print('{0} (formatVersion: {1}, contentVersion: {2})'.format(cp['name'], cp['formatVersion'], cp['contentVersion']))

    # TODO: Should be return JSON value simplified
    return None


def get_vrops_configs(config):
    cfg = config['vrops']
    VROPS_IPADDR, VROPS_USERNAME, VROPS_PASSWORD = cfg['master_node_ip'], cfg['node_user_name'], cfg['node_admin_password']

    print('------ Starting config_dump for vROps: {}'.format(VROPS_IPADDR))
    # Instanciate vROps class
    vrops = VROps(ipaddress=VROPS_IPADDR, username=VROPS_USERNAME, password=VROPS_PASSWORD)

    # Fetch all info from CaSA API
    cluster_conf = vrops.casa_get('/casa/cluster/config')
    ip_conf = vrops.casa_get('/casa/node/status')
    # Fetch all info from Suite API
    versions = vrops.get('/suite-api/api/versions/current')
    mp_info = vrops.get('/suite-api/api/solutions')
    adapter_info = vrops.get('/suite-api/api/adapters')

    print('>>> Version information')
    print('{}'.format(versions['releaseName']))
    print('Release Date: {}'.format(versions['humanlyReadableReleaseDate']))
    print()

    print('>>> Cluster configurations')
    for node in cluster_conf['slices']:
        print('Node: {}'.format(node['node_name']))
        print('IP Address: \t{}'.format(ip_conf['address']))
        print('Deployment Role: {}'.format(node['node_type']))
        print('Netmask: {}'.format(node['network_properties']['network1_netmask']))
        print('Gateway: {}'.format(node['network_properties']['default_gateway']))
        print('DNS Servers: \t{}'.format(node['network_properties']['domain_name_servers']))
        print('Domain Name: \t{}'.format(node['network_properties']['domain_name']))
        print('NTP Servers: \t{}'.format(node['ntp_servers']))
        print()

    print('>>> Installed Management Packs')
    for mp in mp_info['solution']:
        print('{0} (Version : {1})'.format(mp['name'], mp['version']))

    print()

    print('>>> Configured Adapters')
    for adapter in adapter_info['adapterInstancesInfoDto']:
        print('ID: {0}, Name: {1}'.format(adapter['id'], adapter['resourceKey']['name']))

    # TODO: Should be return JSON value simplified
    return None


if __name__ == "__main__":

    CONFIG_FILE_PATH = './InputFile-NFVStack.yaml'
    if os.path.exists(CONFIG_FILE_PATH):
        print('>>> Loading input parameter file : [ {} ]'.format(CONFIG_FILE_PATH))
        configs = read_config_from_file(conf_file_path=CONFIG_FILE_PATH)
    else:
        print('Provided configuration file path is wrong.')
        print('Configuration file is expected to be allocated on: {} '.format(CONFIG_FILE_PATH))
        sys.exit(1)

    print('>>> Start collecting configurations, this might take some time ...')
    print()
    print('--------------------------------------------------------------------')
    print('### M-Plane vCenter Server ')
    vcenter_configs = get_vcenter_configs(config=configs.get('management'))
    print()
    print('### C-Plane vCenter Server ')
    vcenter_configs = get_vcenter_configs(config=configs.get('c_plane'))
    print()
    print('--------------------------------------------------------------------')
    print('### C-Plane NSX-T Manager')
    nsxt_configs = get_nsxt_configs(config=configs.get('c_plane'))
    print()
    print('--------------------------------------------------------------------')
    print('### C-Plane VMware Integrated OpenStack')
    vio_configs = get_vio_configs(config=configs.get('c_plane'))
    print()
    print('--------------------------------------------------------------------')
    print('### C-Plane vRealize Operations Manager')
    vrops_configs = get_vrops_configs(config=configs.get('c_plane'))
    print()
    print('--------------------------------------------------------------------')
    print('### C-Plane vRealize Log Insight')
    vrli_configs = get_vrli_configs(config=configs.get('c_plane'))
    print()
    print('--------------------------------------------------------------------')
    print('### C-Plane vRealize Network Insight')
    vrni_configs = get_vrni_configs(config=configs.get('c_plane'))
    print()
    print('--------------------------------------------------------------------')
    print()
    print('>>> All configuration dumped !!')
    # TODO: print path of logfile and dumped file as stdout

    sys.exit(0)
