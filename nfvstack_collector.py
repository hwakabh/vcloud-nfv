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
    logger.info('--- Collect data from VIO Manager: {}'.format(cfg['ip_address']))
    nsx = Nsxt(
        ipaddress=cfg['ip_address'],
        username=cfg['admin_user_name'],
        password=cfg['admin_password']
    )

    logger.info('\n>>> Version information')
    version_configs = nsx.get_version()
    for k, v in version_configs.items():
        logger.info('{0}: {1}'.format(k, v))

    logger.info('\n>>> Management Network configuration')
    mgmt_network_configs = nsx.get_mgmt_network_configs()
    for mgmt_network in mgmt_network_configs:
        for k, v in mgmt_network.items():
            logger.info('{0}: {1}'.format(k, v))
        logger.info('')

    logger.info('\n>>> Cluster-wide configurations')
    cluster_wide_configs = nsx.get_cluster_wide_configs()
    for k, v in cluster_wide_configs.items():
        logger.info('{0}: {1}'.format(k, v))

    logger.info('\n>>> MangementCluster nodes configurations')
    mgmt_nodes_configs = nsx.get_mgmt_nodes_configs()
    for mgmt_node in mgmt_nodes_configs:
        for k, v in mgmt_node.items():
            logger.info('{0}: {1}'.format(k, v))
        logger.info('')

    logger.info('\n>>> Edge configurations')
    edge_configs = nsx.get_edge_configs()
    for edge in edge_configs:
        for k, v in edge.items():
            logger.info('{0}: {1}'.format(k, v))
        logger.info('')

    logger.info('\n>>> Transport-Zone information')
    tranport_zone_configs = nsx.get_transport_zone_configs()
    for transport_zone in tranport_zone_configs:
        for k, v in transport_zone.items():
            logger.info('{0}: {1}'.format(k, v))
        logger.info('')

    logger.info('\n>>> Transport Nodes information')
    transport_node_configs = nsx.get_host_transport_node_configs()
    for transport_node in transport_node_configs:
        for k, v in transport_node.items():
            logger.info('{0}: {1}'.format(k, v))
        logger.info('')

    logger.info('\n>>> IP Pool information')
    ippool_configs = nsx.get_ippool_configs()
    for ippool in ippool_configs:
        for k, v in ippool.items():
            logger.info('{0}: {1}'.format(k, v))
        logger.info('')

    logger.info('\n>>> Tier-0 Routers')
    tier0s_configs = nsx.get_tier0s_configs()
    for tier0 in tier0s_configs:
        for k, v in tier0.items():
            logger.info('{0}: {1}'.format(k, v))
        logger.info('')

    logger.info('\n>>> DHCP Server Profiles')
    dhcp_server_configs = nsx.get_dhcp_server_configs()
    for dhcp_server in dhcp_server_configs:
        for k, v in dhcp_server.items():
            logger.info('{0}: {1}'.format(k, v))
        logger.info('')

    logger.info('\n>>> Metadata Proxies')
    md_proxy_configs = nsx.get_metadata_proxy_configs()
    for md_proxy in md_proxy_configs:
        for k, v in md_proxy.items():
            logger.info('{0}: {1}'.format(k, v))
        logger.info('')

    config_dump = {
        'product': 'nsxt',
        'versions': version_configs,
        'mgmt_network': mgmt_network_configs,
        'cluster_wide_configs': cluster_wide_configs,
        'mgmt_nodes': mgmt_nodes_configs,
        'edges': edge_configs,
        'transport_zones': tranport_zone_configs,
        'transport_nodes': transport_node_configs,
        'ip_pools': ippool_configs,
        'tier0s': tier0s_configs,
        'dhcp_server_profiles': dhcp_server_configs,
        'metadata_proxies': md_proxy_configs
    }
    return config_dump


def get_vio_configs(config):
    cfg = config['vio']
    logger.info('--- Collect data from VIO Manager: {}'.format(cfg['management_ip']))
    viomgr = Vio(
        ipaddress=cfg['management_ip'],
        username=cfg['user_name'],
        password=cfg['vio_admin_password']
    )

    logger.info('\n>>> Cluster network configurations')
    network_configs = viomgr.get_network_configs()
    for network in network_configs:
        for k, v in network.items():
            logger.info('{0}: {1}'.format(k, v))
        logger.info('')
    ntp_servers = viomgr.get_ntp_servers()
    logger.info('NTP servers: {}'.format(ntp_servers))

    logger.info('\n>>> Nodes configurations')
    node_configs = viomgr.get_node_configs()
    for node in node_configs:
        for k, v in node.items():
            logger.info('{0}: \t{1}'.format(k, v))
        logger.info('')

    logger.info('\n>>> Openstack Deployment configurations')
    osdeployment_configs = viomgr.get_osdeployment_configs()
    for osdeployment in osdeployment_configs:
        for k, v in osdeployment.items():
            logger.info('{0}: \t{1}'.format(k, v))
        logger.info('')

    logger.info('\n>>> Configured backends')
    backend_configs = viomgr.get_backends_configs()
    for k, v in backend_configs.items():
        logger.info('{0}: {1}'.format(k, v))

    # Parse data for filedump
    config_dump = {
        'product': 'vio',
        'cluster': {
            'networks': network_configs,
            'ntp_servers': ntp_servers
        },
        'nodes': node_configs,
        'osdeployment': osdeployment_configs,
        'backends': backend_configs
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
    node_configs = vrni.get_node_configs()
    for k, v in node_configs.items():
        logger.info('{0}: {1}'.format(k, v))

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
            'network': node_configs,
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
    nsx_config_dump = export_config_to_file(
        dump_data=get_nsxt_configs(config=configs.get('c_plane')),
        timestamp=TIMESTAMP
    )
    logger.info('\n--- C-Plane NSX-T config exported : {}'.format(nsx_config_dump))
    logger.info('--------------------------------------------------------------------')
    vio_config_dump = export_config_to_file(
        dump_data=get_vio_configs(config=configs.get('c_plane')),
        timestamp=TIMESTAMP
    )
    logger.info('\n--- C-Plane VIO config exported : {}'.format(vio_config_dump))
    logger.info('--------------------------------------------------------------------')
    vrops_config_dump = export_config_to_file(
        dump_data=get_vrops_configs(config=configs.get('c_plane')),
        timestamp=TIMESTAMP
    )
    logger.info('\n--- C-Plane vROps config exported : {}'.format(vrops_config_dump))
    logger.info('--------------------------------------------------------------------')
    vrli_config_dump = export_config_to_file(
        dump_data=get_vrli_configs(config=configs.get('c_plane')),
        timestamp=TIMESTAMP
    )
    logger.info('\n--- C-Plane vRLI config exported : {}'.format(vrli_config_dump))
    logger.info('--------------------------------------------------------------------')
    vrni_config_dump = export_config_to_file(
        dump_data=get_vrni_configs(config=configs.get('c_plane')),
        timestamp=TIMESTAMP
    )
    logger.info('\n--- C-Plane vRNI config exported : {}'.format(vrni_config_dump))
    logger.info('--------------------------------------------------------------------')
    logger.info('>>> All configuration dumped !!')
    logger.info('Dumped configuration files : [ ./{}_nfvconfig/*_config.json ]'.format(TIMESTAMP))

    sys.exit(0)
