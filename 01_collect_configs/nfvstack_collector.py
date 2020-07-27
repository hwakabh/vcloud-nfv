import yaml
import sys
import os
import json
from datetime import datetime
import logging

from vsphere.vcsa import VCenter
from vsphere.vapi import VApi
from nsxt.nsxt import Nsxt
from vio.vio import Vio
from vrops.vrops import VROps
from vrli.vrli import VRli
from vrni.vrni import VRni


def read_config_from_file(conf_file_path):
    with open(conf_file_path, 'r') as f:
        data = f.read()
    return yaml.safe_load(data)


def export_config_to_file(dump_data, prefix):
    EXPORT_PATH = f'./{prefix}_nfvconfig'
    if not os.path.exists(EXPORT_PATH):
        os.mkdir(EXPORT_PATH)
    target_product = dump_data['product']
    dump_file_name = '{0}/{1}_{2}_config.json'.format(EXPORT_PATH, prefix, target_product)
    with open(dump_file_name, 'w') as f:
        json.dump(dump_data, f, indent=3)
    return dump_file_name


def get_vcenter_configs(config):
    cfg = config['vcenter']
    logger.info('--- Collect data from vSphere vCSA: {}'.format(cfg['ip_address']))
    vc = VCenter(
        ipaddress=cfg['ip_address'],
        username=cfg['user_name'],
        password=cfg['sso_password']
    )
    vapi = VApi(
        ipaddress=cfg['ip_address'],
        username=cfg['user_name'],
        password=cfg['sso_password']
    )

    logger.info('\n>>> Version configurations')
    version_configs = vc.get_version()
    for k, v in version_configs.items():
        logger.info('{0}: {1}'.format(k, v))

    logger.info('\n>>> Appliance configurations')
    appliance_configs = vc.get_appliance_configs()
    for k, v in appliance_configs.items():
        logger.info('{0}: \t{1}'.format(k, v))

    logger.info('\n>>> vCHA configuration')
    vcha_configs = vc.get_vcha_configs()
    for k, v in vcha_configs.items():
        logger.info('{0}: \t{1}'.format(k, v))

    logger.info('\n>>> Datacenters configuration')
    datacenter_configs = vc.get_datacenter_list()
    print(datacenter_configs)

    logger.info('\n>>> Host Cluster configuration')
    cluster_configs = vc.get_cluster_configs()
    for cluster in cluster_configs:
        for k, v in cluster.items():
            logger.info('{0}: \t{1}'.format(k, v))
        logger.info('Hosts: \t{}'.format(
            vc.get_host_list(cluster_moref=cluster['moref']))
        )
        logger.info('')

    logger.info('\n>>> Host configurations')
    managed_hosts_configs = vapi.get_cluster_configs()
    for managed_hosts in managed_hosts_configs:
        logger.info('Cluster: {}'.format(managed_hosts['name']))
        for host_config in managed_hosts['hosts']:
            logger.info(json.dumps(host_config, indent=2))
            logger.info('')
        logger.info('')

    logger.info('\n>>> vSAN configurations')
    for managed_hosts in managed_hosts_configs:
        logger.info('Cluster: {}'.format(managed_hosts['name']))
        for vsan_config in managed_hosts['vsan']:
            logger.info(json.dumps(vsan_config, indent=2))
            logger.info('')
        logger.info('')

    logger.info('\n>>> vDS configuration')
    vds_configs = vapi.get_vds_configs()
    for vds in vds_configs:
        for k, v in vds.items():
            logger.info('{0}: \t{1}'.format(k, v))
        logger.info('')

    config_dump = {
        'product': 'vsphere',
        'versions': version_configs,
        'vcsa': appliance_configs,
        'vcha': vcha_configs,
        'datacenters': datacenter_configs,
        'cluster_configs': cluster_configs,
        'esxi': managed_hosts_configs,
        'vDS': vds_configs
    }
    return config_dump


def get_nsxt_configs(config):
    cfg = config['nsxt']
    logger.info('--- Collect data from NSX-T Manager: {}'.format(cfg['ip_address']))
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
        password=cfg['user_password']
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
        password=cfg['user_password'],
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
        password=cfg['user_password'],
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

    PREFIX = datetime.now().strftime('%Y%m%d_%H%M%S')

    # Log file validations
    LOG_DIR = './logs'
    if not os.path.exists(LOG_DIR):
        os.mkdir(LOG_DIR)
    LOG_FILENAME = f'{PREFIX}_nfvstack_collector.log'
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

    logger.info(f'>>> Logfile : [ {LOG_FILE_PATH} ]')

    # Input file validations
    NFV_STACK_YAML = './InputFile-NFVStack.yaml'
    if os.path.exists(NFV_STACK_YAML):
        logger.info(f'>>> Loading input parameter file : [ {NFV_STACK_YAML} ]')
        configs = read_config_from_file(conf_file_path=NFV_STACK_YAML)
    else:
        logger.error('Provided configuration file path is wrong.')
        logger.error(f'Configuration file is expected to be allocated on: {NFV_STACK_YAML} ')
        sys.exit(1)

    logger.info('>>> Start collecting configurations, this might take some time ...')
    logger.info('')
    logger.info('--------------------------------------------------------------------')
    # mplane_vsphere_config_dump = export_config_to_file(
    #     dump_data=get_vcenter_configs(config=configs.get('management')),
    #     prefix=PREFIX
    # )
    # logger.info('\n--- M-Plane vSphere config exported : {}'.format(mplane_vsphere_config_dump))
    # logger.info('')
    # # cplane_vsphere_config_dump = export_config_to_file(
    # #     dump_data=get_vcenter_configs(config=configs.get('c_plane')),
    # #     prefix=PREFIX
    # # )
    # # logger.info('\n--- C-Plane vSphere config exported : {}'.format(cplane_vsphere_config_dump))
    # logger.info('--------------------------------------------------------------------')
    # nsx_config_dump = export_config_to_file(
    #     dump_data=get_nsxt_configs(config=configs.get('c_plane')),
    #     prefix=PREFIX
    # )
    # logger.info('\n--- C-Plane NSX-T config exported : {}'.format(nsx_config_dump))
    logger.info('--------------------------------------------------------------------')
    vio_config_dump = export_config_to_file(
        dump_data=get_vio_configs(config=configs.get('c_plane')),
        prefix=PREFIX
    )
    logger.info('\n--- C-Plane VIO config exported : {}'.format(vio_config_dump))
    logger.info('--------------------------------------------------------------------')
    vrops_config_dump = export_config_to_file(
        dump_data=get_vrops_configs(config=configs.get('c_plane')),
        prefix=PREFIX
    )
    logger.info('\n--- C-Plane vROps config exported : {}'.format(vrops_config_dump))
    logger.info('--------------------------------------------------------------------')
    vrli_config_dump = export_config_to_file(
        dump_data=get_vrli_configs(config=configs.get('c_plane')),
        prefix=PREFIX
    )
    logger.info('\n--- C-Plane vRLI config exported : {}'.format(vrli_config_dump))
    logger.info('--------------------------------------------------------------------')
    vrni_config_dump = export_config_to_file(
        dump_data=get_vrni_configs(config=configs.get('c_plane')),
        prefix=PREFIX
    )
    logger.info('\n--- C-Plane vRNI config exported : {}'.format(vrni_config_dump))
    logger.info('--------------------------------------------------------------------')
    logger.info('>>> All configuration dumped !!')
    logger.info('Dumped configuration files : [ ./{}_nfvconfig/*_config.json ]'.format(PREFIX))

    sys.exit(0)
