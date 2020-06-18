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
    vcsa_networks = vc.get('/rest/appliance/networking/interfaces')
    vcsa_hostnames = vc.get('/rest/appliance/networking/dns/hostname')
    vcsa_dns = vc.get('/rest/appliance/networking/dns/servers')
    vcsa_ntp = vc.get('/rest/appliance/ntp')
    vcsa_ssh_status = vc.get('/rest/appliance/access/ssh')

    vcsa_dc = vc.get('/rest/vcenter/datacenter')
    vcsa_clusters = vc.get('/rest/vcenter/cluster')

    # Call vAPI to get ESXi host configs
    vapi = VApi(ipaddress=IPADDRESS, username=USERNAME, password=PASSWORD)

    print('>>> Appliance configurations ...')
    print('IP address: \t{}'.format(vcsa_networks['value'][0]['ipv4']['address']))
    print('Subnet Prefix: \t{}'.format(vcsa_networks['value'][0]['ipv4']['prefix']))
    print('Gateway: \t{}'.format(vcsa_networks['value'][0]['ipv4']['default_gateway']))
    print('Hostname: \t{}'.format(vcsa_hostnames['value']))
    print('DNS Servers: \t{}'.format(vcsa_dns['value']['servers']))
    print('NTP Servers: \t{}'.format(vcsa_ntp['value']))
    print('SSH Services: \t{}'.format('Running' if vcsa_ssh_status['value'] == True else 'Not Running'))

    print('>>> vCHA configurations ...')
    vcsa_ha = vc.post('/rest/vcenter/vcha/cluster?action=get')
    print('Status : {}'.format(vcsa_ha['value']))

    print()

    # Retrieve all hostdata prior to compare with response of vSphere REST-API
    esxis = vapi.get_host_objects()
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

            # print(json.dumps(host_info, indent=3, separators=(',', ': ')))
            # print('>>>>>>>>> [ {} ] SSH configurations'.format(host['name']))
            print('SSH service : {}'.format(esxi_parser.get_host_ssh_status(target_host)))

    # TODO: Return JSON value with parsed
    return None


def get_nsxt_configs(config):
    cfg = config['nsxt']
    NSX_MGR, NSX_USERNAME, NSX_PASSWORD = cfg['ip_address'], cfg['admin_user_name'], cfg['admin_password']

    print('------ Starting config_dump for NSX-T Manager: {}'.format(NSX_MGR))
    nsx = Nsxt(ipaddress=NSX_MGR, username=NSX_USERNAME, password=NSX_PASSWORD)
    # Fetch only management network information
    print('>>> Management Network information ...')
    mgmt_networks = nsx.get('/api/v1/node/network/interfaces')
    for net in mgmt_networks['results']:
        print('Interface: \t{0} (Physical Address: {1})'.format(net['interface_id'], net['physical_address']))
        print('IP Address: \t{}'.format(net['ip_addresses'][0]['ip_address']))
        print('Netmask: \t{}'.format(net['ip_addresses'][0]['netmask']))
        if 'default_gateway' in net:
            print('Gateway: \t{}'.format(net['default_gateway']))
        print('MTU: \t\t{}'.format(net['mtu']))
        print()

    hostname = nsx.get('/api/v1/node')
    dns = nsx.get('/api/v1/node/network/name-servers')
    ntp = nsx.get('/api/v1/node/services/ntp')

    print('Hostname: \t{}'.format(hostname['fully_qualified_domain_name']))
    print('DNS Servers: \t{}'.format(dns['name_servers']))
    print('NTP Servers: \t{}'.format(ntp['service_properties']['servers']))

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
    for cfg in config:
        VRNI_IPADDR = cfg['hostname']
        VRNI_USERNAME = cfg['username']
        VRNI_PASSWORD = cfg['password']
        VRNI_DOMAIN = cfg['domain']
        print('------ Starting config_dump for vRNI: {}'.format(VRNI_IPADDR))
        vrni = VRni(ipaddress=VRNI_IPADDR, username=VRNI_USERNAME, password=VRNI_PASSWORD, domain=VRNI_DOMAIN)
        version_info = vrni.get('/api/ni/info/version')
        nodes_info = vrni.get('/api/ni/infra/nodes')
        # cluster_info = vrni.get('/api/ni/entities/clusters')
        # host_info = vrni.get('/api/ni/entities/hosts')

        print('>>> Version information')
        print('API Version : {0}'.format(version_info['api_version']))

        print('>>> Nodes information')
        # Fetch all node ids configured
        # print(vrni_nodes)
        ni_node_ids = [i['id'] for i in nodes_info['results']]
        for node_id in ni_node_ids:
            node = vrni.get('/api/ni/infra/nodes/{}'.format(node_id))
            print('Node ID: {0} (internal: {1})'.format(node['id'], node['node_id']))
            print('IP Address: {}'.format(node['ip_address']))
            print('Deployment Role: {}'.format(node['node_type']))

        # print(cluster_info)
        # print(host_info)

        # user_groups = vrni.get('/api/ni/settings/user-groups')
        # print(user_groups)

        # snmp_info = vrni.get('/api/ni/settings/snmp/profiles')
        # print(snmp_info)

    # TODO: Return JSON value with parsed
    return None


def get_vrli_configs(config):
    for cfg in config:
        VRLI_IPADDR = cfg['hostname']
        VRLI_USERNAME = cfg['username']
        VRLI_PASSWORD = cfg['password']
        VRLI_PROVIDER = cfg['provider']
        print('------ Starting config_dump for vRLI: {}'.format(VRLI_IPADDR))
        vrli = VRli(ipaddress=VRLI_IPADDR, username=VRLI_USERNAME, password=VRLI_PASSWORD, provider=VRLI_PROVIDER)
        version_info = vrli.get('/api/v1/version')
        cluster_info = vrli.get('/api/v1/cluster/vips')
        node_info = vrli.get('/api/v1/cluster/nodes')
        ntp_info = vrli.get('/api/v1/time/config')
        cp_info = vrli.get('/api/v1/content/contentpack/list')
        vsphere_info = vrli.get('/api/v1/vsphere')
        vrops_info = vrli.get('/api/v1/vrops')
        smtp_info = vrli.get('/api/v1/notification/channels')
        ad_info = vrli.get('/api/v1/ad')
        vidm_status = vrli.get('/api/v1/vidm/status')
        vidms = vrli.get('/api/v1/vidm')

        print('>>> Version information')
        print('{0} (Release Type: {1})'.format(version_info['version'], version_info['releaseName']))
        print()

        print('>>> Cluster configurations ...')
        print('> vIP : {0} (FQDN : {1})'.format(cluster_info['vips'][0]['ipAddress'], cluster_info['vips'][0]['fqdn']))
        print('> proxy-node')
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
        print('>>> Products integrated')
        # vrli_vsphere = vrli_api.get('/api/v1/vsphere/{}'.format('vcsa02.nfvlab.local'))
        print(vsphere_info)
        print(vrops_info)

        print('>>> SMTP Configurations ...')
        print(smtp_info)

        print('>>> Authentication source configurations ...')
        print('>>>>>> Active Directories')
        print(ad_info)
        print('>>>>>> vIDM')
        print('Status: {}'.format(vidm_status['state']))
        print(json.dumps(vidms, indent=3, separators=(',', ': ')))
        print()

    # TODO: Should be return JSON value simplified
    return None


def get_vrops_configs(config):
    for cfg in config:
        VROPS_IPADDR = cfg['hostname']
        VROPS_USERNAME = cfg['username']
        VROPS_PASSWORD = cfg['password']
        print('------ Starting config_dump for vROps: {}'.format(VROPS_IPADDR))
        # Instanciate vROps class
        vrops = VROps(ipaddress=VROPS_IPADDR, username=VROPS_USERNAME, password=VROPS_PASSWORD)

        # Fetch all info from CaSA API
        cluster_conf = vrops.casa_get('/casa/cluster/config')
        ip_conf = vrops.casa_get('/casa/node/status')
        # Fetch all info from Suite API
        versions = vrops.get('/suite-api/api/versions/current')
        auth_sources = vrops.get('/suite-api/api/auth/sources')
        mp_info = vrops.get('/suite-api/api/solutions')
        adapter_info = vrops.get('/suite-api/api/adapters')
        snmp_info = vrops.get('/suite-api/api/alertplugins')

        print('>>> Version information')
        print('{}'.format(versions['releaseName']))
        print('Release Date: {}'.format(versions['humanlyReadableReleaseDate']))

        print('>>> Cluster configurations')
        for node in cluster_conf['slices']:
            print('Node: {}'.format(node['node_name']))
            print('IP Address: \t{}'.format(ip_conf['address']))
            print('Deployment Role: {}'.format(node['node_type']))
            # print('IP Address: {}'.format(node['']))
            print('Netmask: {}'.format(node['network_properties']['network1_netmask']))
            print('Gateway: {}'.format(node['network_properties']['default_gateway']))
            print('DNS Servers: \t{}'.format(node['network_properties']['domain_name_servers']))
            print('Domain Name: \t{}'.format(node['network_properties']['domain_name']))
            print('NTP Servers: \t{}'.format(node['ntp_servers']))
            print()

        print()
        print('>>> Authentication sources')
        auth_src_ids = [i['id'] for i in auth_sources['sources']]
        for auth_src_id in auth_src_ids:
            auth_detail = vrops.get('/suite-api/api/auth/sources/{}'.format(auth_src_id))
            auth_name = auth_detail.get('name', None)
            if auth_name is not None:
                print('>>>>>> {}'.format(auth_name))
                print('Source ID: {}'.format(auth_src_id))
                print('Type: {}'.format(auth_detail['sourceType']['id']))

        print('>>> Installed Management Packs')
        for mp in mp_info['solution']:
            print('{0} (Version : {1})'.format(mp['name'], mp['version']))

        print('>>> Configured Adapters')
        for adapter in adapter_info['adapterInstancesInfoDto']:
            print('ID: {0}, Name: {1}'.format(adapter['id'], adapter['resourceKey']['name']))

        # TODO: handle stdout whether Tranp configured or not
        print('>>> SNMP Configurations')
        vrops_snmp_config = {}
        for snmp in snmp_info['notificationPluginInstances']:
            if snmp['pluginTypeId'] == 'SNMP Trap':
                vrops_snmp_config = snmp['configValues']
        if vrops_snmp_config is not {}:
            for s in vrops_snmp_config:
                print(s)

        print()

    # TODO: Should be return JSON value simplified
    return None


if __name__ == "__main__":

    CONFIG_FILE_PATH = './InputFile-NFVStack.yaml'
    if os.path.exists(CONFIG_FILE_PATH):
        print('>>> Loading input parameter file : [ {} ]'.format(CONFIG_FILE_PATH))
        configs = read_config_from_file(conf_file_path=CONFIG_FILE_PATH)
    else:
        print('Provided configuration file path is wrong.')
        print('Configuration file is expected to be allocated on ./config.yaml.')
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
    sys.exit(1)
    print()
    print('--------------------------------------------------------------------')
    print('### vRealize Operations Manager')
    print()
    vrops_configs = get_vrops_configs(config=configs.get('vrops'))
    print()
    print('--------------------------------------------------------------------')
    print('### vRealize Log Insight')
    print()
    vrli_configs = get_vrli_configs(config=configs.get('vrli'))
    print()
    print('--------------------------------------------------------------------')
    print('### vRealize Network Insight')
    print()
    vrni_configs = get_vrni_configs(config=configs.get('vrni'))
    print()
    print('--------------------------------------------------------------------')
    print()
    print('>>> All configuration dumped !!')
    # TODO: print path of logfile and dumped file as stdout

    sys.exit(0)
