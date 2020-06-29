import ssl
import atexit
import logging
logger = logging.getLogger(__name__)

import requests
import urllib3
from urllib3.exceptions import InsecureRequestWarning
urllib3.disable_warnings(InsecureRequestWarning)

from pyVim.connect import SmartConnect, Disconnect
from pyVmomi import vim


class VApi():
    def __init__(self, ipaddress, username, password):
        self.ipaddress = ipaddress
        self.username = username
        self.password = password
        self.context = None

    def _establish_session(self):
        if hasattr(ssl, '_create_unverified_context'):
            self.context = ssl._create_unverified_context()
        vc_session = SmartConnect(
            host=self.ipaddress,
            user=self.username,
            pwd=self.password,
            sslContext=self.context
        )
        atexit.register(Disconnect, vc_session)
        return vc_session.content

    # host general
    def _get_host_system_version(self, host):
        versions = host.summary.config.product
        return {
            'version': versions.version,
            'build': versions.build,
            'api_version': versions.apiVersion
        }

    def _get_host_dns_config(self, host):
        dns_config = host.configManager.networkSystem.dnsConfig
        return {
            'dns_servers': [dns for dns in dns_config.address],
            'search_path': [path for path in dns_config.searchDomain]
        }

    def _get_host_ntp_config(self, host):
        ntp_config = host.configManager.dateTimeSystem.dateTimeInfo.ntpConfig.server
        return [ntp for ntp in ntp_config]

    def _get_host_ssh_status(self, host):
        services = host.configManager.serviceSystem
        ssh_service = [s for s in services.serviceInfo.service if s.key == 'TSM-SSH'][0].running
        return 'Running' if ssh_service == True else 'Error'

    # host networks
    def _get_host_pnics(self, host):
        host_pnics = []
        for pnic in host.config.network.pnic:
            pnic_info = dict()
            pnic_info.update(
                {'device': pnic.device, 'driver': pnic.driver, 'mac': pnic.mac})
            host_pnics.append(pnic_info)
        return host_pnics

    def _get_host_vnics(self, host):
        host_vnics = []
        for vnic in host.config.network.vnic:
            vnic_info = dict()
            vnic_info.update(
                {'device': vnic.device, 'portgroup': vnic.portgroup,
                'dhcp': vnic.spec.ip.dhcp, 'ipAddress': vnic.spec.ip.ipAddress,
                'subnetMask': vnic.spec.ip.subnetMask,
                'mac': vnic.spec.mac, 'mtu': vnic.spec.mtu})
            host_vnics.append(vnic_info)
        return host_vnics

    def _get_host_vswitches(self, host):
        host_vswitches = []
        for vswitch in host.config.network.vswitch:
            vswitch_info = dict()
            vswitch_pnics = []
            vswitch_portgroups = []
            for pnic in vswitch.pnic:
                pnic = pnic.replace('key-vim.host.PhysicalNic-', '')
                vswitch_pnics.append(pnic)
            for pg in vswitch.portgroup:
                pg = pg.replace('key-vim.host.PortGroup-', '')
                vswitch_portgroups.append(pg)
            vswitch_info.update({'name': vswitch.name, 'pnics': vswitch_pnics, 'portgroups': vswitch_portgroups, 'mtu': vswitch.mtu})
            host_vswitches.append(vswitch_info)
        return host_vswitches

    def _get_host_portgroups(self, host):
        host_portgroups = []
        for portgroup in host.config.network.portgroup:
            portgroup_info = dict()
            portgroup_info.update(
                {'name': portgroup.spec.name, 'vlanId': portgroup.spec.vlanId,
                'vswitchName': portgroup.spec.vswitchName,
                'nicTeamingPolicy': portgroup.spec.policy.nicTeaming.policy,
                'allowPromiscuous': portgroup.spec.policy.security.allowPromiscuous,
                'macChanges': portgroup.spec.policy.security.macChanges,
                'forgedTransmits': portgroup.spec.policy.security.forgedTransmits})
            host_portgroups.append(portgroup_info)
        return host_portgroups

    def _get_esxi_networks(self, esxi):
        return {
            'pnics': self._get_host_pnics(host=esxi),
            'vnics': self._get_host_vnics(host=esxi),
            'vswitches': self._get_host_vswitches(host=esxi),
            'portgroups': self._get_host_portgroups(host=esxi),
        }

    def _get_esxi_configs(self, esxis):
        host_configs = []
        for esxi in esxis:
            host_configs.append({
                'hostname': esxi.name,
                'versions': self._get_host_system_version(host=esxi),
                'dns': self._get_host_dns_config(host=esxi),
                'ntp_servers': self._get_host_ntp_config(host=esxi),
                'ssh_services': self._get_host_ssh_status(host=esxi),
                'networks': self._get_esxi_networks(esxi=esxi)
            })
        return host_configs


    def _get_cluster_objects(self):
        ret = self._establish_session()
        cluster_view = ret.viewManager.CreateContainerView(
            ret.rootFolder,
            [vim.ComputeResource],
            True
        )
        clusterlist = [cluster for cluster in cluster_view.view]
        logger.debug(cluster_view)
        cluster_view.Destroy()
        return clusterlist

    def get_cluster_configs(self):
        cluster_configs = []
        cluster_view = self._get_cluster_objects()
        for cluster in cluster_view:
            cluster_configs.append({
                'name': cluster.name,
                'hosts': self._get_esxi_configs(esxis=cluster.host)
            })
        return cluster_configs

    ## class methods for vSAN
    def _get_vsan_cluster_disk_configs(self, esxi):
        disk_map = esxi.config.vsanHostConfig.storageInfo.diskMapping
        vsan_cluster_disk_configs = {
            'disk_group': disk_map[0].ssd.vsanDiskInfo.vsanUuid,
            'disks': []
        }
        for disk in disk_map:
            vsan_cluster_disk_configs.append({
                'flash': disk.ssd.displayName,
                'hdd': [non_ssd.displayName for non_ssd in disk.nonSsd]
            })
        return vsan_cluster_disk_configs

    def get_vsan_cluster_configs(self, esxi_hosts):
        vsan_cluster_configs = []
        for vsan_node in esxi_hosts:
            vsan_cluster_configs.append({
                'name': vsan_node.name,
                'cluster_uuid': vsan_node.configManager.vsanSystem.config.clusterInfo.uuid,
                'node_uuid': vsan_node.configManager.vsanSystem.config.clusterInfo.nodeUuid,
                'disk_groups': self._get_vsan_cluster_disk_configs(esxi=vsan_node)
            })
        return vsan_cluster_configs

    ## class methods for vDS configurations
    def _get_dvs_objects(self):
        ret = self._establish_session()
        dvs_view = ret.viewManager.CreateContainerView(
            ret.rootFolder,
            [vim.DistributedVirtualSwitch],
            True
        )
        dvslist = [dvs for dvs in dvs_view.view]
        logger.debug(dvslist)
        dvs_view.Destroy()
        return dvslist

    def get_vds_configs(self):
        vds_configs = []
        vds_list = self._get_dvs_objects()
        for vds in vds_list:
            vds_configs.append({
                'name': vds.name,
                'hosts': [
                    vds_host.config.host.name
                    for vds_host in vds.config.host
                ],
                'dvportgroups': [
                    dvpg.name
                    for dvpg in vds.config.uplinkPortgroup
                ],
                'uplinks': [
                    uplink
                    for uplink in vds.config.uplinkPortPolicy.uplinkPortName
                ],
                'portgroups': [
                    {
                        'name': pg.name,
                        'vlan_id': pg.config.defaultPortConfig.vlan.vlanId
                    }
                    for pg in vds.portgroup
                    if type(pg.config.defaultPortConfig.vlan.vlanId) == int
                 ]
            })
        return vds_configs

