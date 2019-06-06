

# developed by Sundaram Tirunelveli Radhakrishnan, Engineer, XR BGP, Cisco Systems

import sys
import pdb
import time
from dnac_config import DNAC, DNAC_PORT, DNAC_USER, DNAC_PASSWORD
#from lxml import html

import requests
import xml
import xml.dom.minidom
import json
import lxml.etree as et
import xmltodict

from ncclient import manager

from requests.packages.urllib3.exceptions import InsecureRequestWarning
from requests.auth import HTTPBasicAuth  # for Basic Auth

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)  # Disable insecure https warnings


def netconf_get_hostname(ios_xe_host, ios_xe_port, ios_xe_user, ios_xe_pass):
    """
    This function will retrieve the device hostname via NETCONF
    :param ios_xe_host: device IPv4 address
    :param ios_xe_port: NETCONF port
    :param ios_xe_user: username
    :param ios_xe_pass: password
    :return IOS XE device hostname
    """
    with manager.connect(host=ios_xe_host, port=ios_xe_port, username=ios_xe_user,
                         password=ios_xe_pass, hostkey_verify=False,
                         device_params={'name': 'default'},
                         allow_agent=False, look_for_keys=False) as m:
        # XML filter to issue with the get operation
        # IOS-XE 16.6.2+        YANG model called "Cisco-IOS-XE-native"

        hostname_filter = '''
                                <filter xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
                                    <native xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-native">
                                        <hostname/>
                                    </native>
                                </filter>
                          '''

        result = m.get(hostname_filter)
        xml_doc = xml.dom.minidom.parseString(result.xml)
        int_info = xml_doc.getElementsByTagName('hostname')
        try:
            hostname = int_info[0].firstChild.nodeValue
        except:
            hostname = 'unknown'
        return hostname

def netconf_get_bgp_rtrid(ios_xe_host, ios_xe_port, ios_xe_user, ios_xe_pass):
    """
    This function will retrieve the device hostname via NETCONF
    :param ios_xe_host: device IPv4 address
    :param ios_xe_port: NETCONF port
    :param ios_xe_user: username
    :param ios_xe_pass: password
    :return IOS XE device hostname
    """
    with manager.connect(host=ios_xe_host, port=ios_xe_port, username=ios_xe_user,
                         password=ios_xe_pass, hostkey_verify=False,
                         device_params={'name': 'default'},
                         allow_agent=False, look_for_keys=False) as m:
        # XML filter to issue with the get operation
        # IOS-XE 16.6.2+        YANG model called "Cisco-IOS-XE-native"

        rtrid_filter =   '''
                                <filter xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
                                    <native xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-native">
                                      <router>
                                       <bgp xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-bgp"/>
                                      </router>
                                    </native>
                                </filter>
                          '''

        result = m.get(rtrid_filter)
        #pdb.set_trace()
        xml_doc = xml.dom.minidom.parseString(result.xml)
        int_info = xml_doc.getElementsByTagName('router-id')
        try:
            rtrid = int_info[0].firstChild.nodeValue
        except:
            rtrid = 'unknown'
        return rtrid

def netconf_get_xr_bgp_rtrid(ios_xe_host, ios_xe_port, ios_xe_user, ios_xe_pass):
    """
    This function will retrieve the device hostname via NETCONF
    :param ios_xe_host: device IPv4 address
    :param ios_xe_port: NETCONF port
    :param ios_xe_user: username
    :param ios_xe_pass: password
    :return IOS XE device hostname
    """
    with manager.connect(host=ios_xe_host, port=ios_xe_port, username=ios_xe_user,
                         password=ios_xe_pass, hostkey_verify=False,
                         device_params={'name': 'default'},
                         allow_agent=False, look_for_keys=False) as m:
        # XML filter to issue with the get operation
        # IOS-XE 16.6.2+        YANG model called "Cisco-IOS-XE-native"

        rtrid_filter =   '''
                                <filter xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
                                 <bgp xmlns="http://cisco.com/ns/yang/Cisco-IOS-XR-ipv4-bgp-cfg">
                                 </bgp>
                                </filter>
                          '''

        result = m.get(rtrid_filter)
        #pdb.set_trace()
        xml_doc = xml.dom.minidom.parseString(result.xml)
        int_info = xml_doc.getElementsByTagName('router-id')
        try:
            rtrid = int_info[0].firstChild.nodeValue
        except:
            rtrid = 'unknown'
        return rtrid

def netconf_set_bgp_rtrid(ios_xe_host, ios_xe_port, ios_xe_user, ios_xe_pass):
    """
    This function will retrieve the device hostname via NETCONF
    :param ios_xe_host: device IPv4 address
    :param ios_xe_port: NETCONF port
    :param ios_xe_user: username
    :param ios_xe_pass: password
    :return IOS XE device hostname
    """

    payload = '''<config xmlns:xc="urn:ietf:params:xml:ns:netconf:base:1.0">
        <native xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-native">
         <hostname xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" nc:operation="merge">CSR1000v</hostname>
         <router>
          <bgp xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-bgp">
            <id>65000</id>
            <bgp>
	     <router-id>2.2.2.2</router-id>
	    </bgp>
            <address-family>
              <no-vrf>
                <ipv4>
                  <af-name>unicast</af-name>
                </ipv4>
              </no-vrf>
            </address-family>
          </bgp>
        </router>
        </native>
       </config>'''

    # connect to netconf agent
    with manager.connect(host=ios_xe_host, port=ios_xe_port, username=ios_xe_user,
                         password=ios_xe_pass, hostkey_verify=False,
                         device_params={'name': 'csr'}) as m:

        #m.lock()

        # execute netconf operation
        edit_result = m.edit_config(target='running', config=payload)
        print(edit_result)

        #m.commit(confirmed=True)
        #m.unlock()

def netconf_get_xr_nbr_adv_count(ios_xe_host, ios_xe_port, ios_xe_user, ios_xe_pass):
    """
    This function will retrieve the device hostname via NETCONF
    :param ios_xe_host: device IPv4 address
    :param ios_xe_port: NETCONF port
    :param ios_xe_user: username
    :param ios_xe_pass: password
    :return IOS XE device hostname
    """
    with manager.connect(host=ios_xe_host, port=ios_xe_port, username=ios_xe_user,
                         password=ios_xe_pass, hostkey_verify=False,
                         device_params={'name': 'default'},
                         allow_agent=False, look_for_keys=False) as m:
        # XML filter to issue with the get operation
        # IOS-XE 16.6.2+        YANG model called "Cisco-IOS-XE-native"

        adv_cnt_filter =   '''
                                <filter xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
                                 <bgp xmlns="http://cisco.com/ns/yang/Cisco-IOS-XR-ipv4-bgp-oper">
				   <instances>
				    <instance>
				     <instance-name>default</instance-name>
				     <instance-active>
				      <default-vrf>   
				       <afs>                 
					<af>                         
					 <advertised-path-counts>            
					  <advertised-path-count>                     
					   <neighbor-address>10.1.1.2</neighbor-address>       
					  </advertised-path-count>                                    
					 </advertised-path-counts>                                           
					</af>                                                                       
				       </afs>                                                                              
				      </default-vrf>                                                                             
				     </instance-active>                                                                               
				    </instance>                                                                                         
				   </instances>                                                                                            
				 </bgp>
                                </filter>
                          '''

        result = m.get(adv_cnt_filter)
        #pdb.set_trace()
        xml_doc = xml.dom.minidom.parseString(result.xml)
        int_info = xml_doc.getElementsByTagName('max-prefix-advertisedcount')
        try:
            adv_count = int_info[0].firstChild.nodeValue
        except:
            adv_count = 'unknown'
        return adv_count

def netconf_push_xr_config(ios_xe_host, ios_xe_port, ios_xe_user, ios_xe_pass, my_as, rem_as, my_ip, rtr_id, nbr_name):
    """
    This function will retrieve the device hostname via NETCONF
    :param ios_xe_host: device IPv4 address
    :param ios_xe_port: NETCONF port
    :param ios_xe_user: username
    :param ios_xe_pass: password
    :return IOS XE device hostname
    """

    payload = '''<config xmlns:xc="urn:ietf:params:xml:ns:netconf:base:1.0">
	<routing-policy xmlns="http://cisco.com/ns/yang/Cisco-IOS-XR-policy-repository-cfg">
	     <route-policies>
	      <route-policy>
	       <route-policy-name>pass</route-policy-name>
	       <rpl-route-policy>route-policy pass
	    pass
	  end-policy
	  </rpl-route-policy>
	      </route-policy>
	     </route-policies>
	</routing-policy>
	<interface-configurations xmlns="http://cisco.com/ns/yang/Cisco-IOS-XR-ifmgr-cfg">
	  <interface-configuration>
	      <active>act</active>
	      <interface-name>GigabitEthernet0/0/0/0</interface-name>
              <shutdown xc:operation="remove"></shutdown>
	      <ipv4-network xmlns="http://cisco.com/ns/yang/Cisco-IOS-XR-ipv4-io-cfg">
	       <addresses>
	        <primary>
	         <address>%s</address>
	         <netmask>255.255.255.0</netmask>
	        </primary>
	       </addresses>
	      </ipv4-network>
	     </interface-configuration>
	</interface-configurations>
	<router-static xmlns="http://cisco.com/ns/yang/Cisco-IOS-XR-ip-static-cfg">
	   <default-vrf>
	    <address-family>
	     <vrfipv4>
	      <vrf-unicast>
	       <vrf-prefixes>
	        <vrf-prefix>
	         <prefix>80.1.1.0</prefix>
	         <prefix-length>24</prefix-length>
	         <vrf-route>
	          <vrf-next-hop-table>
	           <vrf-next-hop-interface-name>
	            <interface-name>Null0</interface-name>
	           </vrf-next-hop-interface-name>
	          </vrf-next-hop-table>
	         </vrf-route>
	        </vrf-prefix>
	        <vrf-prefix>
	         <prefix>80.1.2.0</prefix>
	         <prefix-length>24</prefix-length>
	         <vrf-route>
	          <vrf-next-hop-table>
	           <vrf-next-hop-interface-name>
	            <interface-name>Null0</interface-name>
	           </vrf-next-hop-interface-name>
	          </vrf-next-hop-table>
	         </vrf-route>
	        </vrf-prefix>
	       </vrf-prefixes>
	      </vrf-unicast>
	     </vrfipv4>
	    </address-family>
	   </default-vrf>
	</router-static>
    <bgp xmlns="http://cisco.com/ns/yang/Cisco-IOS-XR-ipv4-bgp-cfg">
     <instance>
      <instance-name>default</instance-name>
      <instance-as>
       <as>0</as>
       <four-byte-as>
        <as>%d</as>
        <bgp-running></bgp-running>
        <default-vrf>
         <global>
          <router-id>%s</router-id>
          <global-afs>
           <global-af>
            <af-name>ipv4-unicast</af-name>
            <enable></enable>
            <static-routes/>
           </global-af>
          </global-afs>
         </global>
         <bgp-entity>
          <neighbors>
           <neighbor>
            <neighbor-address>%s</neighbor-address>
            <remote-as>
             <as-xx>0</as-xx>
             <as-yy>%d</as-yy>
            </remote-as>
            <neighbor-afs>
             <neighbor-af>
              <af-name>ipv4-unicast</af-name>
              <activate></activate>
             </neighbor-af>
            </neighbor-afs>
           </neighbor>
          </neighbors>
         </bgp-entity>
        </default-vrf>
       </four-byte-as>
      </instance-as>
     </instance>
    </bgp>
       </config>''' % (my_ip, my_as, rtr_id, nbr_name, rem_as)

    # connect to netconf agent
    with manager.connect(host=ios_xe_host, port=ios_xe_port, username=ios_xe_user,
                         password=ios_xe_pass, hostkey_verify=False,
                         device_params={'name': 'csr'}) as m:

        #m.lock()

        # execute netconf operation
        edit_result = m.edit_config(target='candidate', config=payload)
        print(edit_result)

        m.commit()
        #m.unlock()

def netconf_xr_apply_nbr_rpl(ios_xe_host, ios_xe_port, ios_xe_user, ios_xe_pass, my_as, nbr_name):
     """
     This function will retrieve the device hostname via NETCONF
     :param ios_xe_host: device IPv4 address
     :param ios_xe_port: NETCONF port
     :param ios_xe_user: username
     :param ios_xe_pass: password
     :return IOS XE device hostname
     """

     payload = '''<config>
     <bgp xmlns="http://cisco.com/ns/yang/Cisco-IOS-XR-ipv4-bgp-cfg">
      <instance>
       <instance-name>default</instance-name>
       <instance-as>
        <as>0</as>
        <four-byte-as>
         <as>%d</as>
         <bgp-running></bgp-running>
         <default-vrf>
          <bgp-entity>
           <neighbors>
            <neighbor>
             <neighbor-address>%s</neighbor-address>
             <neighbor-afs>
              <neighbor-af>
               <af-name>ipv4-unicast</af-name>
               <activate></activate>
               <route-policy-in>pass</route-policy-in>
               <route-policy-out>pass</route-policy-out>
              </neighbor-af>
             </neighbor-afs>
            </neighbor>
           </neighbors>
          </bgp-entity>
         </default-vrf>
        </four-byte-as>
       </instance-as>
      </instance>
     </bgp>
     </config>''' % (my_as, nbr_name)

     # connect to netconf agent
     with manager.connect(host=ios_xe_host, port=ios_xe_port, username=ios_xe_user,
                          password=ios_xe_pass, hostkey_verify=False,
                          device_params={'name': 'csr'}) as m:

         #m.lock()

         # execute netconf operation
         edit_result = m.edit_config(target='candidate', config=payload)
         print(edit_result)

         m.commit()
         #m.unlock()

def netconf_get_int_oper_data(interface, ios_xe_host, ios_xe_port, ios_xe_user, ios_xe_pass):
    """
    This function will retrieve the operational data for the interface via NETCONF
    :param interface: interface name
    :param ios_xe_host: device IPv4 address
    :param ios_xe_port: NETCONF port
    :param ios_xe_user: username
    :param ios_xe_pass: password
    :return interface operational data in XML
    """

    with manager.connect(host=ios_xe_host, port=ios_xe_port, username=ios_xe_user,
                         password=ios_xe_pass, hostkey_verify=False,
                         device_params={'name': 'default'},
                         allow_agent=False, look_for_keys=False) as m:
        # XML filter to issue with the get operation
        # IOS-XE 16.6.2+        YANG model called "ietf-interfaces"

        interface_state_filter = '''
                                            <filter xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
                                                <interfaces-state xmlns="urn:ietf:params:xml:ns:yang:ietf-interfaces">
                                                    <interface>
                                                        <name>''' + interface + '''</name>
                                                    </interface>
                                                </interfaces-state>
                                            </filter>
                                        '''

        try:
            result = m.get(interface_state_filter)
            oper_data = xml.dom.minidom.parseString(result.xml)
        except:
            oper_data = 'unknown'
        return oper_data


def netconf_get_int_oper_status(interface, ios_xe_host, ios_xe_port, ios_xe_user, ios_xe_pass):
    """
    This function will retrieve the IPv4 address configured on the interface via NETCONF
    :param interface: interface name
    :param ios_xe_host: device IPv4 address
    :param ios_xe_port: NETCONF port
    :param ios_xe_user: username
    :param ios_xe_pass: password
    :return oper_status: the interface operational status - up/down
    """
    with manager.connect(host=ios_xe_host, port=ios_xe_port, username=ios_xe_user,
                         password=ios_xe_pass, hostkey_verify=False,
                         device_params={'name': 'default'},
                         allow_agent=False, look_for_keys=False) as m:
        # XML filter to issue with the get operation
        # IOS-XE 16.6.2+        YANG model called "ietf-interfaces"

        interface_state_filter = '''
                                    <filter xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
                                        <interfaces-state xmlns="urn:ietf:params:xml:ns:yang:ietf-interfaces">
                                            <interface>
                                                <name>''' + interface + '''</name>
                                                <oper-status/>
                                            </interface>
                                        </interfaces-state>
                                    </filter>
                                '''

        result = m.get(interface_state_filter)
        xml_doc = xml.dom.minidom.parseString(result.xml)
        int_info = xml_doc.getElementsByTagName('oper-status')
        try:
            oper_status = int_info[0].firstChild.nodeValue
        except:
            oper_status = 'unknown'
        return oper_status


def netconf_save_running_config_to_file(file_and_path, ios_xe_host, ios_xe_port, ios_xe_user, ios_xe_pass):
    """
    This function will save the running configuration of the device {ios_xe_host} to file
    :param file_and_path: the path and the file name. example flash:/folder/file
    :param ios_xe_host: device IPv4 address
    :param ios_xe_port: NETCONF port
    :param ios_xe_user: username
    :param ios_xe_pass: password
    :return success/failed
    """
    # define the rpc payload, source and destination file
    # IOS-XE 16.8+        YANG model called "Cisco-IOS-XE-rpc"
    payload = [
        '''
        <copy xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-rpc">
          <_source>running-config</_source>
          <_destination>''' + file_and_path + '''</_destination>
        </copy>
        '''
    ]

    # connect to netconf agent
    with manager.connect(host=ios_xe_host, port=ios_xe_port, username=ios_xe_user,
                         password=ios_xe_pass, hostkey_verify=False,
                         device_params={'name': 'csr'},
                         allow_agent=False, look_for_keys=False) as m:

        # execute netconf operation
        for rpc in payload:
            try:
                response = m.dispatch(et.fromstring(rpc))
                response_str = json.dumps(xmltodict.parse(str(response)))
                if 'bytes copied' in response_str:
                    result = 'Successful'
                else:
                    result = 'Failed'
                data = response.data_ele
            except RPCError as e:
                data = e._raw
                result = 'Failed'

    return data, result


def restconf_get_hostname(ios_xe_host, ios_xe_user, ios_xe_pass):
    """
    This function will retrieve the device hostname via RESTCONF
    :param ios_xe_host: device IPv4 address
    :param ios_xe_user: username
    :param ios_xe_pass: password
    :return IOS XE device hostname
    """
    dev_auth = HTTPBasicAuth(ios_xe_user, ios_xe_pass)
    url = 'https://' + ios_xe_host + '/restconf/data/Cisco-IOS-XE-native:native/hostname'
    header = {'Content-type': 'application/yang-data+json', 'accept': 'application/yang-data+json'}
    response = requests.get(url, headers=header, verify=False, auth=dev_auth)
    hostname_json = response.json()
    hostname = hostname_json['Cisco-IOS-XE-native:hostname']
    return hostname


def restconf_get_int_oper_data(interface, ios_xe_host, ios_xe_user, ios_xe_pass):
    """
    This function will retrieve the operational data for the interface via RESTCONF
    :param interface: interface name
    :param ios_xe_host: device IPv4 address
    :param ios_xe_user: username
    :param ios_xe_pass: password
    :return interface operational data in JSON
    """

    # encode the interface URI: GigabitEthernet0/0/2 - http://10.104.50.97/restconf/data/Cisco-IOS-XE-native:native/interface/GigabitEthernet=0%2F0%2F2
    # ref.: https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/prog/configuration/166/b_166_programmability_cg/restconf_prog_int.html

    interface_uri = interface.replace('/', '%2F')
    interface_uri = interface_uri.replace('.', '%2E')
    dev_auth = HTTPBasicAuth(ios_xe_user, ios_xe_pass)
    url = 'https://' + ios_xe_host + '/restconf/data/ietf-interfaces:interfaces-state/interface=' + interface_uri
    header = {'Content-type': 'application/yang-data+json', 'accept': 'application/yang-data+json'}
    response = requests.get(url, headers=header, verify=False, auth=dev_auth)
    interface_info = response.json()
    oper_data = interface_info['ietf-interfaces:interface']
    return oper_data


def restconf_save_running_config(ios_xe_host, ios_xe_user, ios_xe_pass):
    """
    This function will save the device {ios_xe_host} running configuration to startup-config via RESTCONF
    :param ios_xe_host: device IPv4 address
    :param ios_xe_user: username
    :param ios_xe_pass: password
    :return save config operation result
    """
    dev_auth = HTTPBasicAuth(ios_xe_user, ios_xe_pass)
    url = 'https://' + ios_xe_host + '/restconf/operations/cisco-ia:save-config'
    header = {'Content-type': 'application/yang-data+json', 'accept': 'application/yang-data+json'}
    response = requests.post(url, headers=header, verify=False, auth=dev_auth)
    save_info = response.json()
    save_config_result = save_info['cisco-ia:output']['result']
    return save_config_result


def restconf_rollback_to_saved_config(file_and_path, ios_xe_host, ios_xe_user, ios_xe_pass):
    """
    This function will force a rollback of the device {ios_xe_host} saved configuration {file_and_path}
    to running configuration via RESTCONF
    :param file_and_path: the path and the file name. example flash:/folder/file
    :param ios_xe_host: device IPv4 address
    :param ios_xe_user: username
    :param ios_xe_pass: password
    :return save config operation result
    """
    dev_auth = HTTPBasicAuth(ios_xe_user, ios_xe_pass)
    url = 'https://' + ios_xe_host + '/restconf/operations/cisco-ia:rollback'
    header = {'Content-type': 'application/yang-data+json', 'accept': 'application/yang-data+json'}
    payload = {"rollback": [{"target-url": file_and_path}]}
    response = requests.post(url, headers=header, data=json.dumps(payload), verify=False, auth=dev_auth)
    rollback_info = response.json()
    rollback_result = rollback_info['cisco-ia:output']['result']
    return rollback_result


def restconf_create_checkpoint_config(ios_xe_host, ios_xe_user, ios_xe_pass):
    """
    This function will create a checkpoint config for the device {ios_xe_host} via RESTCONF
    :param ios_xe_host: device IPv4 address
    :param ios_xe_user: username
    :param ios_xe_pass: password
    :param file_and_path: the path and the file name. example flash:/folder/file
    :return save config operation result
    """
    dev_auth = HTTPBasicAuth(ios_xe_user, ios_xe_pass)
    url = 'https://' + ios_xe_host + '/restconf/operations/cisco-ia:checkpoint/'
    header = {'Content-type': 'application/yang-data+json', 'accept': 'application/yang-data+json'}
    # payload = {"rollback": [{"target-url": file_and_path}]}
    response = requests.post(url, headers=header, verify=False, auth=dev_auth)
    checkpoint_info = response.json()
    print(checkpoint_info)
    checkpoint_result = checkpoint_info['cisco-ia:output']['result']
    return checkpoint_result


def restconf_get_capabilities(ios_xe_host, ios_xe_user, ios_xe_pass):
    """
    This function will retrieve the device capabilities via RESTCONF
    :param ios_xe_host: device IPv4 address
    :param ios_xe_user: username
    :param ios_xe_pass: password
    :return: device capabilities
    """
    dev_auth = HTTPBasicAuth(ios_xe_user, ios_xe_pass)
    url = 'https://' + ios_xe_host + '/restconf/data/netconf-state/capabilities'
    header = {'Content-type': 'application/yang-data+json', 'accept': 'application/yang-data+json'}
    response = requests.get(url, headers=header, verify=False, auth=dev_auth)
    capabilities_json =  response.json()
    return capabilities_json['ietf-netconf-monitoring:capabilities']

def sample_netconf():
    ## IOS XE 

    #hostname = netconf_get_hostname('10.10.20.48', 830, 'cisco', 'cisco_1234!')
    #print(hostname)
    #hostname = restconf_get_hostname('10.10.20.48', 'cisco', 'cisco_1234!')
    #print(hostname)
    #rtrid = netconf_get_bgp_rtrid('10.10.20.48', 830, 'cisco', 'cisco_1234!')
    #print(rtrid)
    #netconf_set_bgp_rtrid('10.10.20.48', 830, 'cisco', 'cisco_1234!')
    #rtrid = netconf_get_bgp_rtrid('10.10.20.48', 830, 'cisco', 'cisco_1234!')
    #print(rtrid)
    #hostname = netconf_get_hostname('10.10.20.48', 830, 'cisco', 'cisco_1234!')
    #print(hostname)

    ## IOS XR

        #rtrid = netconf_get_xr_bgp_rtrid('10.10.20.170', 8321, 'admin', 'admin')
        #print("BGP Router ID: ", rtrid)

    ## PUSH CFG TO R1
    print("PUSHING CFG TO R1")
    netconf_push_xr_config('10.10.20.170', 8321, 'admin', 'admin', 65000, 65001, '10.1.1.1', '1.1.1.1', '10.1.1.2')

    ## PUSH CFG TO R2
    print("PUSHING CFG TO R2")
    netconf_push_xr_config('10.10.20.170', 8331, 'admin', 'admin', 65001, 65000, '10.1.1.2', '2.2.2.2', '10.1.1.1')

    ## APPLY RPL on R2
    netconf_xr_apply_nbr_rpl('10.10.20.170', 8331, 'admin', 'admin', 65001, '10.1.1.1')

        #rtrid = netconf_get_xr_bgp_rtrid('10.10.20.170', 8321, 'admin', 'admin')
        #print("BGP Router ID: ", rtrid)

    print("sleep for 60 sec")
    time.sleep(60);

    ## FIND ADVERTISED PATH COUNT AT R1
    print("Finding advertised path count on R1 towards R2...")
    adv_count = netconf_get_xr_nbr_adv_count('10.10.20.170', 8321, 'admin', 'admin')
    print("Advertised Path Count: ", adv_count)

    if adv_count == '0':
        print("Probably, outbound route-policy is not set for ebgp neighbor. Lets set it and check back")
        ## APPLY RPL on R1
        print("Applying outbound route-policy towards R2...")
        netconf_xr_apply_nbr_rpl('10.10.20.170', 8321, 'admin', 'admin', 65000, '10.1.1.2')
        print("sleep for 10 sec")
        time.sleep(10);
        ## FIND ADVERTISED PATH COUNT AT R1
        adv_count = netconf_get_xr_nbr_adv_count('10.10.20.170', 8321, 'admin', 'admin')
        print("Now, Advertised Path Count: ", adv_count)


if __name__ == "__main__":
    sample_netconf()

