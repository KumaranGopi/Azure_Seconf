import requests
import json
import xmltodict
import datetime
from modules.constants import url_const


class StorageAccount:

    def __init__(self, sub_id,  tenant_id, client_id, client_sec):
        self.SUBSCRIPTION_ID = sub_id
        self.TENANT_ID = tenant_id
        self.CLIENT_ID = client_id
        self.CLIENT_SECRECT = client_sec
        self.inc = 0


    # CIS 3.1: Ensure that 'Secure transfer required' is set to 'Enabled'

    def get_storage_account_list(self, mgmt_token):
        """To list the azure storage account details

        """
        req_url = url_const.STORAGE_ACCOUNT_LIST.format(self.SUBSCRIPTION_ID)
        req_header = {'Authorization': 'Bearer {}'.format(mgmt_token),
                      'Content-Type': 'application/json'}
        r = requests.get(req_url, headers=req_header)
        x = r.json()

        if not x["value"]:
            print("===> No SQL servers found!!")
        
        StorageAccount_list = list()
        for _ in x:
            j = 0
            for b in x["value"]:
                StorageAccount_list.append([])
                StorageAccount_list[j].append(b["id"])
                StorageAccount_list[j].append(b["properties"]["supportsHttpsTrafficOnly"])
                StorageAccount_list[j].append(b["name"])
                StorageAccount_list[j].append(b["properties"]["networkAcls"]["defaultAction"])
                j += 1

        self.y = StorageAccount_list 
        print("\nCIS 3.1: Ensure that 'Secure transfer required' is set to 'Enabled'")
                
        for each_property in self.y:
            if each_property[1] is False :
                print(" ===> Storage Account " + each_property[2].upper() + " is non - compliant") 
            elif each_property[1] is True :
                print(" ===> Storage Account " + each_property[2].upper() + " is compliant")
            else:
                print(" ===> Storage Account not found with this subscription ")
        
        return StorageAccount_list


    # CIS 3.6 Ensure that 'Public access level' is set to Private for blob containers
    
    def get_storage_containers_list(self, storage_token):
        """To list the azure storage containers details
        """
        container_pub_nc = list()
        print("\nCIS 3.6: Ensure that 'Public access level' is set to Private for blob containers")
        for each_property in self.y:
            req_url = url_const.STORAGE_CONTAINERS_LIST.format(each_property[2])
            request_time = datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
            req_header = {'Authorization': 'Bearer {}'.format(storage_token),'x-ms-version': '2019-07-07' , 'x-ms-date': request_time}
            r = requests.get(req_url, headers=req_header)
            xpars = xmltodict.parse(r.text)
            container_info = json.loads(json.dumps(xpars))
            
            try:
                if container_info["EnumerationResults"]["Containers"] is None:
                    print(" ===> No containers found in", each_property[2].upper())
                    continue
            except KeyError as ke:
                print(" ===> Secure network firewall rules are enabled in", each_property[2].upper())
                continue
            
            container_comp_info = container_info["EnumerationResults"]["Containers"]["Container"]
            if isinstance(container_comp_info, list):
                for each_con in container_comp_info:
                    try:
                        check_pub = each_con["Properties"]["PublicAccess"]
                        print(" ===> The container", each_con["Name"].upper(), "is not compliant")
                        container_pub_nc.append([])
                        container_pub_nc[self.inc].append(each_property[0])
                        container_pub_nc[self.inc].append(each_con["Name"])
                        self.inc += 1
                    except KeyError as ke:
                        print(" ===> The container", each_con["Name"].upper(), "is compliant")
            
            if isinstance(container_comp_info, dict):
                try:
                    check_pub = container_comp_info["Properties"]["PublicAccess"]
                    print(" ===> The container", container_comp_info["Name"].upper(), "is not compliant")
                    container_pub_nc.append([])
                    container_pub_nc[self.inc].append(each_property[0])
                    container_pub_nc[self.inc].append(container_comp_info["Name"])
                    self.inc += 1
                except KeyError as ke:
                    print(" ===> The container", container_comp_info["Name"].upper(), "is compliant")
        self.inc = 0
        return container_pub_nc


    # CIS 3.7: Ensure default network access rule for Storage Accounts is set to deny
            
    def get_networkaccess_rule_list(self, mgmt_token):
        print("\nCIS 3.7: Ensure default network access rule for Storage Accounts is set to 'deny' ")
        for each_property in self.y:
            if each_property[3] == "Allow":
                 print(" ===> Storage Account " + each_property[2].upper() + " is non - compliant") 
            elif each_property[3] == "Deny" :
                print(" ===> Storage Account " + each_property[2].upper() + " is compliant")
            else:
                print(" ===> Storage Account not found with this subscription")
