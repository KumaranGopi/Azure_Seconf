import requests
import json
from modules.compliance.storage_account import StorageAccount
from modules.constants import url_const
class StorageAccountFix:

    def __init__(self, sub_id, tenant_id, client_id, client_sec):
        self.SUBSCRIPTION_ID = sub_id
        self.TENANT_ID = tenant_id
        self.CLIENT_ID = client_id
        self.CLIENT_SECRECT = client_sec
        self.st = StorageAccount(self.SUBSCRIPTION_ID,self.TENANT_ID,self.CLIENT_ID,self.CLIENT_SECRECT)


    # CIS 3.1: Ensure that 'Secure transfer required' is set to 'Enabled' 

    def storage_account_fix(self, token): # CIS 3.1
        storage_https_data = self.st.get_storage_account_list(token)
        for each_property in storage_https_data:
            unsan_resource_group = each_property[0]
            temp_resource_group = unsan_resource_group.split('/')
            san_resource_group = temp_resource_group[4]
            
            if each_property[1] is False:
                req_url = url_const.STORAGE_ACCOUNT_HTTPS_ENABLE.format(self.SUBSCRIPTION_ID, san_resource_group,each_property[2])
                headers = {'Authorization': 'Bearer {}'.format(token), 'Content-Type': 'application/json'}
                data = {"properties": {"supportsHttpsTrafficOnly":'True'}}
                r = requests.patch(req_url,headers=headers,data=json.dumps(data))
                if r.status_code == 200:
                    print(" ===> Storage account " + each_property[2].upper() + " is now https enabled ")
                else:
                    print(" ===> Not updated!!! Error ")


    # CIS 3.6 Ensure that 'Public access level' is set to Private for blob containers

    def storage_container_fix(self, str_token, mgmt_token): 
        storage_container_data = self.st.get_storage_containers_list(str_token)
        if storage_container_data is None:
            pass
        for each_property in storage_container_data:
            splitted_value = each_property[0].split('/')
            req_url = url_const.STORAGE_CONTAINER_FIX.format(splitted_value[2], splitted_value[4], splitted_value[8], each_property[1])
            headers = {'Authorization': 'Bearer {}'.format(mgmt_token), 'Content-Type': 'application/json'}
            data = data = {"properties": {"publicAccess": "None"}}
            r = requests.patch(req_url,headers=headers,data=json.dumps(data))
            if r.status_code == 200:
                print(" ===> Storage Container", each_property[1].upper(),"is set to private ")
            else:
                print(" ===> Not updated!!! Error ")
    

    # CIS 3.7: Ensure default network access rule for Storage Accounts is set to deny

    def networkaccess_rule_fix(self, token): # CIS 3.7
        storage_network_rule = self.st.get_storage_account_list(token)
        for each_property in storage_network_rule:
            unsan_resource_group = each_property[0]
            temp_resource_group = unsan_resource_group.split('/')
            san_resource_group = temp_resource_group[4]

            if each_property[3] == "Allow":
                req_url = url_const.STORAGE_NETWORKACCESS_RULE_DENY.format(self.SUBSCRIPTION_ID, san_resource_group, each_property[2])
                headers = {'Authorization': 'Bearer {}'.format(token), 'Content-Type': 'application/json'}
                data = {"properties": {"networkAcls": {"defaultAction": "Deny"}}}
                r = requests.patch(req_url, headers = headers, data = json.dumps(data))
                if r.status_code == 200:
                    print(" ===> Storage account", each_property[2].upper(),"NetworkAccess rules are enabled ")
                else:
                    print(" ===> Not updated!!! Error ")
