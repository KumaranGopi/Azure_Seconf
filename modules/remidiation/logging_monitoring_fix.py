import requests
import json
from modules.constants import url_const
from modules.compliance.logging_monitoring import logging_monitoring

class logging_monitoring_fix:
    def __init__(self, sub_id, tenant_id, client_id, client_sec):
        self.SUBSCRIPTION_ID = sub_id
        self.TENANT_ID = tenant_id
        self.CLIENT_ID = client_id
        self.CLIENT_SECRECT = client_sec
        self.lm = logging_monitoring(self.SUBSCRIPTION_ID,self.TENANT_ID,self.CLIENT_ID,self.CLIENT_SECRECT)
    

    # CIS 5.1.1: Ensure that a Log Profile exists

    def log_profile_fix(self, mgmt_token):
        log_profile_data = self.lm.log_profile(mgmt_token)
        if not log_profile_data["value"]:
            while True:
                try:
                    log_retention_Days = int(input("Enter the retention days for Activity logs(Enter 365 or 0):"))
                except ValueError as _:
                    print("Enter only interger values")
                    continue
                if log_retention_Days == 365 or log_retention_Days == 0:
                    break
                else:
                    print("Enter Value as 365 or 0 as per CIS guidelines!!")
                    continue
                    
            
            log_retention_storage = input("Enter StorageAccount_Id(To store Activity Logs): ")
            if log_retention_Days == 365:
                enabled = True
            else:
                enabled = False
            try:
                profile_fix_url = url_const.CREATE_LOG_PROFILE.format(self.SUBSCRIPTION_ID, "default")
                profile_fix_header = {'Authorization': 'Bearer {}'.format(mgmt_token),
                                    'Content-Type': 'application/json'}
                profile_fix_data = {"properties": {"locations": ["australiacentral","australiacentral2","australiaeast","australiasoutheast",
                                                                "brazilsouth","canadacentral","canadaeast","centralindia","centralus","eastasia",
                                                                "eastus","eastus2","francecentral","francesouth","germanynorth","germanywestcentral",
                                                                "japaneast","japanwest","koreacentral","koreasouth","northcentralus","northeurope",
                                                                "norwayeast","norwaywest","southafricanorth","southafricawest","southcentralus",
                                                                "southindia","southeastasia","switzerlandnorth","switzerlandwest","uaecentral",
                                                                "uaenorth","uksouth","ukwest","westcentralus","westeurope","westindia","westus",
                                                                "westus2","global"],"categories": ["Write","Delete","Action"],
                                                                "retentionPolicy": {"enabled": enabled,"days": log_retention_Days},
                                                                "storageAccountId": ""+ log_retention_storage +""}}
                profile_fix_req = requests.put(profile_fix_url, headers=profile_fix_header, data=json.dumps(profile_fix_data))
                if profile_fix_req.status_code == 200:
                    print(" ===> Log Profile Created Successfully ")
                else:
                    print(" ===> Not updated!!! Error")
            except KeyError as ke:
                pass



    # CIS 5.1.2: Ensure that Activity Log Retention is set 365 days or greater
        
    def Activity_log_retention_fix(self, mgmt_token):
        log_retention_data = self.lm.Activity_log_retention(mgmt_token)
        for each_item in log_retention_data["value"]:
            if each_item["properties"]["retentionPolicy"]["enabled"] is False and each_item["properties"]["retentionPolicy"]["days"] == 0:
                pass
            elif each_item["properties"]["retentionPolicy"]["enabled"] is True and each_item["properties"]["retentionPolicy"]["days"] >= 365:
                pass
            else:
                while True:
                    try:
                        log_retention_Days = int(input("Enter the retention days for Activity logs(Enter 365 or 0):"))
                    except ValueError as _:
                        print("Enter only interger values")
                        continue
                    if log_retention_Days == 365 or log_retention_Days == 0:
                        break
                    else:
                        print("Enter Value as 365 or 0 as per CIS guidelines!!")
                        continue
                if log_retention_Days == 365:
                    enabled = True
                else:
                    enabled = False
                log_retention_url = url_const.CREATE_LOG_PROFILE.format(self.SUBSCRIPTION_ID, each_item["name"])
                log_retention_header = {'Authorization': 'Bearer {}'.format(mgmt_token),
                                 'Content-Type': 'application/json'}
                log_retention_data = {"properties": {"locations": each_item["properties"]["locations"],"categories": each_item["properties"]["categories"],
                                                    "retentionPolicy": {"enabled": enabled, "days": log_retention_Days},"storageAccountId": ""+ each_item["properties"]["storageAccountId"] +""}}
                log_retention_req = requests.put(log_retention_url, headers=log_retention_header, data=json.dumps(log_retention_data))
                if log_retention_req.status_code == 200:
                    print(" ===> Activity Log Retention Days Updated Successfully ")
                else:
                    print(" ===> Not updated!!! Error ")


    # CIS 5.1.4: Ensure the log profile captures activity logs for all regions including global
    
    def Activity_log_location_fix(self, mgmt_token):
        log_location_data = self.lm.Activity_log_locations(mgmt_token)
        for each_item in log_location_data["value"]:
            if len(each_item["properties"]["locations"]) != 41:
                locations = ["australiacentral","australiacentral2","australiaeast","australiasoutheast","brazilsouth","canadacentral",
                            "canadaeast","centralindia","centralus","eastasia","eastus","eastus2","francecentral","francesouth",
                            "germanynorth","germanywestcentral","japaneast","japanwest","koreacentral","koreasouth","northcentralus",
                            "northeurope","norwayeast","norwaywest","southafricanorth","southafricawest","southcentralus","southindia",
                            "southeastasia","switzerlandnorth","switzerlandwest","uaecentral","uaenorth","uksouth","ukwest",
                            "westcentralus","westeurope","westindia","westus","westus2","global"]
                log_location_url = url_const.CREATE_LOG_PROFILE.format(self.SUBSCRIPTION_ID, each_item["name"])
                log_location_header = {'Authorization': 'Bearer {}'.format(mgmt_token),
                                 'Content-Type': 'application/json'}
                log_location_fix_data = {"properties": {"locations": locations,"categories": each_item["properties"]["categories"],
                                                    "retentionPolicy": {"enabled": each_item["properties"]["retentionPolicy"]["enabled"], 
                                                    "days": each_item["properties"]["retentionPolicy"]["days"]},
                                                    "storageAccountId": ""+ each_item["properties"]["storageAccountId"] +""}}
                log_location_req = requests.put(log_location_url, headers=log_location_header, data=json.dumps(log_location_fix_data))
                if log_location_req.status_code == 200:
                    print(" ===> Activity Log locations Updated Successfully ")
                else:
                    print(" ===> Not updated!!! Error ")
    

    # CIS 5.1.5: Ensure the storage container storing the activity logs is not publicly accessible

    def log_container_fix(self,mgmt_token, str_token): # CIS 3.6
        log_storage_container_data = self.lm.log_container_comp(mgmt_token, str_token)
        if log_storage_container_data is None:
            pass
        for each_property in log_storage_container_data:
            splitted_value = each_property[0].split('/')
            req_url = url_const.STORAGE_CONTAINER_FIX.format(splitted_value[2], splitted_value[4], splitted_value[8], each_property[1])
            headers = {'Authorization': 'Bearer {}'.format(mgmt_token), 'Content-Type': 'application/json'}
            data = {"properties": {"publicAccess": "None"}}
            r = requests.patch(req_url,headers=headers,data=json.dumps(data))
            if r.status_code == 200:
                print(" ===> Storage Container", each_property[1].upper(),"is set to private ")
            else:
                print(" ===> Not updated!!! Error ")
                

    # CIS 6.5: Ensure that Network Watcher is 'Enabled'

    def network_watcher_fix(self, token):
        network_watcher_data = self.lm.network_watcher_enable(token)

        if len(network_watcher_data) != 0:
            resource_group = input("Enter ResourceGroup Name: ")
            network_watcher_name = resource_group + "_{}"

            try:
                for each_item in network_watcher_data:
                    req_url = url_const.CREATE_NETWORK_WATCHER.format(self.SUBSCRIPTION_ID, resource_group, network_watcher_name.format(each_item))
                    headers = {'Authorization': 'Bearer {}'.format(token), 'Content-Type': 'application/json'}
                    data = {"location": each_item,"properties": {}}
                    r = requests.put(req_url,headers=headers,data=json.dumps(data))
                    if r.status_code != 200 or r.status_code != 201:
                        pass
            except Exception as e:
                print(" ===> Not updated!!! Error", e)

            print(" ===> Network Watchers Enabled Successfully")
        