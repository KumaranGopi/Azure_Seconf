import requests
import json
import xmltodict
import datetime
from modules.constants import url_const

class logging_monitoring:

    def __init__(self, sub_id,  tenant_id, client_id, client_sec):
        self.SUBSCRIPTION_ID = sub_id
        self.TENANT_ID = tenant_id
        self.CLIENT_ID = client_id
        self.CLIENT_SECRECT = client_sec
        self.inc = 0
    

    # CIS 5.1.1: Ensure that a Log Profile exists

    def log_profile(self, mgmt_token):
        req_url = url_const.LOG_PROFILES_LIST.format(self.SUBSCRIPTION_ID)  
        req_header = {'Authorization': 'Bearer {}'.format(mgmt_token),
                      'Content-Type': 'application/json'}
        r = requests.get(req_url, headers=req_header)
        x = r.json()
        print("\nCIS 5.1.1: Ensure that a Log Profile exists")
        if not x["value"]:
            print(" ===> No Log Profile exists !! ")
        else:
            print(" ===> Log Profile exists ")
        return x
    

    # CIS 5.1.2: Ensure that Activity Log Retention is set 365 days or greater

    def Activity_log_retention(self, mgmt_token):
        req_url = url_const.LOG_PROFILES_LIST.format(self.SUBSCRIPTION_ID)  
        req_header = {'Authorization': 'Bearer {}'.format(mgmt_token),
                      'Content-Type': 'application/json'}
        r = requests.get(req_url, headers=req_header)
        x = r.json()
        print("\nCIS 5.1.2: Ensure that Activity Log Retention is set 365 days or greater")
        for each_item in x["value"]:
            if each_item["properties"]["retentionPolicy"]["enabled"] is False and each_item["properties"]["retentionPolicy"]["days"] == 0:
                print(" ===> Your Subscription is Compliant ")
            elif each_item["properties"]["retentionPolicy"]["enabled"] is True and each_item["properties"]["retentionPolicy"]["days"] >= 365:
                print(" ===> Your Subscription is Compliant ")
            else:
                print(" ===> Your Subscription is not Compliant ")
        return x
    

    # CIS 5.1.4: Ensure the log profile captures activity logs for all regions including global 

    def Activity_log_locations(self, mgmt_token):
        req_url = url_const.LOG_PROFILES_LIST.format(self.SUBSCRIPTION_ID)  
        req_header = {'Authorization': 'Bearer {}'.format(mgmt_token),
                      'Content-Type': 'application/json'}
        r = requests.get(req_url, headers=req_header)
        x = r.json()
        print("\nCIS 5.1.4: Ensure the log profile captures activity logs for all regions including global")
        for each_item in x["value"]:
            if len(each_item["properties"]["locations"]) == 41:
                print(" ===> Your Subscription is Compliant ")
            else:
                print(" ===> Your Subscription is not Compliant ")
        return x
    

    # CIS 5.1.5: Ensure the storage container storing the activity logs is not publicly accessible

    def log_container_comp(self, mgmt_token, storage_token):
        log_container_nc = list()
        req_url = url_const.LOG_PROFILES_LIST.format(self.SUBSCRIPTION_ID)  
        req_header = {'Authorization': 'Bearer {}'.format(mgmt_token),
                      'Content-Type': 'application/json'}
        r = requests.get(req_url, headers=req_header)
        x = r.json()
        print("\nCIS 5.1.5: Ensure the storage container storing the activity logs is not publicly accessible")
        StorageAccount_list = list()
        for b in x["value"]:
            StorageAccount_list.append([])
            StorageAccount_list[self.inc].append(b["properties"]["storageAccountId"])
            self.inc += 1  
        for each_property in StorageAccount_list:
            splitted_value = each_property[0].split('/')
            req_url = url_const.STORAGE_CONTAINERS_LIST.format(splitted_value[8])
            request_time = datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
            req_header = {'Authorization': 'Bearer {}'.format(storage_token),'x-ms-version': '2019-07-07' , 'x-ms-date': request_time}
            r = requests.get(req_url, headers=req_header)
            xpars = xmltodict.parse(r.text)
            container_info = json.loads(json.dumps(xpars))
            print(container_info)
            try:
                if container_info["EnumerationResults"]["Containers"] is None:
                    print(" ===> No containers found in", splitted_value[8].upper())
                    continue
            except KeyError as ke:
                print(" ===> Secure network firewall rules are enabled in", splitted_value[8].upper())
                continue
            log_container_comp_info = container_info["EnumerationResults"]["Containers"]["Container"]
            if isinstance(log_container_comp_info, list):
                for each_con in log_container_comp_info:
                    try:
                        if each_con["Name"] == "insights-operational-logs":
                            check_pub = each_con["Properties"]["PublicAccess"]
                            print(" ===> The container", each_con["Name"].upper(), "is not compliant ")
                    except KeyError as ke:
                        print(" ===> The container", each_con["Name"].upper(), "is compliant ")
            if isinstance(log_container_comp_info, dict):
                try:
                    if log_container_comp_info["Name"] == "insights-operational-logs":
                        check_pub = log_container_comp_info["Properties"]["PublicAccess"]
                        print(" ===> The container", log_container_comp_info["Name"].upper(), "is not compliant ")
                        log_container_nc.append([])
                        log_container_nc[self.inc].append(each_property[0])
                        log_container_nc[self.inc].append(log_container_comp_info["Name"])
                        self.inc += 1
                    else:
                        print(" ===> 'insights-operational-logs' container is not found ")
                except KeyError as ke:
                    print(" ===> The container", log_container_comp_info["Name"].upper(), "is compliant ")

        self.inc = 0
        return log_container_nc

    
    # CIS 6.5: Ensure that Network Watcher is 'Enabled'

    def network_watcher_enable(self, mgmt_token):
        req_url = url_const.NETWORK_WATCHER_LIST.format(self.SUBSCRIPTION_ID)  
        req_header = {'Authorization': 'Bearer {}'.format(mgmt_token),
                      'Content-Type': 'application/json'}
        r = requests.get(req_url, headers=req_header)
        x = r.json()

        locations = ["australiacentral","australiaeast","australiasoutheast","brazilsouth",
                    "canadacentral","canadaeast","centralindia","centralus","eastasia",
                    "eastus","eastus2","francecentral","germanywestcentral","japaneast",
                    "japanwest","koreacentral","koreasouth","northcentralus","northeurope",
                    "norwayeast","southafricanorth","southcentralus","southindia","southeastasia",
                    "switzerlandnorth","uaenorth","uksouth","ukwest","westcentralus",
                    "westeurope","westindia","westus","westus2"]
        print("\nCIS 6.5: Ensure that Network Watcher is 'Enabled'")           
        current_locations = list()
        for each_item in x["value"]:
            current_locations.append(each_item["location"])
        
        nc_locations = set(locations).difference(current_locations)
            
        if len(nc_locations) is not 0:
            print(" ===> Network watcher NOT COMPLIANT")
        else:
            print(" ===> Network watcher is COMPLIANT")

        return nc_locations