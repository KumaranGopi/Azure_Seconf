import requests
import json
from modules.constants import url_const

class KeyVault:
    def __init__(self, sub_id,  tenant_id, client_id, client_sec):
        self.SUBSCRIPTION_ID = sub_id
        self.TENANT_ID = tenant_id
        self.CLIENT_ID = client_id
        self.CLIENT_SECRECT = client_sec
        self.inc = 0


    # CIS 8.1: Ensure that the expiration date is set on all keys
    
    def key_expiration(self, mgmt_token, vault_token):
        key_exp_nc = list()
        print("\nCIS 8.1: Ensure that the expiration date is set on all keys")
        req_url = url_const.LIST_KEY_VAULT.format(self.SUBSCRIPTION_ID)
        req_header = {'Authorization': 'Bearer {}'.format(mgmt_token),
                      'Content-Type': 'application/json'}
        r = requests.get(req_url, headers=req_header)
        self.x = r.json()

        for each_item in self.x["value"]:
            get_key_url = url_const.GET_KEYS.format(each_item["properties"]["vaultUri"])
            key_req_header = {'Authorization':'Bearer {}'.format(vault_token),
                      'Content-Type': 'application/json'}
            req = requests.get(get_key_url, headers=key_req_header)
            a = req.json()
            # print(a)
            for key_resp in a["value"]:
                try:
                    splitted_value = key_resp["kid"].split('/')
                    key_resp["attributes"]["exp"]
                    print(" ===>",splitted_value[4].upper()," in KeyVault",each_item["name"].upper(),"is compliant ")
                except KeyError as ke:
                    print(" ===>",splitted_value[4].upper()," in KeyVault",each_item["name"].upper(),"is not compliant ")
                    key_exp_nc.append([])
                    key_exp_nc[self.inc].append(key_resp["kid"])
                    key_exp_nc[self.inc].append(each_item["properties"]["vaultUri"])
                    self.inc += 1
        self.inc = 0
        return key_exp_nc


    # CIS 8.2: Ensure that the expiration date is set on all Secrets

    def secret_expiration(self, mgmt_token, vault_token):
        sec_exp_nc = list()
        print("\nCIS 8.2: Ensure that the expiration date is set on all Secrets")
        for each_item in self.x["value"]:
            get_key_url = url_const.GET_SECRETS.format(each_item["properties"]["vaultUri"])
            key_req_header = {'Authorization':'Bearer {}'.format(vault_token),
                      'Content-Type': 'application/json'}
            req = requests.get(get_key_url, headers=key_req_header)
            a = req.json()
            for sec_resp in a["value"]:
                try:
                    splitted_value = sec_resp["id"].split('/')
                    sec_resp["attributes"]["exp"]
                    print(" ===>",splitted_value[4].upper()," in KeyVault",each_item["name"].upper(),"is compliant ")
                except KeyError as ke:
                    print(" ===>",splitted_value[4].upper()," in KeyVault",each_item["name"].upper(),"is not compliant ")
                    sec_exp_nc.append([])
                    sec_exp_nc[self.inc].append(sec_resp["id"])
                    sec_exp_nc[self.inc].append(each_item["properties"]["vaultUri"])
                    self.inc += 1

        self.inc = 0
        return sec_exp_nc


    # CIS 8.4: Ensure the key vault is recoverable

    def key_vault_recover(self, mgmt_token):
        key_vault_nc = list()
        print("\nCIS 8.4: Ensure the key vault is recoverable")
        for each_item in self.x["value"]:
            try:
                each_item["properties"]["enableSoftDelete"] and each_item["properties"]["enablePurgeProtection"]
                print(" ===> Keyvault",each_item["name"].upper(),"is complaint ")
            except KeyError as ke:
                print(" ===> Keyvault",each_item["name"].upper(),"is not complaint ")
                key_vault_nc.append([])
                key_vault_nc[self.inc].append(each_item["id"])
                self.inc += 1
        self.inc = 0
        return key_vault_nc
