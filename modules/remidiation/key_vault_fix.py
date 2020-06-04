import requests
import json
import datetime
import calendar
from modules.constants import url_const
from modules.compliance.key_vault import KeyVault


class KeyVaultFix:
    def __init__(self, sub_id,  tenant_id, client_id, client_sec):
        self.SUBSCRIPTION_ID = sub_id
        self.TENANT_ID = tenant_id
        self.CLIENT_ID = client_id
        self.CLIENT_SECRECT = client_sec
        self.inc = 0
        self.keyvault_comp = KeyVault(self.SUBSCRIPTION_ID,self.TENANT_ID,self.CLIENT_ID,self.CLIENT_SECRECT)


    # CIS 8.1: Ensure that the expiration date is set on all keys

    def key_expiration_fix(self, mgmt_token, vault_token):
        key_expiration_data = self.keyvault_comp.key_expiration(mgmt_token, vault_token)
        for each_item in key_expiration_data:
            splitted_value = each_item[0].split('/')
            req_url = url_const.GET_KEY_VERSION.format(each_item[1], splitted_value[4])
            req_header = {'Authorization': 'Bearer {}'.format(vault_token),
                      'Content-Type': 'application/json'}
            r = requests.get(req_url, headers=req_header)
            y = r.json()

            low_int = 0
            latest_kid = ""
            for b in y["value"]:
                temp = b["attributes"]["created"]
                if low_int < temp:
                    low_int = temp
                    latest_kid = b["kid"]
            
            split_kid = latest_kid.split('/')

            year = int(input("Enter a key_expiry year for key"+ splitted_value[4] + ":"))
            month = int(input("Enter a key_expiry month for key"+ splitted_value[4] + ":"))
            day = int(input("Enter a key_expiry day for key"+ splitted_value[4] + ":"))
            dt = datetime.date(year, month, day)
            time_stamp = calendar.timegm(dt.timetuple())
            keyexp_fix_uri = url_const.UPDATE_KEYS.format(each_item[1], splitted_value[4], split_kid[5])
            keyexp_fix_header = {'Authorization': 'Bearer {}'.format(vault_token),'Content-Type': 'application/json'}
            keyexp_fix_data = {"attributes": {"enabled": True, "exp": time_stamp}}
            keyexp_req = requests.patch(keyexp_fix_uri, headers=keyexp_fix_header, data=json.dumps(keyexp_fix_data))
            if keyexp_req.status_code == 200:
                print(" ===> Expiry date updated successfully for the key",splitted_value[4].upper(),"")
            else:
                print(" ===> Not updated!!! Error ")  


    # # CIS 8.2: Ensure that the expiration date is set on all Secrets

    def secret_expiration_fix(self, mgmt_token, vault_token):
        secret_expiration_data = self.keyvault_comp.secret_expiration(mgmt_token, vault_token)
        for each_item in secret_expiration_data:
            splitted_value = each_item[0].split('/')
            req_url = url_const.GET_SECRET_VERSION.format(each_item[1], splitted_value[4])
            req_header = {'Authorization': 'Bearer {}'.format(vault_token),
                      'Content-Type': 'application/json'}
            r = requests.get(req_url, headers=req_header)
            y = r.json()

            low_int = 0
            latest_id = ""
            for b in y["value"]:
                temp = b["attributes"]["created"]
                if low_int < temp:
                    low_int = temp
                    latest_id = b["id"]
            
            split_id = latest_id.split('/')

            year = int(input("Enter a key_expiry year for key"+ splitted_value[4] + ":"))
            month = int(input("Enter a key_expiry month for key"+ splitted_value[4] + ":"))
            day = int(input("Enter a key_expiry day for key"+ splitted_value[4] + ":"))
            dt = datetime.date(year, month, day)
            time_stamp = calendar.timegm(dt.timetuple())
            secexp_fix_uri = url_const.UPDATE_SECRETS.format(each_item[1], splitted_value[4], split_id[5])
            secexp_fix_header = {'Authorization': 'Bearer {}'.format(vault_token),'Content-Type': 'application/json'}
            secexp_fix_data = {"attributes": {"enabled": True, "exp": time_stamp}}
            secexp_req = requests.patch(secexp_fix_uri, headers=secexp_fix_header, data=json.dumps(secexp_fix_data))
            if secexp_req.status_code == 200:
                print(" ===> Expiry date updated successfully for the Secret",splitted_value[4].upper(),"")
            else:
                print(" ===> Not updated!!! Error ") 


    # CIS 8.4: Ensure the key vault is recoverable 

    def key_vault_recover_fix(self, mgmt_token):
        keyvault_recover_data = self.keyvault_comp.key_vault_recover(mgmt_token)
        for each_item in keyvault_recover_data:
            splitted_value = each_item[0].split('/')
            req_url = url_const.UPDATE_KEY_VAULT.format(splitted_value[2], splitted_value[4], splitted_value[8])
            req_header = {'Authorization': 'Bearer {}'.format(mgmt_token),
                      'Content-Type': 'application/json'}
            req_data = {"properties": {"enableSoftDelete":True,"enablePurgeProtection":True}}
            r = requests.patch(req_url, headers=req_header, data=json.dumps(req_data))
            if r.status_code == 200:
                print(" ===> SoftDelete and PurgeProtection",splitted_value[8].upper(),"enabled Successfully ")
            else:
                print(" ===> Not updated!!! Error")

    
    