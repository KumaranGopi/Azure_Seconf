import requests
import json
from modules.constants import url_const

class SecurityCenter:

    def __init__(self, sub_id,  tenant_id, client_id, client_sec):

        self.SUBSCRIPTION_ID = sub_id
        self.TENANT_ID = tenant_id
        self.CLIENT_ID = client_id
        self.CLIENT_SECRECT = client_sec
        self.inc = 0
    

    # CIS 2.1 : Ensure that standard pricing tier is selected

    def standard_pricing_tier(self, mgmt_token):
        """To find the type of pricing tier
        """ 
        req_url = url_const.SUBSCRIPTION_TIER.format(self.SUBSCRIPTION_ID)
        req_header = {'Authorization': 'Bearer {}'.format(mgmt_token),
                      'Content-Type': 'application/json'}
        r = requests.get(req_url, headers=req_header)
        x = r.json()
        pricingtier_list = list()
        for _ in x:
            j = 0
            for b in x["value"]:
                pricingtier_list.append([])
                pricingtier_list[j].append(b["properties"]["pricingTier"])
                j += 1
        print("\nCIS 2.1 : Ensure that standard pricing tier is selected")
        for each_property in pricingtier_list:
            if each_property[0] == "Standard" :
                print(" ===> Your Subscription is Compliant ")
            else:
                print(" ===> Your Subscription is not Compliant ")
        return pricingtier_list


    # CIS 2.2 : Ensure that 'Automatic provisioning of monitoring agent' is set to 'On'
    
    def autoprovisoning_of_monitoring_agent(self, mgmt_token):
        """To find the status of autoprovisisoning 
           of monitoring agent
        """ 
        
        req_url = url_const.AUTOPROVISIONING_MONITORING_AGENT.format(self.SUBSCRIPTION_ID)
        req_header = {'Authorization': 'Bearer {}'.format(mgmt_token),
                      'Content-Type': 'application/json'}
        r = requests.get(req_url, headers=req_header)
        x = r.json()
        AutoProvisioning_list = list()
        for _ in x:
            j = 0
            for b in x["value"]:
                AutoProvisioning_list.append([])
                AutoProvisioning_list[j].append(b["properties"]["autoProvision"])
                j += 1
        print("\nCIS 2.2 : Ensure that 'Automatic provisioning of monitoring agent' is set to 'On' ")
        for each_property in AutoProvisioning_list:
            if each_property[0] == "On" :
                print(" ===>Your Subscription is Compliant ")
            else:
                print(" ===>Your Subscription is Non - Compliant ")
        return AutoProvisioning_list


    # CIS 2.16 Ensure that 'Security contact emails' is set

    def securitycontacts_email(self, mgmt_token):
        req_url = url_const.CHECK_SECURITY_CONTACTS.format(self.SUBSCRIPTION_ID)
        req_header = {'Authorization': 'Bearer {}'.format(mgmt_token),
                      'Content-Type': 'application/json'}
        r = requests.get(req_url, headers=req_header)
        securitycontacts = r.json()

        securityemail_list=list()
        for b in securitycontacts["value"]:
            securityemail_list.append(b["name"])
            securityemail_list.append(b["properties"]["email"])
            try:
                securityemail_list.append(b["properties"]["phone"])
            except KeyError as _:
                pass
        print("\nCIS 2.16 Ensure that 'Security contact emails' is set ")
        if not securityemail_list:
            print(" ===> Your SecurityContact List is Empty!!. You are Non - Compliant ")
        elif securityemail_list[1] == "":
            print(" ===> Email Field is empty in your SecurityContact List!!. You are Non - Compliant ")
        else:
            print(" ===> Your Subscription is Compliant ")

        self.inc = 0
        return securityemail_list


    # CIS 2.17: Ensure that security contact 'Phone number' is set

    def securitycontacts_phone(self, mgmt_token):
        req_url = url_const.CHECK_SECURITY_CONTACTS.format(self.SUBSCRIPTION_ID)
        req_header = {'Authorization': 'Bearer {}'.format(mgmt_token),
                      'Content-Type': 'application/json'}
        r = requests.get(req_url, headers=req_header)
        securitycontacts = r.json()
        print("\nCIS 2.17: Ensure that security contact 'Phone number' is set")
        try:
            if securitycontacts["value"][0]["properties"]["phone"]== '':
                print(" ===> Phone Number Field is empty in your SecurityContact List!!. You are Non - Compliant ")
            else:
                print(" ===> Your Subscription is Compliant ")
        except KeyError as ke:
            print(" ===> Phone Number Field is empty in your SecurityContact List!!. You are Non - Compliant ")
        return securitycontacts
            
    # CIS 2.18: Ensure that 'Send email notification for high severity alerts' is set to 'On'

    def sendemail_notification_alerts(self, mgmt_token): # CIS 2.18 
        req_url = url_const.CHECK_SECURITY_CONTACTS.format(self.SUBSCRIPTION_ID)
        req_header = {'Authorization': 'Bearer {}'.format(mgmt_token),
                      'Content-Type': 'application/json'}
        r = requests.get(req_url, headers=req_header)
        securitycontacts = r.json()
        securitynotify_list = list()
        for _ in securitycontacts:
            j = 0
            for b in securitycontacts["value"]:
                securitynotify_list.append(b["name"])
                securitynotify_list.append(b["properties"]["email"])
                securitynotify_list.append(b["properties"]["alertNotifications"])
                try:
                    securitynotify_list.append(b["properties"]["phone"])
                except KeyError as _:
                    pass
                j += 1
        print("\nCIS 2.18: Ensure that 'Send email notification for high severity alerts' is set to 'On'")
        if securitynotify_list[2] == "Off":
            print(" ===> Your Subscription is Non - Compliant ")
        else:
            print(" ===> Your Subscription is Compliant ")
        return securitynotify_list


    # CIS 2.19: Ensure that 'Send email also to subscription owners' is set to 'On'
    
    def admin_notification_alerts(self, mgmt_token): # CIS 2.19
        req_url = url_const.CHECK_SECURITY_CONTACTS.format(self.SUBSCRIPTION_ID)
        req_header = {'Authorization': 'Bearer {}'.format(mgmt_token),
                      'Content-Type': 'application/json'}
        r = requests.get(req_url, headers=req_header)
        securitycontacts = r.json()
        security_Adminnotify_list = list()
        for _ in securitycontacts:
            j = 0
            for b in securitycontacts["value"]:
                security_Adminnotify_list.append(b["name"])
                security_Adminnotify_list.append(b["properties"]["email"])
                security_Adminnotify_list.append(b["properties"]["alertsToAdmins"])
                try:
                    security_Adminnotify_list.append(b["properties"]["phone"])
                except KeyError as _:
                    pass
                j += 1
        print("\nCIS 2.19: Ensure that 'Send email also to subscription owners' is set to 'On'")
        if security_Adminnotify_list[2] == "Off":
            print(" ===> Your Subscription is Non - Compliant ")
        else:
            print(" ===> Your Subscription is Compliant ")
        return security_Adminnotify_list
        



       