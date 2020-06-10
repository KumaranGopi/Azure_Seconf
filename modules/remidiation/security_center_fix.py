import requests
import re
import json
from modules.compliance.security_center import SecurityCenter
from modules.constants import url_const

class SecurityCenterFix:
    def __init__(self, sub_id, tenant_id, client_id, client_sec):
        self.SUBSCRIPTION_ID = sub_id
        self.TENANT_ID = tenant_id
        self.CLIENT_ID = client_id
        self.CLIENT_SECRECT = client_sec
        self.ss = SecurityCenter(self.SUBSCRIPTION_ID,self.TENANT_ID,self.CLIENT_ID,self.CLIENT_SECRECT)

    
    # CIS 2.1 : Ensure that standard pricing tier is selected
    
    def StandardPricing_Tier_Fix(self, token):
        pricing_tier_data = self.ss.standard_pricing_tier(token)
        for each_property in pricing_tier_data:
            if each_property[0] == "Free" :
                req_url = url_const.SUBSCRIPTION_TIER_FIX.format(self.SUBSCRIPTION_ID)
                headers = {'Authorization': 'Bearer {}'.format(token), 'Content-Type': 'application/json'}
                data = {"id": "/subscriptions/"+ self.SUBSCRIPTION_ID +"/providers/Microsoft.Security/pricings/default",
                    "name": "default",
                    "type": "Microsoft.Security/pricings",
                    "properties": {
                        "pricingTier": "Free"
                        }
                    }
                r = requests.put(req_url,headers=headers,data=json.dumps(data))
                if r.status_code == 200:
                    print(" ===> Pricing Tier Updated Successfully ")
                else:
                    print(" ===> Not updated!!! Error ")

    
    # CIS 2.2 : Ensure that 'Automatic provisioning of monitoring agent' is set to 'On'

    def AutoProvisioning_Fix(self, token):
        Autoprovisioning_data = self.ss.autoprovisoning_of_monitoring_agent(token)
        for each_property in Autoprovisioning_data:
            if each_property[0] == "Off":
                req_url = url_const.AUTOPROVISIONING_FIX.format(self.SUBSCRIPTION_ID)
                headers = {'Authorization': 'Bearer {}'.format(token), 'Content-Type': 'application/json'}
                data = {"id": "/subscriptions/"+ self.SUBSCRIPTION_ID +"/providers/Microsoft.Security/autoProvisioningSettings/default",
                        "name": "default",
                        "type": "Microsoft.Security/autoProvisioningSettings",
                        "properties": {
                             "autoProvision":"On"
                         }
                        }
                r = requests.put(req_url,headers=headers,data=json.dumps(data))
                if r.status_code == 200:
                    print(" ===> AutoProvsioning of Monitoring Agent Enabled Successfully ")
                else:
                    print(" ===> Not updated!!! Error ")


    # CIS 2.16 Ensure that 'Security contact emails' is set

    def securitycontacts_email_fix(self, token):
        sec_email_fix = self.ss.securitycontacts_email(token)
        if not sec_email_fix:
            print("Your SecurityContact List is Empty!!. Add a security Contact to get Compliant")
            while True:
                securityContact_emailID = input("Enter the Email_ID: ")
                EMAIL_REGEX = re.compile(r'^[a-z0-9]+[\._]?[a-z0-9]+[@]\w+[.]\w+$')
                if not EMAIL_REGEX.match(securityContact_emailID):
                    print("Please enter a valid email Id")
                    continue
                else:
                    break
            
            req_url = url_const.ADDSECURITY_CONTACTS_FIX.format(self.SUBSCRIPTION_ID)
            headers = {'Authorization': 'Bearer {}'.format(token), 'Content-Type': 'application/json'}
            data = {"id": "/subscriptions/"+ self.SUBSCRIPTION_ID +"/providers/Microsoft.Security/securityContacts/default1",
                    "name": "default1",
                    "type": "Microsoft.Security/securityContacts",
                    "properties": {
                        "email": ""+ securityContact_emailID +"",             
                        "alertNotifications": "On",
                        "alertsToAdmins": "On"
                     }
                  }
            r = requests.put(req_url,data=json.dumps(data), headers=headers)
            if r.status_code == 200:
                print(" ===> Security Contact EmailID Added Successfully ")
            else:
                print(" ===> Not updated!!! Error ")

        elif sec_email_fix[1] == "":
            print("Email ID is not Set in your SecurityContact!!. Add EmailID to get Compliant")
            while True:
                securityContact_emailID = input("Enter the Email_ID: ")
                EMAIL_REGEX = re.compile(r'^[a-z0-9]+[\._]?[a-z0-9]+[@]\w+[.]\w+$')
                if not EMAIL_REGEX.match(securityContact_emailID):
                    print("Please enter a valid email Id")
                    continue
                else:
                    break
            req_url = url_const.UPDATESECURITY_CONTACT_FIX.format(self.SUBSCRIPTION_ID, sec_email_fix[0])
            headers = {'Authorization': 'Bearer {}'.format(token), 'Content-Type': 'application/json'}
            data = {"id": "/subscriptions/"+ self.SUBSCRIPTION_ID +"/providers/Microsoft.Security/securityContacts/"+ sec_email_fix[0] +"",
                    "name": ""+ sec_email_fix[0] +"",
                    "type": "Microsoft.Security/securityContacts",
                    "properties": {
                        "email":""+ securityContact_emailID +"",
                        "phone":""+ sec_email_fix[2] +"",
                        "alertNotifications": "On",
                        "alertsToAdmins": "On"
                    }
                }
            r = requests.patch(req_url,data=json.dumps(data), headers=headers)
            if r.status_code == 200:
                print(" ===> Security Contact EmailID Added Successfully ")
            else:
                print(" ===> Not updated!!! Error ")


    # CIS 2.17: Ensure that security contact 'Phone number' is set

    def securitycontacts_phone_fix(self, token):
        sec_phone_data = self.ss.securitycontacts_phone(token)
        if not sec_phone_data["value"]:
            print("Your SecurityContact List is Empty!!. Add a security Contact to get Compliant")
            while True:
                try:
                    SecurityContact_PhoneNo = int(input("Enter the Phone_Number: "))
                except ValueError as _:
                    print("Enter only interger values")
                    continue
                PHONE_REGEX = re.compile(r'^\+(?:[0-9] ?){6,14}[0-9]$')
                if not PHONE_REGEX.match(SecurityContact_PhoneNo):
                    print("Please enter a valid Phone_No")
                    continue
                else:
                    break
            
            req_url = url_const.ADDSECURITY_CONTACTS_FIX.format(self.SUBSCRIPTION_ID)
            headers = {'Authorization': 'Bearer {}'.format(token), 'Content-Type': 'application/json'}
            data = {"id": "/subscriptions/"+ self.SUBSCRIPTION_ID +"/providers/Microsoft.Security/securityContacts/default1",
                    "name": "default1",
                    "type": "Microsoft.Security/securityContacts",
                    "properties": {
                        "phone": ""+ SecurityContact_PhoneNo +"",             
                        "alertNotifications": "On",
                        "alertsToAdmins": "On"
                     }
                  }
            r = requests.put(req_url,data=json.dumps(data), headers=headers)
            if r.status_code == 200:
                print(" ===> Security Contact Phone Number Added Successfully ")
            else:
                print(" ===> Not updated!!! Error ")

        try:
            if sec_phone_data["value"][0]["properties"]["phone"] == "":
                print("Phone Number is not Set in your SecurityContact!!. Add Phone Number to get Compliant")
                while True:
                    SecurityContact_PhoneNo = str(input("Enter the Phone_Number: "))             
                    PHONE_REGEX = re.compile(r'^\+(?:[0-9] ?){6,14}[0-9]$')
                    if not PHONE_REGEX.match(SecurityContact_PhoneNo):
                        print("Please enter a valid Phone_No")
                        continue
                    else:
                        break
                req_url = url_const.UPDATESECURITY_CONTACT_FIX.format(self.SUBSCRIPTION_ID, sec_phone_data["value"][0]["name"])
                headers = {'Authorization': 'Bearer {}'.format(token), 'Content-Type': 'application/json'}
                data = {"id": "/subscriptions/"+ self.SUBSCRIPTION_ID +"/providers/Microsoft.Security/securityContacts/"+ sec_phone_data["value"][0]["name"] +"",
                            "name": ""+ sec_phone_data["value"][0]["name"] +"",
                            "type": "Microsoft.Security/securityContacts",
                            "properties": {
                                "email":""+ sec_phone_data["value"][0]["properties"]["email"] +"",
                                "phone":""+ SecurityContact_PhoneNo +"",
                                "alertNotifications": "On",
                                "alertsToAdmins": "On"
                            }
                        }
                r = requests.patch(req_url,data=json.dumps(data), headers=headers)
                if r.status_code == 200:
                    print(" ===> Security Contact Phone Number Added Successfully ")
                else:
                    print(" ===> Not updated!!! Error ")
        except KeyError as ke:
            print("Phone Number is not Set in your SecurityContact!!. Add Phone Number to get Compliant")
            while True:
                SecurityContact_PhoneNo = str(input("Enter the Phone_Number: "))  
                PHONE_REGEX = re.compile(r'^\+(?:[0-9] ?){6,14}[0-9]$')
                if not PHONE_REGEX.match(SecurityContact_PhoneNo):
                    print("Please enter a valid Phone_No")
                    continue
                else:
                    break
            req_url = url_const.UPDATESECURITY_CONTACT_FIX.format(self.SUBSCRIPTION_ID, sec_phone_data["value"][0]["name"])
            headers = {'Authorization': 'Bearer {}'.format(token), 'Content-Type': 'application/json'}
            data = {"id": "/subscriptions/"+ self.SUBSCRIPTION_ID +"/providers/Microsoft.Security/securityContacts/"+ sec_phone_data["value"][0]["name"] +"",
                            "name": ""+ sec_phone_data["value"][0]["name"] +"",
                            "type": "Microsoft.Security/securityContacts",
                            "properties": {
                                "email":""+ sec_phone_data["value"][0]["properties"]["email"] +"",
                                "phone":""+ SecurityContact_PhoneNo +"",
                                "alertNotifications": "On",
                                "alertsToAdmins": "On"
                            }
                        }
            r = requests.patch(req_url,data=json.dumps(data), headers=headers)
            if r.status_code == 200:
                print(" ===> Security Contact Phone Number Added Successfully ")
            else:
                print(" ===> Not updated!!! Error ")


    # CIS 2.18: Ensure that 'Send email notification for high severity alerts' is set to 'On'
    
    def emailnotification_alerts_Fix(self, token):
        emailnotification_data = self.ss.sendemail_notification_alerts(token)
        
        if emailnotification_data[2] == "Off":
            req_url = url_const.UPDATESECURITY_CONTACT_FIX.format(self.SUBSCRIPTION_ID, emailnotification_data[0])
            headers = {'Authorization': 'Bearer {}'.format(token), 'Content-Type': 'application/json'}
            data = {"id": "/subscriptions/"+ self.SUBSCRIPTION_ID +"/providers/Microsoft.Security/securityContacts/"+ emailnotification_data[0] +"",
                    "name": ""+ emailnotification_data[0] +"",
                    "type": "Microsoft.Security/securityContacts",
                    "properties": {
                        "email":""+ emailnotification_data[1] +"",
                        "phone":""+ emailnotification_data[3] +"",
                        "alertNotifications": "On"
                    }
                }
            r = requests.patch(req_url,data=json.dumps(data), headers=headers)
            if r.status_code == 200:
                print(" ===> Notification Alerts turned on Successfully ")
            else:
                print(" ===> Not updated!!! Error ")


    # CIS 2.19: Ensure that 'Send email also to subscription owners' is set to 'On'

    def admin_notification_alerts_Fix(self, token):
        adminnotification_data = self.ss.admin_notification_alerts(token)        
        if adminnotification_data[2] == "Off":
            req_url = url_const.UPDATESECURITY_CONTACT_FIX.format(self.SUBSCRIPTION_ID, adminnotification_data[0])
            headers = {'Authorization': 'Bearer {}'.format(token), 'Content-Type': 'application/json'}
            data = {"id": "/subscriptions/"+ self.SUBSCRIPTION_ID +"/providers/Microsoft.Security/securityContacts/"+ adminnotification_data[0] +"",
                    "name": ""+ adminnotification_data[0] +"",
                    "type": "Microsoft.Security/securityContacts",
                    "properties": {
                        "email":""+ adminnotification_data[1] +"",
                        "phone":""+ adminnotification_data[3] +"",
                        "alertNotifications": "On",
                        "alertsToAdmins": "On"
                    }
                }
            r = requests.patch(req_url,data=json.dumps(data), headers=headers)
            if r.status_code == 200:
                print(" ===> Notification Alerts turned on Successfully ")
            else:
                print(" ===> Not updated!!! Error ")