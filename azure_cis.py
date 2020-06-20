#!/usr/bin/python3
"""
This file acts as a entry point for the entire tool

The user should only run this script in order to execute this entire tool
"""
import json
import time
import requests
import string
from modules import config_loader
from modules.argumentParser.arg_parse import parser
from modules.compliance.key_vault import KeyVault
from modules.compliance.logging_monitoring import logging_monitoring
from modules.compliance.security_center import SecurityCenter
from modules.compliance.storage_account import StorageAccount
from modules.compliance.sql_db import DataBaseServices
from modules.constants.token_generator import TokenGenerator, adal
from modules.remidiation.storage_account_fix import StorageAccountFix
from modules.remidiation.security_center_fix import SecurityCenterFix
from modules.remidiation.logging_monitoring_fix import logging_monitoring_fix
from modules.remidiation.sql_db_fix import sql_DB_fix
from modules.remidiation.key_vault_fix import KeyVaultFix


f = open( r'banner.txt', 'r')
file_contents = f.read()
print ('\033[1m'+ file_contents)
f.close()

"""Loading the creds in order to process for CIS benchmark
"""
try:
    creds_info = config_loader.creds_load()
    SUBSCRIPTION_ID = creds_info["SUBSCRIPTION_ID"]
    TENANT_ID = creds_info["TENANT_ID"]
    CLIENT_ID = creds_info["CLIENT_ID"]
    CLIENT_SECRET = creds_info["CLIENT_SECRET"]
except KeyError as ke:
    print("Don't change the key from creds.json only change the value in it.")
except Exception as e:
    print(e)

#Creating a token
token_creation = TokenGenerator(TENANT_ID)
try:
    MGMT_TOKEN = token_creation.management_token_generator(CLIENT_ID,CLIENT_SECRET)
    STORAGE_TOKEN = token_creation.storage_token_generator(CLIENT_ID,CLIENT_SECRET)
    VAULT_TOKEN = token_creation.vault_token_generator(CLIENT_ID, CLIENT_SECRET)
except adal.AdalError as adal_error:
    error_response = adal_error.error_response
    print("An error occured..\n",error_response['error'].upper(),"\nError description:",error_response['error_description'])
    print("==> CHECK WHETHER CREDENTIALS ARE CORRECT OR NOT!!")
    exit(0)

args = parser.parse_args()
if args.check_compliance:
    st = StorageAccount(SUBSCRIPTION_ID,TENANT_ID,CLIENT_ID,CLIENT_SECRET)
    st.get_storage_account_list(MGMT_TOKEN)
    st.get_storage_containers_list(STORAGE_TOKEN)
    st.get_networkaccess_rule_list(MGMT_TOKEN)
    ss = SecurityCenter(SUBSCRIPTION_ID, TENANT_ID, CLIENT_ID, CLIENT_SECRET)
    ss.standard_pricing_tier(MGMT_TOKEN)
    ss.autoprovisoning_of_monitoring_agent(MGMT_TOKEN)
    ss.securitycontacts_email(MGMT_TOKEN)
    ss.securitycontacts_phone(MGMT_TOKEN)
    ss.sendemail_notification_alerts(MGMT_TOKEN)
    ss.admin_notification_alerts(MGMT_TOKEN)
    db_comp = DataBaseServices(SUBSCRIPTION_ID, TENANT_ID, CLIENT_ID, CLIENT_SECRET)
    db_comp.Encryption_on_DB(MGMT_TOKEN)
    db_comp.MySql_SSL_Check(MGMT_TOKEN)
    # db_comp.postgresql_list(MGMT_TOKEN)
    # db_comp.Postgre_log_checkpoints(MGMT_TOKEN)
    # db_comp.Postgre_log_connections(MGMT_TOKEN)
    # db_comp.postgre_log_disconnections(MGMT_TOKEN)
    # db_comp.postgre_log_duration(MGMT_TOKEN)
    # db_comp.postgre_connection_throttling(MGMT_TOKEN)
    # db_comp.postgre_log_retention(MGMT_TOKEN)
    # lm = logging_monitoring(SUBSCRIPTION_ID, TENANT_ID, CLIENT_ID, CLIENT_SECRET)
    # lm.log_profile(MGMT_TOKEN)
    # lm.Activity_log_retention(MGMT_TOKEN)
    # lm.Activity_log_locations(MGMT_TOKEN)
    # lm.log_container_comp(MGMT_TOKEN, STORAGE_TOKEN)
    # lm.network_watcher_enable(MGMT_TOKEN)
    # keyvault_comp = KeyVault(SUBSCRIPTION_ID, TENANT_ID, CLIENT_ID, CLIENT_SECRET)
    # keyvault_comp.key_expiration(MGMT_TOKEN, VAULT_TOKEN)
    # keyvault_comp.secret_expiration(MGMT_TOKEN, VAULT_TOKEN)
    # keyvault_comp.key_vault_recover(MGMT_TOKEN)

if args.remediation:
    # rem = StorageAccountFix(SUBSCRIPTION_ID,TENANT_ID,CLIENT_ID,CLIENT_SECRET)
    # rem.storage_account_fix(MGMT_TOKEN)
    # rem.storage_container_fix(STORAGE_TOKEN, MGMT_TOKEN)
    # rem.networkaccess_rule_fix(MGMT_TOKEN)
    # ss_rem = SecurityCenterFix(SUBSCRIPTION_ID, TENANT_ID, CLIENT_ID, CLIENT_SECRET)
    # ss_rem.StandardPricing_Tier_Fix(MGMT_TOKEN)
    # ss_rem.AutoProvisioning_Fix(MGMT_TOKEN)
    # ss_rem.securitycontacts_email_fix(MGMT_TOKEN)
    # ss_rem.securitycontacts_phone_fix(MGMT_TOKEN)
    # ss_rem.emailnotification_alerts_Fix(MGMT_TOKEN)
    # ss_rem.admin_notification_alerts_Fix(MGMT_TOKEN)
    db_rem = sql_DB_fix(SUBSCRIPTION_ID, TENANT_ID, CLIENT_ID, CLIENT_SECRET)
    db_rem.db_TDE_fix(MGMT_TOKEN)
    db_rem.Mysql_SSL_fix(MGMT_TOKEN)
    # db_rem.postsql_ssl_fix(MGMT_TOKEN)
    # db_rem.Postgre_log_checkpoints_fix(MGMT_TOKEN)
    # db_rem.Postgre_log_connections_fix(MGMT_TOKEN)
    # db_rem.Postgre_log_disconnections_fix(MGMT_TOKEN)
    # db_rem.Postgre_log_duration_fix(MGMT_TOKEN)
    # db_rem.Postgre_connection_throttling_fix(MGMT_TOKEN)
    # db_rem.Postgre_log_retention_fix(MGMT_TOKEN)
    # lm_fix = logging_monitoring_fix(SUBSCRIPTION_ID, TENANT_ID, CLIENT_ID, CLIENT_SECRET)
    # lm_fix.log_profile_fix(MGMT_TOKEN)
    # lm_fix.Activity_log_retention_fix(MGMT_TOKEN)
    # lm_fix.Activity_log_location_fix(MGMT_TOKEN)
    # time.sleep(25)
    # lm_fix.log_container_fix(MGMT_TOKEN,STORAGE_TOKEN)
    # lm_fix.network_watcher_fix(MGMT_TOKEN)
    # key_vault_fix = KeyVaultFix(SUBSCRIPTION_ID, TENANT_ID, CLIENT_ID, CLIENT_SECRET)
    # key_vault_fix.key_expiration_fix(MGMT_TOKEN, VAULT_TOKEN)
    # key_vault_fix.secret_expiration_fix(MGMT_TOKEN, VAULT_TOKEN)
    # key_vault_fix.key_vault_recover_fix(MGMT_TOKEN)

if args.version:
    print('AzureSeconf V 0.1')



