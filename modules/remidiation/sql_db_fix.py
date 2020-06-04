import requests
import json
from modules.constants import url_const
from modules.compliance.sql_db import DataBaseServices

class sql_DB_fix:
    def __init__(self, sub_id, tenant_id, client_id, client_sec):
        self.SUBSCRIPTION_ID = sub_id
        self.TENANT_ID = tenant_id
        self.CLIENT_ID = client_id
        self.CLIENT_SECRECT = client_sec
        self.sd = DataBaseServices(self.SUBSCRIPTION_ID,self.TENANT_ID,self.CLIENT_ID,self.CLIENT_SECRECT)
    

    # CIS 4.9 Ensure that 'Data encryption' is set to 'On' on a SQL Database

    def db_TDE_fix(self, token):
        db_TDE_data = self.sd.Encryption_on_DB(token)
        for each_property in db_TDE_data:
            splitted_value = each_property[0].split('/')
            req_url = url_const.UPDATE_TDE_CONFIG.format(splitted_value[2], splitted_value[4], splitted_value[8], splitted_value[10])
            headers = {'Authorization': 'Bearer {}'.format(token), 'Content-Type': 'application/json'}
            data = data = {"properties": {"status": "Enabled"}}
            r = requests.put(req_url,headers=headers,data=json.dumps(data))
            if r.status_code == 200:
                print(" ===> Storage Container", splitted_value[10].upper(),"is set to private ")
            else:
                print(" ===> Not updated!!! Error ")


    # CIS 4.11: Ensure 'Enforce SSL connection' is set to 'ENABLED' for MySQL Database Server

    def Mysql_SSL_fix(self, token):
        ssl_list = self.sd.MySql_SSL_Check(token)
        for each_property in ssl_list:
            splitted_value = each_property[0].split('/')
            if each_property[2] == "Disabled" :
                req_url = url_const.MYSQL_SSL_FIX.format(splitted_value[2], splitted_value[4], splitted_value[8])
                headers = {'Authorization': 'Bearer {}'.format(token), 'Content-Type': 'application/json'}
                data = {"properties": {"sslEnforcement": "Enabled"}}
                r = requests.patch(req_url,headers=headers,data=json.dumps(data))
                print(r.status_code)
                if r.status_code == 202 or r.status_code == 200:
                    print(" ===> SSL is enforced for MY_SQL server", splitted_value[8].upper())
                else:
                    print(" ===> Not updated!!! Error ")


    # CIS 4.12: Ensure server parameter 'log_checkpoints' is set to 'ON' for PostgreSQL Database Server

    def Postgre_log_checkpoints_fix(self, token):
        post_checkpoints_list = self.sd.Postgre_log_checkpoints(token)
        for each_property in post_checkpoints_list:
            splitted_value = each_property[0].split('/')
            req_url = url_const.POSTGRESQL_CONFIG_UPDATE.format(splitted_value[2], splitted_value[4], splitted_value[8], "log_checkpoints")
            headers = {'Authorization': 'Bearer {}'.format(token), 'Content-Type': 'application/json'}
            data = {"properties": {"value": "on","source": "user-override"}}
            r = requests.put(req_url,headers=headers,data=json.dumps(data))
            if r.status_code == 202 or r.status_code == 200:
                print("===> Log_Checkpoint is set to 'ON' for server", splitted_value[8].upper())
            else:
                print("===> Not updated!!! Error")
    

    # CIS 4.13: Ensure 'Enforce SSL connection' is set to 'ENABLED' for PostgreSQL Database Server

    def postsql_ssl_fix(self, token):
        post_ssl_list = self.sd.postgresql_list(token)
        for each_property in post_ssl_list:
            splitted_value = each_property[0].split('/')
            if each_property[2] == "Disabled":
                req_url = url_const.POSTGRESQL_SSL_FIX.format(splitted_value[2], splitted_value[4], splitted_value[8])
                headers = {'Authorization': 'Bearer {}'.format(token), 'Content-Type': 'application/json'}
                data = {"properties": {"sslEnforcement": "Enabled"}}
                r = requests.patch(req_url,headers=headers,data=json.dumps(data))
                print(r.status_code)
                if r.status_code == 202 or r.status_code == 200:
                    print(" ===> SSL is enforced for PostgreSQL server", splitted_value[8].upper())
                else:
                    print(" ===> Not updated!!! Error ")


    # CIS 4.14: Ensure server parameter 'log_connections' is set to 'ON' for PostgreSQL Database Server

    def Postgre_log_connections_fix(self, token):
        post_connections_list = self.sd.Postgre_log_connections(token)
        for each_property in post_connections_list:
            splitted_value = each_property[0].split('/')
            req_url = url_const.POSTGRESQL_CONFIG_UPDATE.format(splitted_value[2], splitted_value[4], splitted_value[8], "log_connections")
            headers = {'Authorization': 'Bearer {}'.format(token), 'Content-Type': 'application/json'}
            data = {"properties": {"value": "on","source": "user-override"}}
            r = requests.put(req_url,headers=headers,data=json.dumps(data))
            if r.status_code == 202 or r.status_code == 200:
                print("===> Log_Connections is set to 'ON' for server", splitted_value[8].upper())
            else:
                print("===> Not updated!!! Error")


    # CIS 4.15 Ensure server parameter 'log_disconnections' is set to 'ON' for PostgreSQL Database Server
    
    def Postgre_log_disconnections_fix(self, token):
        post_disconnections_list = self.sd.postgre_log_disconnections(token)
        for each_property in post_disconnections_list:
            splitted_value = each_property[0].split('/')
            req_url = url_const.POSTGRESQL_CONFIG_UPDATE.format(splitted_value[2], splitted_value[4], splitted_value[8], "log_disconnections")
            headers = {'Authorization': 'Bearer {}'.format(token), 'Content-Type': 'application/json'}
            data = {"properties": {"value": "on","source": "user-override"}}
            r = requests.put(req_url,headers=headers,data=json.dumps(data))
            if r.status_code == 202 or r.status_code == 200:
                print("===> Log_Disconnections is set to 'ON' for server", splitted_value[8].upper())
            else:
                print("===> Not updated!!! Error")


    # CIS 4.16 Ensure server parameter 'log_duration' is set to 'ON' for PostgreSQL Database Server

    def Postgre_log_duration_fix(self, token):
        post_duration_list = self.sd.postgre_log_duration(token)
        for each_property in post_duration_list:
            splitted_value = each_property[0].split('/')
            req_url = url_const.POSTGRESQL_CONFIG_UPDATE.format(splitted_value[2], splitted_value[4], splitted_value[8], "log_duration")
            headers = {'Authorization': 'Bearer {}'.format(token), 'Content-Type': 'application/json'}
            data = {"properties": {"value": "on","source": "user-override"}}
            r = requests.put(req_url,headers=headers,data=json.dumps(data))
            if r.status_code == 202 or r.status_code == 200:
                print("===> Log_Duration is set to 'ON' for server", splitted_value[8].upper())
            else:
                print("===> Not updated!!! Error")


    # CIS 4.17: Ensure server parameter 'connection_throttling' is set to 'ON' for PostgreSQL Database Server

    def Postgre_connection_throttling_fix(self, token):
        post_throttling_list = self.sd.postgre_connection_throttling(token)
        for each_property in post_throttling_list:
            splitted_value = each_property[0].split('/')
            req_url = url_const.POSTGRESQL_CONFIG_UPDATE.format(splitted_value[2], splitted_value[4], splitted_value[8], "connection_throttling")
            headers = {'Authorization': 'Bearer {}'.format(token), 'Content-Type': 'application/json'}
            data = {"properties": {"value": "on","source": "user-override"}}
            r = requests.put(req_url,headers=headers,data=json.dumps(data))
            if r.status_code == 202 or r.status_code == 200:
                print("===> Connection_Throttling is set to 'ON' for server", splitted_value[8].upper())
            else:
                print("===> Not updated!!! Error")


    # CIS 4.18: Ensure server parameter 'log_retention_days' is greater than 3 days for PostgreSQL Database Server
    
    def Postgre_log_retention_fix(self, token):
        post_retention_list = self.sd.postgre_log_retention(token)
        Retention_Days = input("Enter log_retention days(4-7): ")
        for each_property in post_retention_list:
            splitted_value = each_property[0].split('/')
            req_url = url_const.POSTGRESQL_CONFIG_UPDATE.format(splitted_value[2], splitted_value[4], splitted_value[8], "log_retention_days")
            headers = {'Authorization': 'Bearer {}'.format(token), 'Content-Type': 'application/json'}
            data = {"properties": {"value": ""+ Retention_Days +"","source": "user-override"}}
            r = requests.put(req_url,headers=headers,data=json.dumps(data))
            if r.status_code == 202 or r.status_code == 200:
                print("===> Log_Retention_Days is set to more than 3 days for server", splitted_value[8].upper())
            else:
                print("===> Not updated!!! Error")