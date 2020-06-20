import requests
import json
import xmltodict
from modules.constants import url_const

class DataBaseServices:
    def __init__(self, sub_id,  tenant_id, client_id, client_sec):
        self.SUBSCRIPTION_ID = sub_id
        self.TENANT_ID = tenant_id
        self.CLIENT_ID = client_id
        self.CLIENT_SECRECT = client_sec
        self.inc = 0


    # CIS 4.9 Ensure that 'Data encryption' is set to 'On' on a SQL Database
        
    def Encryption_on_DB(self, mgmt_token):
        """To find the state of Data Encryption on SQL DB
        """ 
        # listing DB servers in the subscription
        req_url = url_const.SQL_SERVERS_LIST.format(self.SUBSCRIPTION_ID)  
        req_header = {'Authorization': 'Bearer {}'.format(mgmt_token),
                      'Content-Type': 'application/json'}
        r = requests.get(req_url, headers=req_header)
        x = r.json()
        print("\nCIS 4.9 Ensure that 'Data encryption' is set to 'On' on a SQL Database")
        if not x["value"]:
            print(" ===> No SQL servers found!! ")
        #Appending the output to a list with only 'name' and 'id' fields
        db_server_list = list()
        for _ in x:
            j = 0
            for b in x["value"]:
                db_server_list.append([])
                db_server_list[j].append(b["name"])
                db_server_list[j].append(b["id"])
                j += 1

        self.y = db_server_list
        # listing databases under each server 
        DB_enrypt_list = list()        
        for each_item in self.y:
            unsan_resource_group = each_item[1]
            temp_resource_group = unsan_resource_group.split('/')
            san_resource_group = temp_resource_group[4]
            db_list_url = url_const.SQL_DB_LIST.format(self.SUBSCRIPTION_ID, san_resource_group, each_item[0]) 
            req_header = {'Authorization': 'Bearer {}'.format(mgmt_token),
                      'Content-Type': 'application/json'}
            h = requests.get(db_list_url, headers=req_header)
            y = h.json()

            DB_list = list()
            for db_fix in y["value"]:
                DB_list.append(db_fix["id"])
                unsan_server_name = db_fix["id"]
                temp_id = unsan_server_name.split('/')
                DB_ENCRPT_URL = url_const.TDE_CONFIG_DB.format(temp_id[2], temp_id[4], temp_id[8], temp_id[10])
                DB_ENCRPT_HEADER = {'Authorization': 'Bearer {}'.format(mgmt_token),
                                    'Content-Type': 'application/json'}
                DB_req = requests.get(DB_ENCRPT_URL, headers=DB_ENCRPT_HEADER)
                xpars = xmltodict.parse(DB_req.text)
                sql_info = json.loads(json.dumps(xpars))

                if temp_id[10] != "master":
                    if sql_info["entry"]["content"]["m:properties"]["d:properties"]["d:status"] == "Enabled":
                        print(" ===> The SQL database", temp_id[10].upper(), "in", temp_id[8].upper() ,"server is compliant ")
                    else:
                        print(" ===> The SQL database", temp_id[10].upper(), "in", temp_id[8].upper() ,"server is NOT compliant ")
                        DB_enrypt_list.append([])
                        DB_enrypt_list[self.inc].append(db_fix["id"])
                        self.inc += 1
        self.inc = 0
        return(DB_enrypt_list)

    
    # CIS 4.11: Ensure 'Enforce SSL connection' is set to 'ENABLED' for MySQL Database Server

    def MySql_SSL_Check(self, mgmt_token):
        req_url = url_const.MYSQL_SERVER_LIST.format(self.SUBSCRIPTION_ID)
        req_header = {'Authorization': 'Bearer {}'.format(mgmt_token),
                      'Content-Type': 'application/json'}
        h = requests.get(req_url, headers=req_header)
        y = h.json()
        if not y["value"]:
            print(" ===> No MySQL servers found!! ")
        
        Mysql_SSL_list = list()
        for _ in y:
            j = 0
            for b in y["value"]:
                Mysql_SSL_list.append([])
                Mysql_SSL_list[j].append(b["id"])
                Mysql_SSL_list[j].append(b["name"])
                Mysql_SSL_list[j].append(b["properties"]["sslEnforcement"])
                j += 1
        print("\nCIS 4.11: Ensure 'Enforce SSL connection' is set to 'ENABLED' for MySQL Database Server  ")        
        for each_property in Mysql_SSL_list:
            if each_property[2] == "Enabled":
                print("===> MySQL Server",each_property[1].upper(),"is compliant") 
            elif each_property[2] == "Disabled":
                print("===> MySQL Server",each_property[1].upper(),"is not compliant")
            else:
                print("===> MySQL Server not found")
        
        return Mysql_SSL_list


    # CIS 4.12: Ensure server parameter 'log_checkpoints' is set to 'ON' for PostgreSQL Database Server

    def Postgre_log_checkpoints(self, mgmt_token):
        postgre_checkpoint_list = list()
        req_url = url_const.POSTGRESQL_SERVER_LIST.format(self.SUBSCRIPTION_ID)
        req_header = {'Authorization': 'Bearer {}'.format(mgmt_token),
                      'Content-Type': 'application/json'}
        h = requests.get(req_url, headers=req_header)
        y = h.json()
        if not y["value"]:
            print(" ===> No PostgreSQL servers found!! ")
        post_sql_list = list()
        for _ in y:
            j = 0
            for b in y["value"]:
                post_sql_list.append([])
                post_sql_list[j].append(b["id"])
                post_sql_list[j].append(b["name"])
                post_sql_list[j].append(b["properties"]["sslEnforcement"])
                j += 1
        print("\nCIS 4.12: Ensure server parameter 'log_checkpoints' is set to 'ON' for PostgreSQL Database Server")
        for each_property in post_sql_list:
            splitted_value = each_property[0].split('/')
            req_url = url_const.POSTGRESQL_CONFIG_LIST.format(splitted_value[2], splitted_value[4], splitted_value[8])
            req_header = {'Authorization': 'Bearer {}'.format(mgmt_token),'Content-Type': 'application/json'}
            h = requests.get(req_url, headers=req_header)
            postgre_config_resp = h.json()
                
            for b in postgre_config_resp["value"]:
                if b["name"] == "log_checkpoints" and b["properties"]["value"].upper() == "ON":
                    print("===> PostgreSQL server",splitted_value[8].upper(),"is compliant")
                elif b["name"] == "log_checkpoints" and b["properties"]["value"].upper() == "OFF":
                    print("===> PostgreSQL server",splitted_value[8].upper(),"is not compliant")
                    postgre_checkpoint_list.append([])
                    postgre_checkpoint_list[self.inc].append(b["id"])
                    self.inc += 1
        self.inc = 0     
        return postgre_checkpoint_list


    # CIS 4.13: Ensure 'Enforce SSL connection' is set to 'ENABLED' for PostgreSQL Database Server
        
    def postgresql_list(self, mgmt_token):
        req_url = url_const.POSTGRESQL_SERVER_LIST.format(self.SUBSCRIPTION_ID)
        req_header = {'Authorization': 'Bearer {}'.format(mgmt_token),
                      'Content-Type': 'application/json'}
        h = requests.get(req_url, headers=req_header)
        y = h.json()
        if not y["value"]:
            print(" ===> No PostgreSQL servers found!! ")
        post_sql_list = list()
        for _ in y:
            j = 0
            for b in y["value"]:
                post_sql_list.append([])
                post_sql_list[j].append(b["id"])
                post_sql_list[j].append(b["name"])
                post_sql_list[j].append(b["properties"]["sslEnforcement"])
                j += 1

        self.post_sql_list = post_sql_list
        print("\nCIS 4.13: Ensure 'Enforce SSL connection' is set to 'ENABLED' for PostgreSQL Database Server")        
        for each_property in self.post_sql_list:
            if each_property[2] == "Enabled" :
                print(" ===> PostGreSQL Server",each_property[1].upper(),"is compliant") 
            elif each_property[2] == "Disabled":
                print(" ===> PostGreSQL Server",each_property[1].upper(),"is not compliant")
        return post_sql_list
    
    
    # CIS 4.14: Ensure server parameter 'log_connections' is set to 'ON' for PostgreSQL Database Server               

    def Postgre_log_connections(self, mgmt_token):
        print("\nCIS 4.14: Ensure server parameter 'log_connections' is set to 'ON' for PostgreSQL Database Server")
        postgre_connection_list = list()
        if not self.post_sql_list:
            print(" ===> No PostgreSQL servers found!! ")
        for each_property in self.post_sql_list:
            splitted_value = each_property[0].split('/')
            req_url = url_const.POSTGRESQL_CONFIG_LIST.format(splitted_value[2], splitted_value[4], splitted_value[8])
            req_header = {'Authorization': 'Bearer {}'.format(mgmt_token),'Content-Type': 'application/json'}
            h = requests.get(req_url, headers=req_header)
            postgre_config_resp = h.json()

            for d in postgre_config_resp["value"]:
                if d["name"] == "log_connections" and d["properties"]["value"].upper() == "ON":
                    print(" ===> PostgreSQL server",splitted_value[8].upper(),"is compliant")
                elif d["name"] == "log_connections" and d["properties"]["value"].upper() == "OFF":
                    print(" ===> PostgreSQL server",splitted_value[8].upper(),"is not compliant")
                    postgre_connection_list.append([])
                    postgre_connection_list[self.inc].append(d["id"])
                    self.inc += 1  
        self.inc = 0   
        return postgre_connection_list


    # CIS 4.15 Ensure server parameter 'log_disconnections' is set to 'ON' for PostgreSQL Database Server
    
    def postgre_log_disconnections(self, mgmt_token):
        print("\nCIS 4.15 Ensure server parameter 'log_disconnections' is set to 'ON' for PostgreSQL Database Server")
        postgre_disconnection_list = list()
        if not self.post_sql_list:
            print(" ===> No PostgreSQL servers found!! ")
        for each_property in self.post_sql_list:
            splitted_value = each_property[0].split('/')
            req_url = url_const.POSTGRESQL_CONFIG_LIST.format(splitted_value[2], splitted_value[4], splitted_value[8])
            req_header = {'Authorization': 'Bearer {}'.format(mgmt_token),'Content-Type': 'application/json'}
            h = requests.get(req_url, headers=req_header)
            postgre_config_resp = h.json()

            for e in postgre_config_resp["value"]:
                if e["name"] == "log_disconnections" and e["properties"]["value"].upper() == "ON":
                    print(" ===> PostgreSQL server",splitted_value[8].upper(),"is compliant")
                elif e["name"] == "log_disconnections" and e["properties"]["value"].upper() == "OFF":
                    print(" ===> PostgreSQL server",splitted_value[8].upper(),"is not compliant")
                    postgre_disconnection_list.append([])
                    postgre_disconnection_list[self.inc].append(e["id"])
                    self.inc += 1  
        self.inc = 0   
        return postgre_disconnection_list
    

    # CIS 4.16 Ensure server parameter 'log_duration' is set to 'ON' for PostgreSQL Database Server

    def postgre_log_duration(self, mgmt_token):
        print("\nCIS 4.16 Ensure server parameter 'log_duration' is set to 'ON' for PostgreSQL Database Server")
        postgre_logduration_list = list()
        if not self.post_sql_list:
            print(" ===> No PostgreSQL servers found!! ")
        for each_property in self.post_sql_list:
            splitted_value = each_property[0].split('/')
            req_url = url_const.POSTGRESQL_CONFIG_LIST.format(splitted_value[2], splitted_value[4], splitted_value[8])
            req_header = {'Authorization': 'Bearer {}'.format(mgmt_token),'Content-Type': 'application/json'}
            h = requests.get(req_url, headers=req_header)
            postgre_config_resp = h.json()

            for f in postgre_config_resp["value"]:
                if f["name"] == "log_duration" and f["properties"]["value"].upper() == "ON":
                    print(" ===> PostgreSQL server",splitted_value[8].upper(),"is compliant")
                elif f["name"] == "log_duration" and f["properties"]["value"].upper() == "OFF":
                    print(" ===> PostgreSQL server",splitted_value[8].upper(),"is not compliant")
                    postgre_logduration_list.append([])
                    postgre_logduration_list[self.inc].append(f["id"])
                    self.inc += 1  
        self.inc = 0   
        return postgre_logduration_list


    # CIS 4.17: Ensure server parameter 'connection_throttling' is set to 'ON' for PostgreSQL Database Server
    
    def postgre_connection_throttling(self, mgmt_token):
        print("\nCIS 4.17: Ensure server parameter 'connection_throttling' is set to 'ON' for PostgreSQL Database Server")
        postgre_connthrottling_list = list()
        if not self.post_sql_list:
            print(" ===> No PostgreSQL servers found!! ")
        for each_property in self.post_sql_list:
            splitted_value = each_property[0].split('/')
            req_url = url_const.POSTGRESQL_CONFIG_LIST.format(splitted_value[2], splitted_value[4], splitted_value[8])
            req_header = {'Authorization': 'Bearer {}'.format(mgmt_token),'Content-Type': 'application/json'}
            h = requests.get(req_url, headers=req_header)
            postgre_config_resp = h.json()

            for g in postgre_config_resp["value"]:
                if g["name"] == "connection_throttling" and g["properties"]["value"].upper() == "ON":
                    print(" ===> PostgreSQL server",splitted_value[8].upper(),"is compliant")
                elif g["name"] == "connection_throttling" and g["properties"]["value"].upper() == "OFF":
                    print(" ===> PostgreSQL server",splitted_value[8].upper(),"is not compliant")
                    postgre_connthrottling_list.append([])
                    postgre_connthrottling_list[self.inc].append(g["id"])
                    self.inc += 1  
        self.inc = 0   
        return postgre_connthrottling_list


    # CIS 4.18: Ensure server parameter 'log_retention_days' is greater than 3 days for PostgreSQL Database Server

    def postgre_log_retention(self, mgmt_token):
        print("\nCIS 4.18: Ensure server parameter 'log_retention_days' is greater than 3 days for PostgreSQL Database Server")
        postgre_logretention_list = list()
        if not self.post_sql_list:
            print(" ===> No PostgreSQL servers found!!")
        for each_property in self.post_sql_list:
            splitted_value = each_property[0].split('/')
            req_url = url_const.POSTGRESQL_CONFIG_LIST.format(splitted_value[2], splitted_value[4], splitted_value[8])
            req_header = {'Authorization': 'Bearer {}'.format(mgmt_token),'Content-Type': 'application/json'}
            h = requests.get(req_url, headers=req_header)
            postgre_config_resp = h.json()

            for h in postgre_config_resp["value"]:
                if h["name"] == "log_retention_days" and h["properties"]["value"] >= "4":
                    print(" ===> PostgreSQL server",splitted_value[8].upper(),"is compliant")
                elif h["name"] == "log_retention_days" and h["properties"]["value"] <= "3":
                    print(" ===> PostgreSQL server",splitted_value[8].upper(),"is not compliant")
                    postgre_logretention_list.append([])
                    postgre_logretention_list[self.inc].append(h["id"])
                    self.inc += 1  
        self.inc = 0   
        return postgre_logretention_list