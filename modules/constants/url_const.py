"""
This file should contain all the URL constants.
"""

AUTHORITY_URL = 'https://login.microsoftonline.com/{}'
MGMT_RESOURCE = 'https://management.azure.com/'
STORAGE_RESOURCE = 'https://storage.azure.com/'
VAULT_RESOURCE = 'https://vault.azure.net'

# ==================================
# STORAGE ACCCOUNT RELATED CONSTANTS
# ==================================

# {SUBSCRIPTION_ID} should be filed in {}

STORAGE_ACCOUNT_LIST = "https://management.azure.com/subscriptions/{}/providers/Microsoft.Storage/storageAccounts?api-version=2019-06-01"

# 1.{SUBSCRIPTION_ID}, 2. {RESOURCE_GROUP} 3. {STORAGE_NAME} eg: krichh1
STORAGE_ACCOUNT_HTTPS_ENABLE = "https://management.azure.com/subscriptions/{}/resourceGroups/{}/providers/Microsoft.Storage/storageAccounts/{}?api-version=2019-06-01"

# 1.{STORAGE_NAME} eg: krichh1
STORAGE_CONTAINERS_LIST = "https://{}.blob.core.windows.net/?comp=list"


# 1.{SUBSCRIPTION_ID}, 2. {RESOURCE_GROUP} 3. {STORAGE_NAME} 4. {CONTAINER_NAME}

STORAGE_CONTAINER_FIX = "https://management.azure.com/subscriptions/{}/resourceGroups/{}/providers/Microsoft.Storage/storageAccounts/{}/blobServices/default/containers/{}?api-version=2019-06-01"

# 1. {SUBSCRIPTION_ID}, 2. {RESPOURCE_GROUP} 3. {STORAGE_NAME}

STORAGE_NETWORKACCESS_RULE_DENY = "https://management.azure.com/subscriptions/{}/resourceGroups/{}/providers/Microsoft.Storage/storageAccounts/{}?api-version=2019-06-01"



# ==================================
# SECURITY SERVICES RELATED CONSTANTS
# ==================================

# 1.{SUBSCRIPTION_ID}
SUBSCRIPTION_TIER = "https://management.azure.com/subscriptions/{}/providers/Microsoft.Security/pricings?api-version=2017-08-01-preview"

# 1. {SUBSCRIPTION_ID}
SUBSCRIPTION_TIER_FIX = "https://management.azure.com/subscriptions/{}/providers/Microsoft.Security/pricings/default?api-version=2017-08-01-preview"

# 1. {SUBSCRIPTION_ID}
AUTOPROVISIONING_MONITORING_AGENT = "https://management.azure.com/subscriptions/{}/providers/Microsoft.Security/autoProvisioningSettings?api-version=2017-08-01-preview"


# 1.{SUBSCRIPTION_ID}
AUTOPROVISIONING_FIX = "https://management.azure.com/subscriptions/{}/providers/Microsoft.Security/autoProvisioningSettings/default?api-version=2017-08-01-preview"

# 1. {SUBSCRIPTION_ID}
CHECK_SECURITY_CONTACTS = "https://management.azure.com/subscriptions/{}/providers/Microsoft.Security/securityContacts?api-version=2017-08-01-preview"

# 1. {SUBSCRIPTION_ID}
ADDSECURITY_CONTACTS_FIX = "https://management.azure.com/subscriptions/{}/providers/Microsoft.Security/securityContacts/default1?api-version=2017-08-01-preview"

UPDATESECURITY_CONTACT_FIX = "https://management.azure.com/subscriptions/{}/providers/Microsoft.Security/securityContacts/{}?api-version=2017-08-01-preview"




# ==================================
# SQL DB RELATED CONSTANTS
# ==================================

# 1. {SUBSCRIPTION_ID}

SQL_SERVERS_LIST = "https://management.azure.com/subscriptions/{}/providers/Microsoft.Sql/servers?api-version=2019-06-01-preview"


# 1. {SUBSCRIPTION_ID} 2. {RESOURCE_GROUP} 3. {SQL_SERVER}

SQL_DB_LIST = "https://management.azure.com/subscriptions/{}/resourceGroups/{}/providers/Microsoft.Sql/servers/{}/databases?api-version=2017-10-01-preview"

# 1. {SUBSCRIPTION_ID} 2. {RESOURCE_GROUP} 3. {SQL_SERVER} 4. {DB_NAME}

TDE_CONFIG_DB = "https://management.azure.com/subscriptions/{}/resourceGroups/{}/providers/Microsoft.Sql/servers/{}/databases/{}/transparentDataEncryption/current?api-version=2014-04-01"

# 1. {SUBSCRIPTION_ID} 2. {RESOURCE_GROUP} 3. {SQL_SERVER} 4. {DB_NAME}
 
UPDATE_TDE_CONFIG = "https://management.azure.com/subscriptions/{}/resourceGroups/{}/providers/Microsoft.Sql/servers/{}/databases/{}/transparentDataEncryption/current?api-version=2014-04-01"

# 1. {SUBSCRIPTION_ID} 2. {RESOURCE_GROUP} 3. {SQL_SERVER}

TDE_PROTECTOR_CHECK = "https://management.azure.com/subscriptions/{}/resourceGroups/{}/providers/Microsoft.Sql/servers/{}/encryptionProtector?api-version=2015-05-01-preview"

# 1. {SUBSCRIPTION_ID} 2. {RESOURCE_GROUP} 3. {SQL_SERVER} 4.{KEY_NAME}

CREATE_SERVER_KEY = "https://management.azure.com/subscriptions/{}/resourceGroups/{}/providers/Microsoft.Sql/servers/{}/keys/{}?api-version=2015-05-01-preview"

# 1. {SUBSCRIPTION_ID} 2. {RESOURCE_GROUP} 3. {SQL_SERVER}

UPDATE_ENCRYPTION_PROTECTOR = "https://management.azure.com/subscriptions/{}/resourceGroups/{}/providers/Microsoft.Sql/servers/{}/encryptionProtector/current?api-version=2015-05-01-preview"

# 1. {SUBSCRIPTION_ID

MYSQL_SERVER_LIST = "https://management.azure.com/subscriptions/{}/providers/Microsoft.DBforMySQL/servers?api-version=2017-12-01"

# 1. {SUBSCRIPTION_ID} 2. {RESOURCE_GROUP} 3. {SQL_SERVER}

MYSQL_SSL_FIX = "https://management.azure.com/subscriptions/{}/resourceGroups/{}/providers/Microsoft.DBforMySQL/servers/{}?api-version=2017-12-01"

# 1. {SUBSCRIPTION_ID}

POSTGRESQL_SERVER_LIST = "https://management.azure.com/subscriptions/{}/providers/Microsoft.DBforPostgreSQL/servers?api-version=2017-12-01"

# 1. {SUBSCRIPTION_ID} 2. {RESOURCE_GROUP} 3. {POSTGRESQL_SERVER}

POSTGRESQL_SSL_FIX = "https://management.azure.com/subscriptions/{}/resourceGroups/{}/providers/Microsoft.DBforPostgreSQL/servers/{}?api-version=2017-12-01"

# 1. {SUBSCRIPTION_ID} 2. {RESOURCE_GROUP} 3. {POSTGRESQL_SERVER}

POSTGRESQL_CONFIG_LIST = "https://management.azure.com/subscriptions/{}/resourceGroups/{}/providers/Microsoft.DBforPostgreSQL/servers/{}/configurations?api-version=2017-12-01"

# 1. {SUBSCRIPTION_ID} 2. {RESOURCE_GROUP} 3. {POSTGRESQL_SERVER} 4.{CONFIG_NAME}

POSTGRESQL_CONFIG_UPDATE = "https://management.azure.com/subscriptions/{}/resourceGroups/{}/providers/Microsoft.DBforPostgreSQL/servers/{}/configurations/{}?api-version=2017-12-01"





# ===========================================
# LOGGING AND MONITORING RELATED CONSTANTS
# ===========================================

# 1. {SUBSCRIPTION_ID}

LOG_PROFILES_LIST = "https://management.azure.com/subscriptions/{}/providers/microsoft.insights/logprofiles?api-version=2016-03-01"

# 1. {SUBSCRIPTION_ID} 2. {LOG_PROFILE}

CREATE_LOG_PROFILE = "https://management.azure.com/subscriptions/{}/providers/microsoft.insights/logprofiles/{}?api-version=2016-03-01"

# 1. {SUBSCRIPTION_ID}

NETWORK_WATCHER_LIST = "https://management.azure.com/subscriptions/{}/providers/Microsoft.Network/networkWatchers?api-version=2016-03-30"

# 1. {SUBSCRIPTION_ID} 2. {RESOURCE_GROUP} 3. {NETWORKWATCHER_NAME}

CREATE_NETWORK_WATCHER = "https://management.azure.com/subscriptions/{}/resourceGroups/{}/providers/Microsoft.Network/networkWatchers/{}?api-version=2020-04-01"




# ==================================
# KEY-VAULT RELATED CONSTANTS
# ==================================

# 1. {SUBSCRIPTION_ID}

LIST_KEY_VAULT = "https://management.azure.com/subscriptions/{}/providers/Microsoft.KeyVault/vaults?api-version=2019-09-01"

# 1. {VAULT_BASE_URI}

GET_KEYS = "{}/keys?api-version=7.0"


# 1. {VAULT_BASE_URI}  2. {key-name}


GET_KEY_VERSION = "{}/keys/{}/versions?api-version=7.0"


# 1. {VAULT_BASE_URI}  2. {key-name}  3. {key-version}

UPDATE_KEYS = "{}/keys/{}/{}?api-version=7.0"

# 1. {VAULT_BASE_URI}

GET_SECRETS = "{}/secrets?api-version=7.0"

# 1. {VAULT_BASE_URI}  2. {secret-name}

GET_SECRET_VERSION = "{}/secrets/{}/versions?api-version=7.0"

# 1. {VAULT_BASE_URI}  2. {secret-name}  3. {secret-version}

UPDATE_SECRETS = "{}/secrets/{}/{}?api-version=7.0"

# 1. {SUBSCRIPTION_ID} 2. {RESOURCE_GROUP} 3. {KEY_VAULT_NAME}

UPDATE_KEY_VAULT = "https://management.azure.com/subscriptions/{}/resourceGroups/{}/providers/Microsoft.KeyVault/vaults/{}?api-version=2019-09-01"



