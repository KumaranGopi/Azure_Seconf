import json


def creds_load():
    """To load the credentials from the creds.json file for CIS Benchmark

    Returns:

        dict -- Contains all the credential information such as subscription ID, tenant id, client id and secrect.
        False -- If any exception found.
    
    Raises:
    
        FileNotFoundError -- If creds.json file is not found.
        Exception --  for any other exception
    """
    try:
        with open('creds.json') as creds_file:
            az_creds = json.load(creds_file)
    except FileNotFoundError as no_cred_file:
        print("Unable to find the creds.json file: ", no_cred_file)
        return False
    except Exception as e:
        print(e)
        return False

    return az_creds["CREDENTIALS"]
