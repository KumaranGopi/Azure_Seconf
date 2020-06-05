"""
if you want to implement the argument parsing feature 

such as azure_cis.py -h or -v then you need to write the argument parse thing here and call it
in  the main script

-c or -r
"""
from argparse import ArgumentParser, RawTextHelpFormatter


parser = ArgumentParser(prog='Azure SeConf',
                                description='Azure CIS benchmark tool for compliance and remediation',
                                formatter_class=RawTextHelpFormatter)

azure_seconf_group = parser.add_mutually_exclusive_group(required=True)                                    
azure_seconf_group.add_argument("-c", "--check_compliance",
                                help='To check whether your Azure subscription is compliant to CIS Benchmark', action='store_true')
azure_seconf_group.add_argument("-r", "--remediation",
                                help='To remediate the Azure Resource Configs as per CIS Benchmark', action='store_true')
azure_seconf_group.add_argument("-v", "--version", help='To display the version of the tool')
