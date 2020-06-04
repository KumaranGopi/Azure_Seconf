"""
if you want to implement the argument parsing feature 

such as azure_cis.py -h or -v then you need to write the argument parse thing here and call it
in  the main script
"""
import argparse

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--check-compliance", action="store_true", required=True)
    parser.add_argument("-r", "--remediation", action="store_true", required=False)

