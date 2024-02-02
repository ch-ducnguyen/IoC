from falconpy import IOC
import argparse
import os 
from dotenv import load_dotenv
import pandas as pd 

load_dotenv()

CLIENT_ID = os.getenv('CLIENT_ID')
CLIENT_SECRET = os.getenv('CLIENT_SECRET')


def tlist(tag: str):
    return [i.upper() for i in tag.split(',')]

def action(action : str):
    return action.lower()

def plist(platform: str):
    return [i.capitalize() for i in platform.split(',')]

parser = argparse.ArgumentParser()
parser.add_argument('-C','--csv',help='Path to csv file',required=True,action='store')
parser.add_argument('-t','--tag',help="""Tag for indicator. Use "," as delimeter. Example TAG1,TAG2,TAG3""",type=tlist,required=True)
parser.add_argument('-G','--apply-global',help='Apply globally (Default = False)',default=False,action='store_true')
parser.add_argument('-s','--severity',help='Indicator severity (Default = Informational)',default='Informational')
parser.add_argument('-p','--platform',help='Platform name. Use "," as delimeter. Example Windows,Mac,Linux',default='Windows,Mac,Linux',type=plist)
parser.add_argument('-H','--host-group',help='Host group. Use "," as delimeter. If --apply-global is set this will be empty',type=tlist, default="")
parser.add_argument('-c','--comment',help='Comment for indicator (Default is empty)',default="")
parser.add_argument('-d','--description',help='Description for indicator (Default is empty)',default="")
parser.add_argument('-a','--action',help="Action for indicator (Default is detect). Valid value : 'detect','block'",default='detect',type=action)

args = parser.parse_args()

if args.apply_global == False and args.host_group is [""]:
    print('[!] Please specify host group. Use -h or --help for more information.')
    exit(1)
if args.apply_global == True: 
    args.host_group = ""

# Do not hardcode API credentials!
falcon = IOC(client_id=CLIENT_ID,
             client_secret=CLIENT_SECRET
             )

def falcon_request(ioc_type,ioc_value):
    response = falcon.indicator_create(action=args.action,
                                       applied_globally=args.apply_global,
                                       comment=args.comment,
                                       description=args.description,
                                       host_groups=args.host_group,
                                       ignore_warnings=True,
                                       platforms=args.platform,
                                       severity=args.severity,
                                       tags=args.tag,
                                       type=ioc_type,
                                       value=ioc_value)  
    return response

def check_response(response,ioc_value):
    if response['status_code'] == 201:
        print(f'[+] IoC for {ioc_value} created')
    else:
        print(response)
def create_IoCs(df: pd.DataFrame):
    for _, row in df.iterrows():
        ioc_type_pre = row['ItemType']

        if ioc_type_pre == 'IP Address':
            ioc_type_ipv4 = 'IPv4'
            ioc_value_ipv4 = row['Item'].replace('[', '').replace(']', '')
            response = falcon_request(ioc_type_ipv4,ioc_value_ipv4)
            check_response(response,ioc_value_ipv4)
        elif ioc_type_pre == 'File':
            ioc_value_md5 = row['MD5']
            ioc_type_md5 = 'MD5'
            ioc_value_sha256 = row['SHA256']
            ioc_type_sha256 = 'SHA256'
            md5_response = falcon_request(ioc_type_md5,ioc_value_md5)
            sha256_response = falcon_request(ioc_type_sha256,ioc_value_sha256)
            check_response(md5_response,ioc_value_md5)
            check_response(sha256_response,ioc_value_sha256)
        elif ioc_type_pre == 'Domain' or ioc_type_pre == 'URL':
            ioc_value_domain = row['Item'].replace('[', '').replace(']', '')
            ioc_type_domain = 'Domain'
            domain_response = falcon_request(ioc_type_domain,ioc_value_domain)
            check_response(domain_response,ioc_value_domain)
        else:
            print("[!] Unknown Item type")

if __name__ == '__main__':
    df = pd.read_csv(args.csv,delimiter=',',index_col=False)
    create_IoCs(df)
    # print(type(args.csv),type(args.tag),type(args.apply_global),type(args.severity),type(args.platform),type(args.host_group),type(args.comment),type(args.description),type(args.action))