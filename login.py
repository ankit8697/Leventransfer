import sys, getopt, getpass
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from netsim.netinterface import network_interface

username = ''
password = ''

try:
    opts, args = getopt.getopt(sys.argv[1:], 'hu:p:', ['help', 'username=', 'password='])
except:
    print('Usage:')
    print('  - Login Protocol:')
    print('    login.py -u <username> -p <password>')

for opt, arg in opts:
    if opt in ('-h', '--help'):
        print('Usage:')
        print('  - Login Protocol')
        print('    login.py -u <username> -p <password>')
    elif opt in ('-u', '--username'):    
        username = arg
    elif opt in ('-p', '--password'):
        password = arg
