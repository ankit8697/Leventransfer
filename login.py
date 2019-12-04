import sys, getopt, getpass
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
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


payload, username_length = generate_hashed_payload(username, password)

def generate_hashed_payload(username, password):
    hashfnUsername = SHA256.new()
    hashfnUsername.update(username)
    hashed_username = hashfnUsername.digest()
    hashfnPassword = SHA256.new()
    hashfnPassword.update(password)
    hashed_password = hashfnPassword.digest()

    username_length = len(hashed_username)

    payload = hashed_username + hashed_password
    return payload, username_length