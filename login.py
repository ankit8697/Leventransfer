import sys, getopt, getpass
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from netsim.netinterface import network_interface

username = ''
password = ''
pubkeyfile = 'test_pubkey.pem'

def load_publickey(pubkeyfile):
    with open(pubkeyfile, 'rb') as f:
        pubkeystr = f.read()
    try:
        return RSA.import_key(pubkeystr)
    except ValueError:
        print('Error: Cannot import public key from file ' + pubkeyfile)
        sys.exit(1)

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


pubkey = load_publickey(pubkeyfile)
RSAcipher = PKCS1_OAEP.new(pubkey)

symkey = Random.get_random_bytes(32) # we need a 256-bit (32-byte) AES key
sessionkey = Random.get_random_bytes(32)
iv = Random.get_random_bytes(AES.block_size)
AEScipher = AES.new(key, AES.MODE_CBC, iv)

encsymkey = RSAcipher.encrypt(symkey)


payload, username_length = generate_hashed_payload(username, password)
