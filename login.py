import sys, getopt, getpass
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto import Random
from netsim.netinterface import network_interface
from datetime import datetime
from time import time

username = ''
password = ''
pubkeyfile = 'test_pubkey.pem'
privkeyfile = 'test_keypair.pem'

def generate_session_key():
    sessionkey = Random.get_random_bytes
    pubkey = load_publickey(pubkeyfile)
    RSAcipher = PKCS1_OAEP.new(pubkey)

    symkey = Random.get_random_bytes(32) # we need a 256-bit (32-byte) AES key
    sessionkey = Random.get_random_bytes(32)
    iv = Random.get_random_bytes(AES.block_size)
    AEScipher = AES.new(key, AES.MODE_CBC, iv)

    encsymkey = RSAcipher.encrypt(symkey)

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


#generate login message
def generate_message(username, password):
    payload = generate_payload(username, password)
    header = generate_message_header(len(payload))
    return header + payload


# generate message header (5 bytes)
def generate_message_header(msg_length):
    header_version = b'\x01\x00'                            # protocol version 1.0
    header_type = b'\x01'                                   # message type 0
    header_length = msg_length.to_bytes(2, byteorder='big') # message length
    return header_version + header_type + header_length


# generate payload for login message
def generate_payload(username, password):
    return generate_hashed_credentials(username, password) + \
           generate_timestamp() + generate_session_key()


# hash user credentials
def generate_hashed_credentials(username, password):
    hashfnUsername = SHA256.new()
    hashfnUsername.update(username.encode("utf-8"))
    hashed_username = hashfnUsername.digest()
    hashfnPassword = SHA256.new()
    hashfnPassword.update(password.encode("utf-8"))
    hashed_password = hashfnPassword.digest()

    credentials = hashed_username + hashed_password
    return credentials


# generate current timestamp (20 bytes)
def generate_timestamp():
    dt = datetime.now()
    timestamp = int(dt.timestamp() * 1e3)
    # return dt.strftime('%Y%m%d%H%M%S%f').encode("utf-8")
    return timestamp.to_bytes(13, byteorder='big')


# generate session symmetric key ()
def generate_session_key():
    return Random.get_random_bytes(AES.block_size)

i = 1
print(i.to_bytes(1, byteorder='big'))
print(generate_timestamp())
