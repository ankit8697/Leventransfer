import sys, getopt, getpass
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Signature import pss
from Crypto import Random
from netsim.netinterface import network_interface
from datetime import datetime

# Assumption: Username will be OWN_ADDR
NET_PATH = './netsim/'
OWN_ADDR = ''
session_key = ''
iv = ''
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
    AEScipher = AES.new(sessionkey, AES.MODE_CBC, iv)

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
    return generate_hashed_credentials(username, password) + generate_timestamp() + generate_sk() + generate_nonce()

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
    return dt.strftime('%Y%m%d%H%M%S%f').encode("utf-8")

# generate session symmetric key ()
def generate_sk():
    session_key = Random.get_random_bytes(AES.block_size)
    return session_key

def generate_iv():
    iv = Random.get_random_bytes(AES.block_size)
    return iv

# print(len(generate_message("bob", "abc")))

OWN_ADDR = username
netif = network_interface(NET_PATH, OWN_ADDR)
logged_in = False
while True:
    if not logged_in:
        message = generate_message(username, password)
        netif.send_msg('S', message)
        status, msg = netif.receive_msg(blocking=True)
        if status:
            cipher = AES.new(session_key, AES.MODE_CBC, iv=iv) 
            pubkey = load_publickey('test_pubkey.pem')
            verifier = pss.new(pubkey)
            h = SHA256.new()
            h.update(msg[:-7])
            try:
                verifier.verify(h, msg[-7:])
            except (ValueError, TypeError) as e:
                print('That username and password does not exist. Please try again.')
                break
            print('Login Successful. Please enter your commands.')
            logged_in = True
    
    else:
        # We are now ready to send commands
        command = input('Enter your command: ')
        if command[:3] == 'MKD':
            filename = command[7:]

        elif command[:3] == 'RMD':
            filename = command[7:]

        elif command[:3] == 'GWD':
            pass

        elif command[:3] == 'CWD':
            filepath = command[7:]

        elif command[:3] == 'LST':
            pass

        elif command[:3] == 'UPL':
            filename = command[7:]

        elif command[:3] == 'DNL':
            pass

        elif command[:3] == 'RMF':
            filename = command[7:]


    if input('Continue? (y/n): ') == 'n': break
    
	
