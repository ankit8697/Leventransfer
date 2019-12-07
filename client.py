import sys, getopt, getpass, json
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES
from Crypto.Hash import SHA256, HMAC
from Crypto.Signature import pss
from Crypto import Random
from datetime import datetime
from base64 import b64encode
from netsim.netinterface import network_interface


'''
=========================== CONSTANTS AND VARIABLES ============================
'''

# protocol codes
TYPE_LOGIN = 0
TYPE_COMMAND = 1
LENGTH_HEADER = 21
LENGTH_ENC_SK = 256
LENGTH_AUTHTAG = 16
SUCCESS = '200'          # successful operation (login or command)
BAD_COMMAND = '500'      # failure to execute command
BAD_MSG_LENGTH = '501'   # invalid message length in header
BAD_TIMESTAMP = '502'    # invalid timestamp (expired or in the future)
BAD_AUTH_AND_DEC = '503' # failure to verify authtag and decrypt
BAD_CREDENTIALS = '504'  # invalid credentials (username, hash of password)
BAD_SIGNATURE = '505'    # invalid signature

RESPONSES = {
    SUCCESS: {
        'LOGIN': "Login successful. Please enter your command.",
        'MKD': "",
        'RMD': "",
        'GWD': "",
        'CWD': "",
        'LST': "",
        'UPL': "",
        'DNL': "",
        'RMF': ""
    },
    BAD_COMMAND: {
        'MKD': "",
        'RMD': "",
        'GWD': "",
        'CWD': "",
        'LST': "",
        'UPL': "",
        'DNL': "",
        'RMF': ""
    },
    BAD_MSG_LENGTH: "Message length cannot be verified.",
    BAD_TIMESTAMP: "Timestamp is invalid.",
    BAD_AUTH_AND_DEC: "Authentication and decryption of message failed.",
    BAD_CREDENTIALS: "Username or password is invalid.",
    BAD_SIGNATURE: "Authentication of server failed."
}

# network variables
NET_PATH = './netsim/'
OWN_ADDR = ''
SERVER_ADDR = 'S'

# crypto variables
sessionkey = ''
username = ''
password = ''
pubkeyfile = 'test_pubkey.pem'
privkeyfile = 'test_keypair.pem'


'''
================================== FUNCTIONS ===================================
'''

def load_publickey(pubkeyfile):
    with open(pubkeyfile, 'rb') as f:
        pubkeystr = f.read()
    try:
        return RSA.import_key(pubkeystr)
    except ValueError:
        print('Error: Cannot import public key from file ' + pubkeyfile)
        sys.exit(1)

# send login message
def send_login_message(username, password):
    sessionkey = generate_sessionkey()
    payload = generate_login_payload(username, password)
    message = generate_message(TYPE_LOGIN, sessionkey, payload)
    netif.send_msg(SERVER_ADDR, message)


# create client message
def generate_message(msg_type, sessionkey, payload):
    # get timestamp and random bytes
    timestamp = generate_timestamp()
    random = Random.get_random_bytes(3)
    nonce = timestamp + random

    # get encrypted payload and authentication tag
    AE = AES.new(sessionkey, AES.MODE_GCM, nonce=nonce, mac_len=LENGTH_AUTHTAG)

    if msg_type == TYPE_LOGIN:
        msg_len = LENGTH_HEADER + LENGTH_ENC_SK + len(payload) + LENGTH_AUTHTAG
        header = generate_header(msg_type, msg_len, timestamp, random)
        header_dict = generate_header_dict(header)

        # get encrypted session key
        pubkey = load_publickey(pubkeyfile)
        RSAcipher = PKCS1_OAEP.new(pubkey)
        enc_sk = RSAcipher.encrypt(sessionkey)

        AE.update(header + enc_sk)
        enc_payload, authtag = AE.encrypt_and_digest(payload)

        msg_k = ['header', 'enc_sessionkey', 'enc_payload', 'authtag']
        msg_v = [header_dict] + [b64encode(x).decode('utf-8') for x in [enc_sk, enc_payload, authtag]]

    elif msg_type == TYPE_COMMAND:
        msg_len = LENGTH_HEADER + len(payload) + LENGTH_AUTHTAG
        header = generate_header(msg_type, msg_len, timestamp, random)
        header_dict = generate_header_dict(header)

        AE.update(header)
        enc_payload, authtag = AE.encrypt_and_digest(payload)

        msg_k = ['header', 'enc_payload', 'authtag']
        msg_v = [header_dict] + [b64encode(x).decode('utf-8') for x in [enc_payload, authtag]]

    msg = json.dumps(dict(zip(msg_k, msg_v)), indent=2)
    return msg


# create message header (21 bytes)
def generate_header(msg_type, msg_length, timestamp, random):
    version = b'\x01\x00'                            # protocol version 1.0
    type = msg_type.to_bytes(1, byteorder='big')     # message type
    length = msg_length.to_bytes(2, byteorder='big') # message length

    return version + type + length + timestamp + random


def generate_header_dict(header):
    version = ord(header[:1]) + ord(header[1:2]) / 10
    type = int.from_bytes(header[2:3], byteorder="big")
    length = int.from_bytes(header[3:5], byteorder="big")
    timestamp = header[5:18].decode('utf-8')
    random = b64encode(header[18:21]).decode('utf-8')

    header_k = ['version', 'type', 'length', 'timestamp', 'random']
    header_v = [version, type, length, timestamp, random]

    header_dict = dict(zip(header_k, header_v))
    return header_dict


# create UNIX timestamp with millisecond precision (13 bytes)
def generate_timestamp():
    dt = datetime.now()
    return str(int(dt.timestamp() * 1e3)).encode("utf-8")


# create a session key used for AES
def generate_sessionkey():
    sessionkey = Random.get_random_bytes(32)
    return sessionkey


# create the login message payload
def generate_login_payload(username, password):
    return (username + password).encode("utf-8")


# create the command message payload
def generate_command_payload(command):
    cipher = AES.new(session_key, AES.MODE_CBC, iv=iv)
    ciphertext = cipher.encrypt(command)
    return ciphertext


def parse_command_reply(msg):
    type_of_message = msg[:1]
    version = msg[1:2]
    length = msg[2:4]
    iv = msg[4:4+AES.block_size]
    payload = msg[4+AES.block_size:4+AES.block_size+length]
    mac = msg[4+AES.block_size+length:]
    return iv, payload, mac


def verify_mac(mac):
    h = HMAC.new(session_key, digestmod=SHA256)
    h.update(payload)
    try:
        mac = h.verify()
    except (ValueError) as e:
        return False
    return True


def decrypt_server_payload(msg, iv):
    cipher = AES.new(session_key, AES.MODE_CBC, iv=iv)
    plaintext = cipher.decrypt(msg)
    return plaintext


'''
================================== MAIN CODE ===================================
'''
'''
# parse command line arguments
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

# run client logic
OWN_ADDR = username
netif = network_interface(NET_PATH, OWN_ADDR)
logged_in = False
while True:
    if not logged_in:
        send_login_msg(username, password)
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
            foldername = command[7:]
            netif.send_msg('S', generate_command_message(command))
            status, msg = netif.receive_msg(blocking=True)
            iv, payload, mac = parse_command_reply(msg)
            if verify_mac(mac):
                plaintext = decrypt_server_payload(msg, iv)
                if plaintext == b'200':
                    print(f'the folder ${foldername} has been created.')
                else:
                    print('There was an error in creating the folder.')
            else:
                print('MAC not verified. Please try again')

        elif command[:3] == 'RMD':
            foldername = command[7:]
            netif.send_msg('S', generate_command_message(command))

        elif command[:3] == 'GWD':
            netif.send_msg('S', generate_command_message(command))

        elif command[:3] == 'CWD':
            filepath = command[7:]
            netif.send_msg('S', generate_command_message(command))

        elif command[:3] == 'LST':
            netif.send_msg('S', generate_command_message(command))

        elif command[:3] == 'UPL':
            filename = command[7:]
            netif.send_msg('S', generate_command_message(command))

        elif command[:3] == 'DNL':
            values = command.split(' ')
            filename = values[2]
            destination_path = values[4]
            netif.send_msg('S', generate_command_message(command))

        elif command[:3] == 'RMF':
            filename = command[7:]
            netif.send_msg('S', generate_command_message(command))


    if input('Continue? (y/n): ') == 'n': break
'''

sessionkey = generate_sessionkey()
payload = generate_login_payload("bob", "abc")
message = generate_message(TYPE_COMMAND, sessionkey, payload)
print(message)
