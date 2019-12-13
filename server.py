import sys, getopt, getpass, os, time, shutil, json
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto.Hash import SHA256, HMAC
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pss
from Crypto import Random
from datetime import datetime
from base64 import b64encode, b64decode
from netsim.netinterface import network_interface


'''
=========================== CONSTANTS AND VARIABLES ============================
'''

# protocol codes
TYPE_LOGIN = 0
TYPE_COMMAND = 1
LENGTH_HEADER = 21
LENGTH_SIGNATURE = 256
LENGTH_AUTHTAG = 16
SUCCESS = '200'          # successful operation (login or command)
BAD_COMMAND = '500'      # failure to execute command
BAD_MSG_LENGTH = '501'   # invalid message length in header
BAD_TIMESTAMP = '502'    # invalid timestamp (expired or in the future)
BAD_AUTH_AND_DEC = '503' # failure to verify authtag and decrypt
BAD_CREDENTIALS = '504'  # invalid credentials (username, hash of password)
BAD_SIGNATURE = '505'    # invalid signature
SERVER_BUSY = '506'
TIMESTAMP_WINDOW = 5     # window for timestamp verification
RED = '\033[91m'
GREEN = '\033[92m'
ORANGE = '\033[93m'
BLUE = '\033[94m'

# network constants/variables
NET_PATH = './network/'
OWN_ADDR = 'S'
CLIENT_ADDR = 'L'
NUMBER_OF_USERS = 4
USERNAME = ''
LOGGED_IN = False
CURRENT_SERVER_DIR = './server/'
CURRENT_CLIENT_DIR = './client/'

# crypto constants/variables
SESSION_KEY = ''
KEY_PAIR = None


'''
================================== FUNCTIONS ===================================
'''
### load key functions

def load_keypair():
    privkeyfile = 'server/test_keypair.pem'
    passphrase = getpass.getpass('Enter a passphrase to load the RSA keypair:')
    # passphrase = 'cryptography'

    with open(privkeyfile, 'rb') as f:
        keypairstr = f.read()
    try:
        return RSA.import_key(keypairstr, passphrase = passphrase)

    except ValueError:
        print('Error: Cannot import private key from file ' + privkeyfile)
        sys.exit(1)


def load_publickey(pubkeyfile):
    with open(pubkeyfile, 'rb') as f:
        pubkeystr = f.read()
    try:
        return RSA.import_key(pubkeystr)
    except ValueError:
        print('Error: Cannot import public key from file ' + pubkeyfile)
        sys.exit(1)


### send and receive message functions
# send server response
def send_response(dst, msg_type, keypair, sessionkey, response):
    response = generate_message(msg_type, keypair, sessionkey, response).encode('utf-8')
    display_sent_msg(response)
    netif.send_msg(dst, response)


# receive client message
def receive_client_message():
    return netif.receive_msg(blocking=True)


### generate message functions
# create server message
def generate_message(msg_type, keypair, sessionkey, payload):
    # get timestamp and random bytes
    timestamp = generate_timestamp()
    random = Random.get_random_bytes(3)
    nonce = timestamp + random

    # get encrypted payload and authentication tag
    AE = AES.new(sessionkey, AES.MODE_GCM, nonce=nonce, mac_len=LENGTH_AUTHTAG)

    if msg_type == TYPE_LOGIN:
        msg_len = LENGTH_HEADER + len(payload) + LENGTH_AUTHTAG + LENGTH_SIGNATURE
        header = generate_header(msg_type, msg_len, timestamp, random)
        header_dict = generate_header_dict(header)

        AE.update(header)
        enc_payload, authtag = AE.encrypt_and_digest(payload)

        # sign message
        signer = pss.new(keypair)
        hashfn = SHA256.new(header + enc_payload + authtag)
        signature = signer.sign(hashfn)

        msg_k = ['header', 'enc_payload', 'authtag', 'signature']
        msg_v = [header_dict] + [b64encode(x).decode('utf-8') for x in [enc_payload, authtag, signature]]

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


# convert header to readable format
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


# create the server message payload
def generate_payload(response):
    return (response).encode("utf-8")


### process message functions
# process client message to get session key, response code, payload
def process_message(msg_type, msg, keypair, sessionkey=None):
    try:
        msg_dict = json.loads(msg.decode('utf-8'))
        header_dict = msg_dict['header']
        msg_length = 0

        # parse fields in the message
        if header_dict['type'] == TYPE_LOGIN:
            enc_sessionkey = b64decode(msg_dict['enc_sessionkey'].encode('utf-8'))
            sessionkey = decrypt_sessionkey(enc_sessionkey, keypair)
            msg_length += len(enc_sessionkey)
            # failure to decrypt session key returns in NULL response code
            if (not sessionkey):
                sessionkey = generate_sessionkey()
                return sessionkey, BAD_AUTH_AND_DEC, None
            if (msg_type == TYPE_COMMAND):
                return sessionkey, SERVER_BUSY, None

        digit_1 = int(header_dict['version'])
        digit_2 = int(header_dict['version'] * 10) % 10
        header_version = digit_1.to_bytes(1, byteorder='big') + \
                         digit_2.to_bytes(1, byteorder='big')
        header_type = header_dict['type'].to_bytes(1, byteorder='big')
        header_length = header_dict['length'].to_bytes(2, byteorder='big')
        header_timestamp = header_dict['timestamp'].encode('utf-8')
        header_random = b64decode(header_dict['random'])
        header_nonce = header_timestamp + header_random
        header = header_version + header_type + header_length + header_nonce
        enc_payload = b64decode(msg_dict['enc_payload'])
        authtag = b64decode(msg_dict['authtag'])
        msg_length += len(header) + len(enc_payload) + len(authtag)

        # verify header length
        if msg_length != header_dict['length']:
            print("Client message error: invalid header length.")
            return sessionkey, BAD_MSG_LENGTH, None

        # verify timestamp
        if not valid_timestamp(header_dict['timestamp']):
            print("Client message error: invalid timestamp.")
            return sessionkey, BAD_TIMESTAMP, None

        # authenticate and decrypt payload
        AE = AES.new(sessionkey, AES.MODE_GCM, nonce=header_nonce)
        if msg_type == TYPE_LOGIN:
            AE.update(header + enc_sessionkey)
        elif msg_type == TYPE_COMMAND:
            AE.update(header)

        payload = AE.decrypt_and_verify(enc_payload, authtag)
        return sessionkey, SUCCESS, payload

    except (ValueError, KeyError):
        print("Client message error: the client message may be compromised.")
        return sessionkey, BAD_AUTH_AND_DEC, None


# get session key
def decrypt_sessionkey(enc_sessionkey, keypair):
    try:
        RSAcipher = PKCS1_OAEP.new(keypair)
        return RSAcipher.decrypt(enc_sessionkey)

    except (ValueError, TypeError):
        print("Login message error: cannot decrypt session key.")
        return None # if failure, return Null


# verify timestamp_length
def valid_timestamp(timestamp):
    current_timestamp = int(generate_timestamp().decode('utf-8'))
    delta_t = current_timestamp - int(timestamp)
    tolerance = TIMESTAMP_WINDOW * 1e3 # in milliseconds
    return (delta_t >= 0) and (delta_t < tolerance)


# verify credentials
def verify_credentials(credentials):
    try:
        length_username = ord(credentials[:1])
        username = credentials[1:length_username + 1]
        username = username.decode('utf-8')
        password = credentials[length_username + 1:]

        hashfn = SHA256.new()
        hashfn.update(password)
        hash_password = hashfn.digest()
        hash_password = b64encode(hash_password).decode('utf-8')

        with open('server/users.json', 'r') as f:
            credentials_dict = json.load(f)
            
            if credentials_dict[username] == hash_password:
                with open('server/addr_mapping.json', 'r') as g:
                    addr_dict = json.load(g)
                    return username, addr_dict[username]
        return None, None

    except Exception as e:
        print(e)
        print("Login message error: cannot verify user credentials.")
        return None, None


# checks path validity
def fix_path(directory, username, type = 'SERVER'):
    real_path = os.path.realpath(directory)
    path = real_path.replace(os.getcwd(), '.')
    if type == 'SERVER':
        expected_prefix = './server/' + username
    else:
        expected_prefix = './client/' + username

    if path[0:len(expected_prefix)] != expected_prefix:
            return None
    return path


def display_sent_msg(msg):
    color = ORANGE
    print(f'{color}\nMessage sent:\033[0m')
    print(msg.decode('utf-8'))
    print()


def display_received_msg(msg):
    color = BLUE
    print(f'{color}\nMessage received:\033[0m')
    print(msg.decode('utf-8'))
    print()


'''
================================== MAIN CODE ===================================
'''
# set server folder as root directory
netif = network_interface(NET_PATH, OWN_ADDR)

# load keypair using passphrase
KEY_PAIR = load_keypair()

print('Server connected...')

while True:
    status, msg = receive_client_message() # receive client login message
    display_received_msg(msg)

    if status:
        if not LOGGED_IN:
            SESSION_KEY, response_code, payload = process_message(TYPE_LOGIN, msg, KEY_PAIR)
            user_addr = None

            if response_code == SUCCESS:
                # verify credentials
                username, user_addr = verify_credentials(payload)
                if user_addr:
                    LOGGED_IN = True
                    CURRENT_SERVER_DIR += username
                    USERNAME = username
                    print(f'Current server directory: {CURRENT_SERVER_DIR}')

                else:
                    response_code = BAD_CREDENTIALS

            send_response(CLIENT_ADDR, TYPE_LOGIN, KEY_PAIR, SESSION_KEY, response_code.encode('utf-8'))
            if user_addr:
                CLIENT_ADDR = user_addr

        else:
            sessionkey, response_code, payload = process_message(TYPE_COMMAND, msg, KEY_PAIR, SESSION_KEY)

            if response_code == SERVER_BUSY:
                send_response('L', TYPE_LOGIN, KEY_PAIR, sessionkey, response_code.encode('utf-8'))
                continue

            SESSION_KEY = sessionkey

            if response_code == SUCCESS:
                command_arguments = payload.decode('utf-8').split()
                command = ''
                response = BAD_COMMAND

                if len(command_arguments) > 0:
                    command = command_arguments[0]

                if command == 'MKD':
                    foldername = f"{CURRENT_SERVER_DIR}/{command_arguments[2]}"
                    try:
                        print(fix_path(foldername, USERNAME))
                        os.mkdir(fix_path(foldername, USERNAME))
                    except (OSError, TypeError) as e:
                        print(e)
                        print(f'The folder \"{foldername}\" could not be created.')
                    else:
                        response = SUCCESS
                        print(f'The folder \"{foldername}\" has been created.')

                elif command == 'RMD':
                    foldername = f"{CURRENT_SERVER_DIR}/{command_arguments[2]}"
                    try:
                        os.rmdir(fix_path(foldername, USERNAME))
                        if command_arguments[2] == '.':
                            CURRENT_SERVER_DIR = fix_path(foldername, USERNAME)
                            folder = os.path.basename(CURRENT_SERVER_DIR)
                            CURRENT_SERVER_DIR = CURRENT_SERVER_DIR[:-len(folder)-1]

                    except (OSError, TypeError):
                        print(f'The folder \"{foldername}\" could not be removed.')
                    else:
                        response = SUCCESS
                        print(f'The folder \"{foldername}\" has been removed.')

                elif command == 'GWD':
                    try:
                        directory = CURRENT_SERVER_DIR.replace('./server/', '')
                        response = SUCCESS + directory
                        print(f'The current directory is \"{directory}\".')
                    except OSError:
                        print('The current directory could not be identified.')

                elif command == 'CWD':
                    foldername = command_arguments[2]
                    temp_dir = fix_path(f'{CURRENT_SERVER_DIR}/{foldername}', USERNAME)
                    print(temp_dir)
                    try:
                        if os.path.exists(temp_dir):
                            CURRENT_SERVER_DIR = temp_dir
                            directory = CURRENT_SERVER_DIR.replace('./server/', '')
                            response = SUCCESS
                            print(f'The current directory is now \"{directory}\".')
                        else:
                            print(f'The current directory could not be changed via the given path.')
                    except (OSError, TypeError):
                        print(f'The current folder could not be changed via the given path.')

                elif command == 'LST':
                    try:
                        items = os.listdir(CURRENT_SERVER_DIR)
                    except OSError:
                        print(f'Failed to retrieve the list of items.' )
                    else:
                        response = SUCCESS
                        items_list = ''
                        # print(items)
                        for item in items:
                            items_list += item + '\n'

                        items_list = items_list[:-1]
                        response += items_list
                        print(f'Successfully sent the list of items in {CURRENT_SERVER_DIR} to client')

                elif command == 'UPL':
                    filepath = command_arguments[2]
                    filepath = CURRENT_CLIENT_DIR + USERNAME + '/' + filepath
                    # print(filepath)
                    try:
                        shutil.copy(fix_path(filepath, USERNAME, 'CLIENT'), CURRENT_SERVER_DIR)
                    except (OSError, TypeError) as e:
                        print(e)
                        print(f'The file from \"{filepath}\" could not be uploaded')
                    else:
                        response = SUCCESS
                        print(f'The file from \"{filepath}\" has been uploaded.')

                elif command == 'DNL':
                    filename = command_arguments[2]
                    dstpath = command_arguments[4]
                    dstpath = CURRENT_CLIENT_DIR + USERNAME + '/' + dstpath
                    source = CURRENT_SERVER_DIR + '/' + filename
                    try:
                        shutil.copy(fix_path(source, USERNAME), fix_path(dstpath, USERNAME, 'CLIENT'))
                    except (OSError, TypeError) as e:
                        print(e)
                        print(f'The file \"{filename}\" from could not be downloaded to \"{dstpath}\".')
                    else:
                        response = SUCCESS
                        print(f'The file \"{filename}\" has been downloaded to \"{dstpath}\".')

                elif command == 'RMF':
                    filename = command_arguments[2]
                    filepath = f'{CURRENT_SERVER_DIR}/{filename}'
                    try:
                        os.remove(fix_path(filepath, USERNAME))
                    except (OSError, TypeError) as e:
                        print(e)
                        print(f'The file \"{filepath}\" could not be removed.')
                    else:
                        response = SUCCESS
                        print(f'The file \"{filepath}\" has been removed.')

                # used to indicate to server that user has logged out
                elif command == 'EXT':
                    LOGGED_IN = False
                    USERNAME = ''
                    CLIENT_ADDR = 'L'
                    CURRENT_SERVER_DIR = './server/'
                    CURRENT_CLIENT_DIR = './client/'
                    print('The user logged out.')
                    continue

                send_response(CLIENT_ADDR, TYPE_COMMAND, KEY_PAIR, SESSION_KEY, response.encode('utf-8'))
