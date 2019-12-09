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

TIMESTAMP_WINDOW = 5     # window for timestamp verification

# network constants/variables
NET_PATH = './network/'
OWN_ADDR = 'S'
CLIENT_ADDR = 'L'
CURRENT_DIR = './server/'
NUMBER_OF_USERS = 4
USERNAME = ''
LOGGED_IN = False

# crypto constants/variables
SESSION_KEY = ''


'''
================================== FUNCTIONS ===================================
'''
### load key functions

def load_keypair():
    privkeyfile = 'server/test_keypair.pem'
    # passphrase = getpass.getpass('Enter a passphrase to protect the saved private key')
    passphrase = 'cryptography'

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
def send_response(dst, msg_type, sessionkey, response):
    response = generate_message(msg_type, sessionkey, response)
    print(dst)
    netif.send_msg(dst, response.encode('utf-8'))
    print("Sent response")


# receive client message
def receive_client_message():
    return netif.receive_msg(blocking=True)


### generate message functions
# create server message
def generate_message(msg_type, sessionkey, payload):
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
        keypair = load_keypair()
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
def process_message(msg_type, msg, sessionkey=None):
    try:
        msg_dict = json.loads(msg.decode('utf-8'))
        msg_length = 0

        # parse fields in the message
        if msg_type == TYPE_LOGIN:
            enc_sessionkey = b64decode(msg_dict['enc_sessionkey'].encode('utf-8'))
            sessionkey = decrypt_sessionkey(enc_sessionkey)
            msg_length += len(enc_sessionkey)
            # failure to decrypt session key returns in NULL response code
            if (not sessionkey):
                sessionkey = generate_sessionkey()
                return sessionkey, BAD_AUTH_AND_DEC, None

        header_dict = msg_dict['header']
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
def decrypt_sessionkey(enc_sessionkey):
    try:
        keypair = load_keypair()
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

#checks path validity
def fix_path(directory, username):
    real_path = os.path.realpath(directory)
    sub_dir = real_path.split('/')
    fixed_path = f''
    for i in range(sub_dir.index(username), len(sub_dir)-1):
        fixed_path += sub_dir[i] + '/'
    fixed_path += sub_dir[len(sub_dir)-1]
    return fixed_path

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

'''
================================== MAIN CODE ===================================
'''
'''
netif = network_interface(NET_PATH, OWN_ADDR)

# set server folder as root directory
print('Server connected...')
while True:
    print('entered loop')
    status, msg = receive_client_message() # receive client login message
    print(msg)

    if status:
        if not LOGGED_IN:
            SESSION_KEY, response_code, payload = process_message(TYPE_LOGIN, msg)

            if response_code == SUCCESS:
                # verify credentials
                username, user_addr = verify_credentials(payload)
                if user_addr:
                    LOGGED_IN = True
                    CURRENT_DIR += username
                    USERNAME = username
                    print(CURRENT_DIR)

                else:
                    response_code = BAD_CREDENTIALS

            send_response(CLIENT_ADDR, TYPE_LOGIN, SESSION_KEY, response_code.encode('utf-8'))
            if user_addr:
                CLIENT_ADDR = user_addr

        else:
            SESSION_KEY, response_code, payload = process_message(TYPE_COMMAND, msg, SESSION_KEY)

            if response_code == SUCCESS:
                command_arguments = payload.decode('utf-8').split()
                command = ''
                response = BAD_COMMAND

                if len(command_arguments) > 0:
                    command = command_arguments[0]

                if command == 'MKD':
                    if command_arguments[1] != '-n':
                        print('An incorrect flag was used. Please use the correct flag.')
                    else:
                        foldername = f"{CURRENT_DIR}/{command_arguments[2]}"
                        try:
                            os.mkdir(foldername)
                        except OSError:
                            print(f'The folder \"{foldername}\" could not be created.')
                        else:
                            response = SUCCESS
                            print(f'The folder \"{foldername}\" has been created.')

                elif command == 'RMD':
                    if command_arguments[1] != '-n':
                        print('An incorrect flag was used. Please use the correct flag.')
                    else:
                        foldername = f"{CURRENT_DIR}/{command_arguments[2]}"
                        try:
                            os.rmdir(foldername)
                        except OSError:
                            print(f'The folder \"{foldername}\" could not be removed.')
                        else:
                            response = SUCCESS
                            print(f'The folder \"{foldername}\" has been removed.')

                elif command == 'GWD':
                    try:
                        foldername = os.path.basename(CURRENT_DIR)
                    except OSError:
                        print('The current folder could not be identified.')
                    else:
                        response = SUCCESS + foldername
                        print(f'The current folder is \"{foldername}\".')

                elif command == 'CWD':
                    if command_arguments[1] != '-p':
                        print('An incorrect flag was used. Please use the correct flag.')
                    else:
                        foldername = command_arguments[2]
                        temp_dir = f'{CURRENT_DIR}/{foldername}'
                        try:
                            if os.path.exists(temp_dir):
                                CURRENT_DIR = temp_dir
                                real_path = os.path.realpath(CURRENT_DIR)

                                response = SUCCESS
                                print(f'The current folder is now \"{foldername}\".')
                            else:
                                print(f'The current folder \"{foldername}\" could not be changed via the given path.')
                        except OSError:
                            print(f'The current folder \"{foldername}\" could not be changed via the given path.')

                elif command == 'LST':
                    try:
                        items = os.listdir(CURRENT_DIR)
                    except OSError:
                        print(f'Failed to retrieve the list of items.' )
                    else:
                        response = SUCCESS
                        items_list = ''
                        print(CURRENT_DIR)
                        print(list)
                        for item in items:
                            items_list += item + '\n'
                        list_bytes = bytes(items_list, 'utf-8')
                        response += list_bytes
                        print(f'Successfully sent the list of items in {CURRENT_DIR} to client')

                elif command == 'UPL':
                    if command_arguments[1] != '-f':
                        print('An incorrect flag was used. Please use the correct flag.')
                    else:
                        filepath = command_arguments[2]
                        try:
                            shutil.copyfile(filepath, CURRENT_DIR)
                        except OSError:
                            print(f'The file from \"{filepath}\" could not be uploaded')
                        else:
                            response = SUCCESS
                            print(f'The file from \"{filepath}\" has been uploaded.')

                elif command == 'DNL':
                    if command_arguments[1] != '-f' or command_arguments[3] != '-d':
                        print('An incorrect flag was used. Please use the correct flag.')
                    else:
                        filename = command_arguments[2]
                        dstpath = command_arguments[4]
                        try:
                            shutil.copyfile(CURRENT_DIR + filename, dstpath)
                        except OSError:
                            print(f'The file \"{filename}\" from \"{dstpath}\" could not be downloaded.')
                        else:
                            response = SUCCESS
                            print(f'The file \"{filename}\" from \"{dstpath}\" has been downloaded.')


                elif command == 'RMF':
                    if command_arguments[1] != '-f':
                        print('An incorrect flag was used. Please use the correct flag.')
                    else:
                        filename = command_arguments[2]
                        filepath = CURRENT_DIR + filename
                        try:
                            os.remove(filepath)
                        except OSError:
                            print(f'The file \"{filename}\" could not be removed.')
                        else:
                            response = SUCCESS
                            print(f'There file \"{filename}\" has been removed.')

                print(CLIENT_ADDR)
                send_response(CLIENT_ADDR, TYPE_COMMAND, SESSION_KEY, response.encode('utf-8'))


''' # TESTING
path = '/mnt/c/Users/winst/github/Leventransfer/server/levente12/hello'
print(os.path.realpath(path))
print(fix_path(path, 'levente12'))
# '''
