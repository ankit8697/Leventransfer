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
CURRENT_DIR = ''
NUMBER_OF_USERS = 4
LOGGED_IN = False

# crypto constants/variables
SESSION_KEY = ''


'''
================================== FUNCTIONS ===================================
'''
### load key functions

def load_keypair():
    privkeyfile = 'test_keypair.pem'
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
    login_response = generate_message(msg_type, sessionkey, response)
    netif.send_msg(dst, login_response.encode('utf-8'))
    print("Sent login response")


# receive client message
def receive_client_message():
    print("Received client message")
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
            if (not sessionkey): return None, BAD_AUTH_AND_DEC, payload

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
        return None # if failure, return NULL


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
        password = credentials[length_username + 1:]

        # password = b'ilovemath'

        hashfn = SHA256.new()
        hashfn.update(password)
        hash_password = hashfn.digest()
        hash_password = b64encode(hash_password).decode('utf-8')

        with open('users.json', 'r') as f:
            credentials_dict = json.load(f)

            if credentials_dict[username.decode('utf-8')] == hash_password:
                with open('addr_mapping.json', 'r') as g:
                    addr_dict = json.load(g)
                    print("Username:" + username.decode('utf-8'))
                    return addr_dict[username.decode('utf-8')]

    except Exception as e:
        print(e)
        print(e)
        print("Login message error: cannot verify user credentials.")
        return None

'''
================================== MAIN CODE ===================================
'''
# '''
netif = network_interface(NET_PATH, OWN_ADDR)
CURRENT_DIR = NET_PATH
print('Server connected...')
print('update')
while True:
# Calling receive_msg() in non-blocking mode ...
#	status, msg = netif.receive_msg(blocking=False)
#	if status: print(msg)      # if status is True, then a message was returned in msg
#	else: time.sleep(2)        # otherwise msg is empty

# Calling receive_msg() in blocking mode ...
    print('entered loop')
    status,msg = receive_client_message() # receive client login message

    if status:
        if not LOGGED_IN:
            SESSION_KEY, response_code, payload = process_message(TYPE_LOGIN, msg)

            if response_code == SUCCESS:
                # verify credentials
                dirname = verify_credentials(payload)
                if dirname:
                    LOGGED_IN = True
                    CURRENT_DIR += CLIENT_ADDR + '/IN/'
                else:
                    response_code = BAD_CREDENTIALS

            send_response(CLIENT_ADDR, TYPE_LOGIN, SESSION_KEY, response_code.encode('utf-8'))
            CLIENT_ADDR = dirname

        else:
            SESSION_KEY, response_code, payload = process_message(TYPE_COMMAND, msg, SESSION_KEY)

            if response_code == SUCCESS:
                command_arguments = payload.decode('utf-8').split()
                command = command_arguments[0]
                response = ''

                if command == 'MKD':
                    name_of_folder = f"{CURRENT_DIR}{command_arguments[2]}"
                    try:
                        os.mkdir(name_of_folder)
                    except OSError:
                        response = BAD_COMMAND
                        print("Creation of the directory $%s failed" % name_of_folder)
                    else:
                        response = SUCCESS
                        print("Successfully created the directory %s " % name_of_folder)

                elif command == 'RMD':
                    name_of_folder = f"{CURRENT_DIR}{command_arguments[2]}"
                    try:
                        os.rmdir(name_of_folder)
                    except OSError:
                        response = BAD_COMMAND
                        print("Deletion of the directory $%s failed" % name_of_folder)
                    else:
                        response = SUCCESS
                        print("Successfully deleted the directory $%s " % name_of_folder)

                    encrypted_message = generate_response_message(iv, response_code)
                    netif.send_msg(CLIENT_ADDR, encrypted_message)

                elif command == 'GWD':
                    try:
                        current_folder = os.path.basename(CURRENT_DIR)
                    except OSError:
                        response = BAD_COMMAND
                        print('There was an error in getting the name of the current folder.')
                    else:
                        response = SUCCESS + current_folder
                        print("The current folder is %s" % current_folder)

                elif command == 'CWD':
                    path_of_folder = command_arguments[2]
                    try:
                        os.chdir(path_of_folder)
                    except OSError:
                        response = BAD_COMMAND
                        print('That path is invalid or that folder could not be found.')
                    else:
                        response_code = SUCCESS
                        print("The current folder is now %s" % current_folder)

                elif command == 'LST':
                    try:
                        items = os.listdir(CURRENT_DIR)
                    except OSError:
                        response = BAD_COMMAND
                        print("Getting list of items from %s failed" % CURRENT_DIR)
                    else:
                        response = SUCCESS
                        list_of_items = ''
                        for item in items:
                            list_of_items += item + '\n'
                        list_bytes = bytes(list_of_items, 'utf-8')
                        response += list_bytes
                        print('Successfully sent list of items from %s to client' % CURRENT_DIR)

                elif command == 'UPL':
                    path_of_file = command_arguments[2]
                    try:
                        shutil.copyfile(path_of_file, CURRENT_DIR)
                    except OSError:
                        response = BAD_COMMAND
                        print("Uploading of the file from %s failed" % path_of_file)
                    else:
                        response = SUCCESS
                        print("Successfully uploaded the file from %s " % path_of_file)

                elif command == 'DNL':
                    name_of_file = command_arguments[2]
                    destination_path = command_arguments[4]
                    try:
                        shutil.copyfile(CURRENT_DIR+name_of_file, destination_path)
                    except OSError:
                        response = BAD_COMMAND
                        print("Downloading of the file %s failed" % name_of_file)
                    else:
                        response = SUCCESS
                        print("Successfully downloaded the file %s " % name_of_file)

                elif command == 'RMF':
                    name_of_file = command_arguments[2]
                    path_to_file = CURRENT_DIR+name_of_file
                    try:
                        os.remove(path_to_file)
                    except OSError:
                        response = BAD_COMMAND
                        print("Removal of the file %s failed" % name_of_file)
                    else:
                        response = SUCCESS
                        print("Successfully removed the file %s " % name_of_folder)

                send_response(CLIENT_ADDR, TYPE_COMMAND, SESSION_KEY, response.encode('utf-8'))


''' # TESTING
print(CURRENT_DIR)
sessionkey = client.generate_sessionkey()
payload = client.generate_login_payload("levente12", "ilovemath")
message = client.generate_message(TYPE_LOGIN, sessionkey, payload)
print(message)
sessionkey, code, payload = process_message(TYPE_LOGIN, message)
print(verify_credentials(payload))
# '''
