import sys, getopt, getpass, os, time, shutil, json
# import client
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto.Hash import SHA256, HMAC
from Crypto.Cipher import PKCS1_OAEP
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

# network variables
NET_PATH = './netsim/'
OWN_ADDR = 'S'
CLIENT_ADDR = ''
NUMBER_OF_USERS = 4

# crypto variables
sessionkey = ''


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

        keypair = load_keypair()
        signer = pss.new(keypair)
        hashfn = SHA256.new()
        hashfn.update(enc_payload)
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
# parse client message
def parse_message(msg):
    try:
        msg_dict = json.loads(msg)
        json_k = [ 'nonce', 'header', 'ciphertext', 'tag' ]
        jv = {k:b64decode(b64[k]) for k in json_k}

        cipher = AES.new(key, AES.MODE_EAX, nonce=jv['nonce'])
        cipher.update(jv['header'])
        plaintext = cipher.decrypt_and_verify(jv['ciphertext'], jv['tag'])
        print("The message was: " + plaintext)
    except (ValueError, KeyError):
        print("Incorrect decryption")


# get session key
def decrypt_sessionkey(enc_sessionkey):
    try:
        keypair = load_keypair()
        RSAcipher = PKCS1_OAEP.new(keypair)
        return RSAcipher.decrypt(enc_sessionkey)
    except (ValueError, TypeError):
        return generate_sessionkey # if failure, generate random sessionkey


def parse_login_message(msg):
    keypair = load_keypair()
    RSAcipher = PKCS1_OAEP.new(keypair)
    type_of_message = msg[:1]
    version = msg[1:2]
    length = msg[2:4]
    payload = msg[4:]
    decrypted_message = RSAcipher.decrypt(payload)
    if length == len(decrypted_message):
        username_length = decrypted_message[:2]
        password_length = decrypted_message[2:4]
        timestamp_length = 20
        username = decrypted_message[4:username_length]
        password = decrypted_message[4+username_length:4+username_length+password_length]
        timestamp = decrypted_message[4+username_length+password_length:4+username_length+password_length+timestamp_length]
        symkey = decrypted_message[4+username_length+password_length+timestamp_length:4+username_length+password_length+timestamp_length+AES.block_size]
        iv = decrypted_message[-AES.block_size:]
        return username, password, timestamp, symkey, iv


def parse_command(msg):
    header = msg[:5]
    type_of_message = header[:1]
    version = header[1:2]
    length = header[2:4]
    iv = msg[5:5+AES.block_size]
    payload = msg[5+AES.block_size: 5+AES.block_size + length]
    mac = msg[-AES.block_size:]
    return type_of_message, version, length, iv, payload, mac


'''
================================== MAIN CODE ===================================
'''
'''
logged_in = False
netif = network_interface(NET_PATH, OWN_ADDR)
CURRENT_DIR = NET_PATH
print('Server loop started...')

while True:
# Calling receive_msg() in non-blocking mode ...
#	status, msg = netif.receive_msg(blocking=False)
#	if status: print(msg)      # if status is True, then a message was returned in msg
#	else: time.sleep(2)        # otherwise msg is empty

# Calling receive_msg() in blocking mode ...
    if not logged_in:
        status, msg = netif.receive_msg(blocking=True)     # when returns, status is True and msg contains a message
        if status:
            username, password, timestamp, sessionkey, iv = parse_login_message(msg)
            with open('donotopen.json', 'rb') as f:
                username_label_length = len(b'Username Hash')
                password_label_length = len(b'Password Hash')
                credentials = f.read()
                for i in range(NUMBER_OF_USERS):
                    stored_username = credentials[(i+1) * (username_label_length):(i+1) * (username_label_length+32)]
                    stored_password = credentials[(i+1) * (username_label_length+32+password_label_length) : (i+1) * (username_label_length+32+password_label_length+32)]
                    if username == stored_username and password == stored_password:
                        logged_in = True
                        CLIENT_ADDR = username
                        CURRENT_DIR += CLIENT_ADDR+'/IN/'
                send_success_or_failure(logged_in, symkey, iv)

    else:
        status, msg = netif.receive_msg(blocking=True)
        type_of_message, version, length, iv, payload, mac = parse_command(msg)
        response_code = b'500'

        if verify_mac(mac, payload):
            plaintext = decrypt_client_payload(payload, iv)
            command_arguments = plaintext.split()
            command = command_arguments[0]

            if command == 'MKD':
                name_of_folder = f"${CURRENT_DIR}${command_arguments[2]}"
                try:
                    os.mkdir(name_of_folder)
                except OSError:
                    print("Creation of the directory %s failed" % name_of_folder)
                else:
                    response_code = b"200"
                    print("Successfully created the directory %s " % name_of_folder)

                encrypted_message = generate_response_message(iv, response_code)
                netif.send_msg(CLIENT_ADDR, encrypted_message)

            elif command == 'RMD':
                name_of_folder = f"${CURRENT_DIR}${command_arguments[2]}"
                try:
                    os.rmdir(name_of_folder)
                except OSError:
                    print("Deletion of the directory %s failed" % name_of_folder)
                else:
                    response_code = b"200"
                    print("Successfully deleted the directory %s " % name_of_folder)

                encrypted_message = generate_response_message(iv, response_code)
                netif.send_msg(CLIENT_ADDR, encrypted_message)

            elif command == 'GWD':
                try:
                    current_folder = os.path.basename(CURRENT_DIR)
                except OSError:
                    print("The current folder is %s" % current_folder)
                else:
                    response_code = b"200"
                    print('There was an error in getting the name of the current folder.')

                encrypted_message = generate_response_message(iv, response_code + current_folder)
                netif.send_msg(CLIENT_ADDR, encrypted_message)

            elif command == 'CWD':
                path_of_folder = command_arguments[2]
                try:
                    os.chdir(path_of_folder)
                except OSError:
                    print("The current folder is now %s" % current_folder)
                else:
                    response_code = b"200"
                    print('That path is invalid or that folder could not be found.')

                encrypted_message = generate_response_message(iv, response_code)
                netif.send_msg(CLIENT_ADDR, encrypted_message)

            elif command == 'LST':
                try:
                    items = os.listdir(CURRENT_DIR)
                except OSError:
                    print("Getting list of items from %s failed" % CURRENT_DIR)
                else:
                    response_code = b'200'
                    list_of_items = ''
                    for item in items:
                        list_of_items += item + '\n'
                    list_bytes = bytes(list_of_items, 'utf-8')
                    print('Successfully sent list of items from %s to client' % CURRENT_DIR)

                encrypted_message = generate_response_message(iv, response_code+list_bytes)
                netif.send_msg(CLIENT_ADDR, encrypted_message)


            elif command == 'UPL':
                path_of_file = command_arguments[2]
                try:
                    shutil.copyfile(path_of_file, CURRENT_DIR)
                except OSError:
                    print("Uploading of the file from %s failed" % path_of_file)
                else:
                    response_code = b"200"
                    print("Successfully uploaded the file from %s " % path_of_file)

                encrypted_message = generate_response_message(iv, response_code)
                netif.send_msg(CLIENT_ADDR, encrypted_message)

            elif command == 'DNL':
                name_of_file = command_arguments[2]
                destination_path = command_arguments[4]
                try:
                    shutil.copyfile(CURRENT_DIR+name_of_file, destination_path)
                except OSError:
                    print("Downloading of the file %s failed" % name_of_file)
                else:
                    response_code = b"200"
                    print("Successfully downloaded the file %s " % name_of_file)

                encrypted_message = generate_response_message(iv, response_code)
                netif.send_msg(CLIENT_ADDR, encrypted_message)

            elif command == 'RMF':
                name_of_file = command_arguments[2]
                path_to_file = CURRENT_DIR+name_of_file
                try:
                    os.remove(path_to_file)
                except OSError:
                    print("Removal of the file %s failed" % name_of_file)
                else:
                    response_code = b"200"
                    print("Successfully removed the file %s " % name_of_folder)

                encrypted_message = generate_response_message(iv, response_code)
                netif.send_msg(CLIENT_ADDR, encrypted_message)
'''
# sessionkey = client.generate_sessionkey()
# payload = client.generate_login_payload("bob", "abc")
# message = client.generate_message(TYPE_LOGIN, sessionkey, payload)
