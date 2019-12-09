import sys, getopt, getpass, json
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES
from Crypto.Hash import SHA256, HMAC
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
LENGTH_ENC_SK = 256
LENGTH_AUTHTAG = 16
SUCCESS = '200'          # successful operation (login or command)
BAD_COMMAND = '500'      # failure to execute command
BAD_MSG_LENGTH = '501'   # invalid message length in header
BAD_TIMESTAMP = '502'    # invalid timestamp (expired or in the future)
BAD_AUTH_AND_DEC = '503' # failure to verify authtag and decrypt
BAD_CREDENTIALS = '504'  # invalid credentials (username, hash of password)
BAD_SIGNATURE = '505'
SERVER_BUSY = '506'    # invalid signature
TIMESTAMP_WINDOW = 5     # window for timestamp verification
RED = '\033[91m'
GREEN = '\033[92m'
ORANGE = '\033[93m'
BLUE = '\033[94m'

# network constants/variables
NET_PATH = './network/'
OWN_ADDR = 'L'
SERVER_ADDR = 'S'
LOGGED_IN = False

# crypto constants/variables
sessionkey = ''
username = ''
password = ''


'''
================================== FUNCTIONS ===================================
'''
### load key functions
def load_publickey():
    pubkeyfile = 'client/test_pubkey.pem'
    with open(pubkeyfile, 'rb') as f:
        pubkeystr = f.read()
    try:
        return RSA.import_key(pubkeystr)
    except ValueError:
        print('Error: Cannot import public key from file ' + pubkeyfile)
        sys.exit(1)


### send and receive message functions
# send login message
def send_login_message(username, password, sessionkey):
    payload = generate_login_payload(username, password)
    message = generate_message(TYPE_LOGIN, sessionkey, payload)
    netif.send_msg(SERVER_ADDR, message.encode('utf-8'))


# send command message
def send_command_message(command, sessionkey):
    payload = generate_command_payload(command)
    message = generate_message(TYPE_COMMAND, sessionkey, payload)
    netif.send_msg(SERVER_ADDR, message.encode('utf-8'))
    # print("Sent command message")

# receive server message
def receive_server_message():
    return netif.receive_msg(blocking=True)


### generate message functions
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
        pubkey = load_publickey()
        RSAcipher = PKCS1_OAEP.new(pubkey)
        enc_sessionkey = RSAcipher.encrypt(sessionkey)

        AE.update(header + enc_sessionkey)
        enc_payload, authtag = AE.encrypt_and_digest(payload)

        msg_k = ['header', 'enc_sessionkey', 'enc_payload', 'authtag']
        msg_v = [header_dict] + [b64encode(x).decode('utf-8') for x in [enc_sessionkey, enc_payload, authtag]]

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
    type = int.from_bytes(header[2:3], byteorder='big')
    length = int.from_bytes(header[3:5], byteorder='big')
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
    return len(username).to_bytes(1, byteorder='big') + \
           (username + password).encode("utf-8")


# create the command message payload
def generate_command_payload(command):
    return command.encode("utf-8")


### process message functions
# process server message to get response code, payload
def process_message(msg_type, msg, sessionkey):
    try:
        msg_dict = json.loads(msg.decode('utf-8'))
        msg_length = 0

        # parse fields in the message
        header_dict = msg_dict['header']
        digit_1 = int(header_dict['version'])
        digit_2 = int(header_dict['version'] * 10) % 10
        header_version = digit_1.to_bytes(1, byteorder='big') + \
                         digit_2.to_bytes(1, byteorder='big')
        header_type = header_dict['type'].to_bytes(1, byteorder='big')
        header_length = header_dict['length'].to_bytes(2, byteorder='big')
        header_timestamp = header_dict['timestamp'].encode('utf-8')
        header_random = b64decode(header_dict['random'].encode('utf-8'))
        header_nonce = header_timestamp + header_random
        header = header_version + header_type + header_length + header_nonce
        enc_payload = b64decode(msg_dict['enc_payload'].encode('utf-8'))
        authtag = b64decode(msg_dict['authtag'].encode('utf-8'))
        msg_length += len(header) + len(enc_payload) + len(authtag)

        # verify signature for login response
        if msg_type == TYPE_LOGIN:
            signature = b64decode(msg_dict['signature'].encode('utf-8'))
            signed_msg = header + enc_payload + authtag
            msg_length += len(signature)
            if not valid_signature(signature, signed_msg):
                return BAD_SIGNATURE, None

        # verify header length
        if msg_length != header_dict['length']:
            print(msg_length) #
            print(header_dict['length']) #
            print('Server response error: invalid header length.')
            return BAD_MSG_LENGTH, None

        # verify timestamp
        if not valid_timestamp(header_dict['timestamp']):
            print('Server response error: invalid timestamp.')
            return BAD_TIMESTAMP, None

        # authenticate and decrypt payload
        AE = AES.new(sessionkey, AES.MODE_GCM, nonce=header_nonce)
        AE.update(header)

        payload = AE.decrypt_and_verify(enc_payload, authtag)
        return SUCCESS, payload

    except (ValueError, KeyError):
        print('Server response error: the response may be compromised.')
        return BAD_AUTH_AND_DEC, None


# verify signature
def valid_signature(signature, signed_msg):
    pubkey = load_publickey()
    h = SHA256.new(signed_msg)

    try:
        verifier = pss.new(pubkey)
        verifier.verify(h, signature)
    except (ValueError, TypeError):
        print('Server response error: unable to authenticate server.')
        return False
    else:
        return True


# verify timestamp_length
def valid_timestamp(timestamp):
    current_timestamp = int(generate_timestamp().decode('utf-8'))
    delta_t = current_timestamp - int(timestamp)
    tolerance = TIMESTAMP_WINDOW * 1e3 # in milliseconds
    return (delta_t >= 0) and (delta_t < tolerance)


'''
================================== MAIN CODE ===================================
'''
# '''
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
        sys.exit(1)
    elif opt in ('-u', '--username'):
        username = arg
    elif opt in ('-p', '--password'):
        password = arg


# Login Protocol (send messages as 'L')
netif = network_interface(NET_PATH, OWN_ADDR)
while True:
    SESSION_KEY = generate_sessionkey()
    send_login_message(username, password, SESSION_KEY)
    status, msg = receive_server_message()

    if status:
        server_code, payload = process_message(TYPE_LOGIN, msg, SESSION_KEY)

        if not server_code == SUCCESS: # server message is invalid
            print('Login unsuccessful - server response cannot be read')
        else:
            # process result of login
            login_code = payload.decode('utf-8')

            if login_code in [BAD_MSG_LENGTH, BAD_TIMESTAMP, BAD_AUTH_AND_DEC]:
                print('Login unsuccessful - login message cannot be read')
            elif login_code == BAD_CREDENTIALS:
                print('Login unsuccessful - username or password is incorrect')
            elif login_code == SERVER_BUSY:
                print('Login unsuccessful - someone else is logged into the server')
            elif login_code == SUCCESS:
                LOGGED_IN = True
                with open('client/addr_mapping.json', 'r') as f:
                    addr_dict = json.load(f)
                    OWN_ADDR = addr_dict[username]
                print('Login successful :)')
        break


# Command Protocol (send messages as logged-in user)
netif = network_interface(NET_PATH, OWN_ADDR)
while LOGGED_IN:
    # We are now ready to send commands
    color = RED
    command = input(f'{color}[{username}]\033[0m Enter your command: ')

    send_command_message(command, SESSION_KEY)
    status, msg = receive_server_message()

    if status:
        server_code, payload = process_message(TYPE_COMMAND, msg, SESSION_KEY)

        if server_code == SUCCESS:
            response = payload.decode('utf-8')
            command_code = response[:3]

            # get any attached data
            if len(response) > 3:
                data = response[3:]

            # output result of executing command
            if command[:3] == 'MKD':
                foldername = command[7:]
                if command_code == SUCCESS:
                    print(f'The folder \"{foldername}\" has been created.')
                else:
                    print(f'The folder \"{foldername}\" could not be created.')

            elif command[:3] == 'RMD':
                foldername = command[7:]
                if command_code == SUCCESS:
                    print(f'The folder \"{foldername}\" has been removed.')
                else:
                    print(f'The folder \"{foldername}\" could not be removed.')

            elif command[:3] == 'GWD':
                foldername = data
                if command_code == SUCCESS:
                    print(f'The current folder is \"{foldername}\".')
                else:
                    print('The current folder could not be identified.')

            elif command[:3] == 'CWD':
                foldername = command[7:]
                if command_code == SUCCESS:
                    print(f'The current folder is now \"{foldername}\".')
                else:
                    print(f'The current folder \"{foldername}\" could not be changed via the given path.')

            elif command[:3] == 'LST':
                if command_code == SUCCESS:
                    print('Current folder:')
                    for filename in data.split('\n'):
                        print(f'\"{filename}\"')
                else:
                    print('The items in the current directory could not be listed.')

            elif command[:3] == 'UPL':
                filepath = command[7:]
                if command_code == SUCCESS:
                    print(f'The file from \"{filepath}\" has been uploaded.')
                else:
                    print(f'The file from \"{filepath}\" could not be uploaded')

            elif command[:3] == 'DNL':
                values = command.split(' ')
                filename = values[2]
                dstpath = values[4]
                if command_code == SUCCESS:
                    print(f'The file \"{filename}\" from \"{dstpath}\" has been downloaded.')
                else:
                    print(f'The file \"{filename}\" from \"{dstpath}\" could not be downloaded.')

            elif command[:3] == 'RMF':
                filename = command[7:]
                if command_code == SUCCESS:
                    print(f'The file \"{filename}\" has been removed.')
                else:
                    print(f'There file \"{filename}\" could not be removed.')

            else:
                print('Usage: ')
                print('  > Make directory')
                print('        MKD -n <foldername>')
                print('  > Remove directory')
                print('        RMD -n <foldername>')
                print('  > Get directory:')
                print('        GWD')
                print('  > Change directory')
                print('        CWD -p <folderpath>')
                print('  > List directory')
                print('        LST')
                print('  > Upload')
                print('        UPL -f <filepath>')
                print('  > Download')
                print('        DNL -f <filename> -d <targetpath>')
                print('  > Remove file')
                print('        RMF -f <filename>')

        else:
            print('The server response could not be read.')

        if input(f'{color}[{username}]\033[0m Continue? (y/n): ') == 'n':
            payload = 'EXT'
            send_command_message(payload, SESSION_KEY)
            break
'''
# sessionkey = generate_sessionkey()
# payload = generate_login_payload("bob", "abc")
# message = generate_message(TYPE_LOGIN, sessionkey, payload)
# print(message)
# '''
