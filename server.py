from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Util import Counter
import sys, getopt, getpass
from Crypto.Hash import SHA256, HMAC
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pss
import os
import time
import shutil
from netsim.netinterface import network_interface

NET_PATH = './netsim/'
OWN_ADDR = 'S'
CLIENT_ADDR = ''
symkey = ''
NUMBER_OF_USERS = 4

netif = network_interface(NET_PATH, OWN_ADDR)

def load_keypair():
    privkeyfile = 'test_keypair.pem'
    passphrase = getpass.getpass('Enter a passphrase to protect the saved private key')

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

def send_success_or_failure(success, symkey, iv):
    message = ''
    cipher = AES.new(symkey, AES.MODE_CBC, iv=iv)
    if success:
        message = cipher.encrypt("Success")
    else:
        message = cipher.encrypt("Failure")
    keypair = load_keypair('test_keypair.pem')
    signer = pss.new(keypair)
    hashfn = SHA256.new()
    hashfn.update(message)
    signature = signer.sign(hashfn)
    payload = message + signature
    netif.send_msg(CLIENT_ADDR, payload)


def parse_command(msg):
    header = msg[:5]
    type_of_message = header[:1]
    version = header[1:2]
    length = header[2:4]
    iv = msg[5:5+AES.block_size]
    payload = msg[5+AES.block_size: 5+AES.block_size + length]
    mac = msg[-AES.block_size:]
    return type_of_message, version, length, iv, payload, mac

def verify_mac(mac, payload):
    h = HMAC.new(symkey, digestmod=SHA256)
    h.update(payload)
    try:
        h.verify(mac)
    except (ValueError) as e:
        return False
    return True

def decrypt_client_payload(msg, iv):
    cipher = AES.new(symkey, AES.MODE_CBC, iv=iv)
    plaintext = cipher.decrypt(msg)
    return plaintext

# generate message header (5 bytes)
def generate_message_header(msg_length):
    header_version = b'\x01\x00'                            # protocol version 1.0
    header_type = b'\x01'                                   # message type 0
    header_length = msg_length.to_bytes(2, byteorder='big') # message length
    return header_version + header_type + header_length

def generate_response_payload(response, iv):
    cipher = AES.new(symkey, AES.MODE_CBC, iv=iv)
    ciphertext = cipher.encrypt(response)
    return ciphertext

def generate_response_mac(payload):
    h = HMAC.new(symkey, digestmod=SHA256)
    h.update(payload)
    mac = h.digest()
    return mac

def generate_response_message(iv, response):
    header = generate_message_header(len(response))
    payload = generate_response_payload(response)
    mac = generate_response_mac(payload)
    message = header+iv+payload+mac
    return message


logged_in = False
print('Server loop started...')
CURRENT_DIR = NET_PATH
while True:
# Calling receive_msg() in non-blocking mode ...
#	status, msg = netif.receive_msg(blocking=False)
#	if status: print(msg)      # if status is True, then a message was returned in msg
#	else: time.sleep(2)        # otherwise msg is empty

# Calling receive_msg() in blocking mode ...
    if not logged_in:
        status, msg = netif.receive_msg(blocking=True)     # when returns, status is True and msg contains a message
        if status:
            username, password, timestamp, symkey, iv = parse_login_message(msg)
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
