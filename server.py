from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
import sys, getopt, getpass
from Crypto.Hash import SHA256
from Crypto.Cipher import PKCS1_OAEP
import time
from netsim.netinterface import network_interface

NET_PATH = './netsim/'
OWN_ADDR = 'S'

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

def parse_message(msg):
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
        symkey = decrypted_message[4+username_length+password_length+timestamp_length:]
        return username, password, timestamp, symkey

netif = network_interface(NET_PATH, OWN_ADDR)
print('Server loop started...')
while True:
# Calling receive_msg() in non-blocking mode ... 
#	status, msg = netif.receive_msg(blocking=False)    
#	if status: print(msg)      # if status is True, then a message was returned in msg
#	else: time.sleep(2)        # otherwise msg is empty

# Calling receive_msg() in blocking mode ...
    status, msg = netif.receive_msg(blocking=False)     # when returns, status is True and msg contains a message 
    if status:
        username, password, timestamp, symkey = parse_message(msg)
    else: 
        time.sleep(2)
        



