from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Util import Counter
import sys, getopt, getpass
from Crypto.Hash import SHA256
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pss
import time
from netsim.netinterface import network_interface

NET_PATH = './netsim/'
OWN_ADDR = 'S'
CLIENT_ADDR = ''
symkey = ''

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
    
logged_in = False
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
            username, password, timestamp, symkey, iv = parse_login_message(msg)
            with open('donotopen.json', 'rb') as f:
                username_label_length = len(b'Username Hash')
                password_label_length = len(b'Password Hash')
                credentials = f.read()
                for i in range(4):
                    stored_username = credentials[(i+1) * (username_label_length):(i+1) * (username_label_length+32)]
                    stored_password = credentials[(i+1) * (username_label_length+32+password_label_length) : (i+1) * (username_label_length+32+password_label_length+32)]
                    if username == stored_username and password == stored_password:
                        logged_in = True
                        CLIENT_ADDR = username
                send_success_or_failure(logged_in, symkey, iv)
    
    else:
        # We are now ready to accept commands
        pass