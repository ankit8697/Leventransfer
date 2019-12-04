import sys, getopt, getpass
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES

username = ''
password = ''
pubkeyfile = 'test_pubkey.pem'

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

def message_header():

hashfn = SHA256.new()

hashfn.update(username)
hashfn.update(password)

hashed_user = hashfn.digest()

pubkey = load_publickey(pubkeyfile)
RSAcipher = PKCS1_OAEP.new(pubkey)

symkey = Random.get_random_bytes(32) # we need a 256-bit (32-byte) AES key
sessionkey = Random.get_random_bytes(32)
iv = Random.get_random_bytes(AES.block_size)
AEScipher = AES.new(key, AES.MODE_CBC, iv)

encsymkey = RSAcipher.encrypt(symkey)
