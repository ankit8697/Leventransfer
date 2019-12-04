import sys, getopt, getpass
from base64 import b64encode, b64decode
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Signature import pss
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Util import Padding
from Crypto import Random

print('hello')
def save_publickey(pubkey, pubkeyfile):
    with open(pubkeyfile, 'wb') as f:
        f.write(pubkey.export_key(format='PEM'))

def load_publickey(pubkeyfile):
    with open(pubkeyfile, 'rb') as f:
        pubkeystr = f.read()
    try:
        return RSA.import_key(pubkeystr)
    except ValueError:
        print('Error: Cannot import public key from file ' + pubkeyfile)
        sys.exit(1)

def save_keypair(keypair, privkeyfile):
    #The key pair contains the private key, so we want to save it protected with a passphrase
    #We use the getpass() function of the getpass class to input the passphrase from the user
    passphrase = getpass.getpass('Enter a passphrase to protect the saved private key: ')

    with open(privkeyfile, 'wb') as f:
        f.write(keypair.export_key(format='PEM', passphrase = passphrase))


def load_keypair(privkeyfile):
    passphrase = getpass.getpass('Enter a passphrase to protect the saved private key')

    with open(privkeyfile, 'rb') as f:
        keypairstr = f.read()
    try:
        return RSA.import_key(keypairstr, passphrase = passphrase)

    except ValueError:
        print('Error: Cannot import private key from file ' + privkeyfile)
        sys.exit(1)

def newline(s):
    return s + b'\n'

# ----------------------------------
# processing command line parameters
# ----------------------------------

operation = ''
pubkeyfile = ''
privkeyfile = ''
inputfile = ''
outputfile = ''
sign = False

try:
    opts, args = getopt.getopt(sys.argv[1:], 'hkedp:s:i:o:', ['help', 'kpg', 'enc', 'dec', 'pubkeyfile=', 'privkeyfile=', 'inputfile=', 'outputfile='])
except getopt.GetoptError:
    print('Usage:')
    print('  - RSA key pair generation:')
    print('    hybrid.py -k -p <pubkeyfile> -s <privkeyfile>')
    print('  - encryption with optional signature generation:')
    print('    hybrid.py -e -p <pubkeyfile> [-s <privkeyfile>] -i <inputfile> -o <outputfile>')
    print('  - decryption with optional signature verification:')
    print('    hybrid.py -d -s <privkeyfile> [-p <pubkeyfile>] -i <inputfile> -o <outputfile>')
    sys.exit(1)

for opt, arg in opts:
    if opt in ('-h', '--help'):
        print('Usage:')
        print('  - RSA key pair generation:')
        print('    hybrid.py -k -p <pubkeyfile> -s <privkeyfile>')
        print('  - encryption with optional signature generation:')
        print('    hybrid.py -e -p <pubkeyfile> [-s <privkeyfile>] -i <inputfile> -o <outputfile>')
        print('  - decryption with optional signature verification:')
        print('    hybrid.py -d -s <privkeyfile> [-p <pubkeyfile>] -i <inputfile> -o <outputfile>')
        sys.exit(0)
    elif opt in ('-k', '--kpg'):
        operation = 'kpg'
    elif opt in ('-e', '--enc'):
        operation = 'enc'
    elif opt in ('-d', '--dec'):
        operation = 'dec'
    elif opt in ('-p', '--pubkeyfile'):
        pubkeyfile = arg
    elif opt in ('-s', '--privkeyfile'):
        privkeyfile = arg
    elif opt in ('-i', '--inputfile'):
        inputfile = arg
    elif opt in ('-o', '--outputfile'):
        outputfile = arg

#Handling missing or wrongly given parameters...

if operation not in ('kpg', 'enc', 'dec'):
    print('Error: Operation must be -k (for key pair generation) or -e (for encryption) or -d (for decryption).')
    sys.exit(1)

#Handle a missing public key file...
#Print an error if pubkeyfile is empty and the operation is 'enc' or 'kpg'
if (not pubkeyfile) and (operation == 'enc' or operation == 'kpg'):
    print('Error: Name of the public key file is missing.')
    sys.exit(1)

if operation in ('dec', 'kpg') and (not privkeyfile):
    print('Error: Name of the private key file is missing.')
    sys.exit(1)

if operation in ('enc', 'dec') and (not inputfile):
    print('Error: Name of input file is missing.')
    sys.exit(1)

if operation in ('enc', 'dec') and (not outputfile):
    print('Error: Name of output file is missing.')
    sys.exit(1)

if (operation == 'enc') and privkeyfile:
    sign = True

# -------------------
# key pair generation
# -------------------

if operation == 'kpg':
    print('Generating a new 2048-bit RSA key pair...')
    keypair = RSA.generate(2048)

    save_publickey(keypair.publickey(), pubkeyfile)

    #Save the entire key pair in privkeyfile
    save_keypair(keypair, privkeyfile)
    print('Done.')

# ----------
# encryption
# ----------

elif operation == 'enc':
    print('Encrypting...')

    pubkey = load_publickey(pubkeyfile)
    RSAcipher = PKCS1_OAEP.new(pubkey)

    #Read the plaintext from the input file
    with open(inputfile, 'rb') as f:
        plaintext = f.read()
    padded_plaintext = Padding.pad(plaintext, AES.block_size)

    symkey = Random.get_random_bytes(32) # we need a 256-bit (32-byte) AES key
    iv = Random.get_random_bytes(AES.block_size)
    AEScipher = AES.new(key, AES.MODE_CBC, iv)

    ciphertext = cipher.encrypt(plaintext)

    encsymkey = RSAcipher.encrypt(symkey)

    #Compute signature if needed
    if sign:
        keypair = load_keypair(privkeyfile)
        signer = pss.new(keypair)
        hashfn = SHA256.new()
        hashfn.update(encsymkey+iv+ciphertext)
        signature = signer.sign(hashfn)

    #Write out the encrypted AES key, the IV, the ciphertext,
    #and the signature in base64 encoding
    with open(outputfile, 'wb') as f:
        f.write(newline(b'--- ENCRYPTED AES KEY ---'))
        f.write(newline(b64encode(encsymkey)))
        f.write(newline(b'--- IV FOR CBC MODE ---'))
        f.write(newline(b64encode(iv)))
        f.write(newline(b'--- CIPHERTEXT ---'))
        f.write(newline(b64encode(ciphertext)))
        if sign:
            f.write(newline(b'--- SIGNATURE ---'))
            f.write(newline(b64encode(signature)))

    print('Done.')

# ----------
# decryption
# ----------

elif operation == 'dec':
    print('Decrypting...')

    #Read and parse the input...
    encsymkey = b''
    iv = b''
    ciphertext = b''

    with open(inputfile, 'rb') as f:
        sep = f.readline()
        while sep:
            data = f.readline()
            data = data[:-1]   # removing \n from the end
            sep = sep[:-1]     # removing \n from the end

            if sep == b'--- ENCRYPTED AES KEY ---':
                encsymkey = b64decode(data)
            elif sep == b'--- IV FOR CBC MODE ---':
                iv = b64decode(data)
            elif sep == b'--- CIPHERTEXT ---':
                ciphertext = b64decode(data)
            elif sep == b'--- SIGNATURE ---':
                signature = b64decode(data)
                sign = True

            sep = f.readline()

    if (not encsymkey) or (not iv) or (not ciphertext):
        print('Error: Could not parse content of input file ' + inputfile)
        sys.exit(1)

    if sign and (not pubkeyfile):
        print('Error: Public key file is missing for  ' + inputfile)
        sys.exit(1)

    #Verify signature if needed...
    if sign:
        if not pubkeyfile:
            print('Error: Public key file is missing, signature cannot be verified.')
        else:
            try:
                pubkey =
                pubkey = RSA.import_key(pubkeystr)
                verifier = PKCS1_PSS.new(pubkey)
                h = SHA256.new()

            except (ValueError, TypeError):
                yn = input('Do you want to continue nevertheless (y/n)? ')
                if yn != 'y':
                    sys.exit(1)

    #Write out the plaintext into the output file
    with open(outputfile, 'wb') as f:
        f.write(plaintext)

    print('Done.')
