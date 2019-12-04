from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from netsim.netinterface import network_interface

NET_PATH = './netsim/S'
OWN_ADDR = 'S'

netif = network_interface(NET_PATH, OWN_ADDR)
print('Main loop started...')
while True:
# Calling receive_msg() in non-blocking mode ... 
#	status, msg = netif.receive_msg(blocking=False)    
#	if status: print(msg)      # if status is True, then a message was returned in msg
#	else: time.sleep(2)        # otherwise msg is empty

# Calling receive_msg() in blocking mode ...
	status, msg = netif.receive_msg(blocking=True)      # when returns, status is True and msg contains a message 
	print(msg.decode('utf-8'))