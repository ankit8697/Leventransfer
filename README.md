# LevenTransfer
State-of-the-art file transfer crypto-system offering confidentiality, integrity protection and authentication, and replay protection. Created by Ankit Sanghi, Mark Rubakh, Winston Wang, 
Aurnov Chattopadhyay, and Snow Kang Fall 2019 under Dr. Levente Buttyán.


## Key Variables

#### Session Passphrase:  
cryptography

#### Username-Password Pairs:
usernames = ['levente12', 'istvanist', 'gaborgabo']  
passwords = ['Ey3L0v3m@@thH','tEs$sor1t2','aitAITaitA1T']

#### Success and Error Dictionary:
success_error_dict = {200: Success, 500: ‘Invalid Credentials’, 501: ‘Timestamp out of Range’, 502: ‘Unable to Authenticate’, 503: ‘Bad Mac’}

## Get Started 
#### Available Commands:  
* **MKD -n <name_of_folder>**  *creating a folder on the server*  
* **RMD -n <name_of_folder>**  *removing a folder from the server* 
* **GWD**  *get the current folder name on the server*  
* **CWD -p <path_to_folder>**  *changing the current folder on the server*  
* **LST**  *listing the content of a folder on the server*  
* **UPL -f <path_of_file>**  *uploading a file to the server*  
* **DNL -f <filename> -d <destination_path>**  *downloading a file from the server*  
* **RMF -f <filename>**  *removing a file from a folder on the server*

#### Recommended Commands:  
```shell
python3 netsim/network.py -p ‘./network’ --clean
```
```shell
python3 server.py
```
```shell
python3 client.py -u levente12 -p Ey3L0v3m@@thH
```
