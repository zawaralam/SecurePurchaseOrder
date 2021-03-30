import socket,pickle, time, sys, string, secrets, base64, webbrowser                   # Import socket module

from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Signature import PKCS1_v1_5
import binascii

#Generate nonce
alphabet = string.ascii_letters + string.digits
nonce2 = ''.join(secrets.choice(alphabet) for i in range(8))


print('\nSecure Purchase Order')


s = socket.socket()             # Create a socket object
port = 25000                    # Reserve a port for your service.

#Generate the purchaser's RSA key
rsa_key_purchasingdepartment = RSA.generate(2048)

#Generate the purchaser's public key from the RSA key
pub_key_purchasingdepartment = rsa_key_purchasingdepartment = RSA.generate(2048).publickey()
pubKeyPEM_purchasingdepartment = pub_key_purchasingdepartment.exportKey()

#Obtain purchaser's private key
privKeyPEM_purchasingdepartment = rsa_key_purchasingdepartment.exportKey()

print("\nPurchasing Department")
print("\nConnecting to Manager...")
time.sleep(1)
s.connect(('127.0.0.1', port))
print("Connected to Manager...\n")

#purchaser receives manager's public key and prints it
pub_key_manager_received = s.recv(524488)
pub_key_manager = RSA.importKey(pub_key_manager_received)
print(pub_key_manager)

#purchaser sends purchasers's public key 
s.send(pubKeyPEM_purchasingdepartment)
s.close()
