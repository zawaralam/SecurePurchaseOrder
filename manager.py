import socket,pickle, time, sys, string, secrets, base64, webbrowser
import webbrowser
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Signature import PKCS1_v1_5
import binascii

#Generate nonce
alphabet = string.ascii_letters + string.digits
nonce1 = ''.join(secrets.choice(alphabet) for i in range(8))

print('\nSecure Purchase Order\n')

port_purchaser = 60000                    # Reserve a port for your service.
port_purchasingdepartment = 25000
s_purchaser = socket.socket()             # Create a socket object
s_purchasingdepartment = socket.socket()
host = socket.gethostname()     # Get local machine name
print(host)
s_purchaser.bind(('127.0.0.1', port_purchaser)) 
s_purchasingdepartment.bind(('127.0.0.1', port_purchasingdepartment))     # Bind to the port
print("\nManager")
s_purchaser.listen(1) 
s_purchasingdepartment.listen(1)                    # Now wait for client connection.

print("\nWaiting to connect...\n")



conn_purchaser, addr_purchaser = s_purchaser.accept()     # Establish connection with client.
conn_purchasingdepartment, addr_purchasingdepartment = s_purchasingdepartment.accept()     # Establish connection with client.

#Generate the manager's RSA key
rsa_key_manager = RSA.generate(2048)

#Generate the manager's public key from the manager's RSA key
pub_key_manager = rsa_key_manager.publickey()
pubKeyPEM_manager = pub_key_manager.exportKey()

#Obtain manager's private key
privKeyPEM_manager = rsa_key_manager.exportKey()

#Manager sends its public key
conn_purchaser.send(pubKeyPEM_manager)
conn_purchasingdepartment.send(pubKeyPEM_manager)
print("Sending to purchaser" + pubKeyPEM_manager.decode())
print("Sending to purchasing department" + pubKeyPEM_manager.decode())

#manager receives purchaser's public key and prints it
pub_key_received_purchaser = conn_purchaser.recv(524288)
pub_key_purchaser = RSA.importKey(pub_key_received_purchaser)
print(pub_key_purchaser)

#manager receives purchasing department's public key and prints it
pub_key_received_purchasingdepartment = conn_purchasingdepartment.recv(524288)
pub_key_purchasingdepartment = RSA.importKey(pub_key_received_purchasingdepartment)
print(pub_key_purchasingdepartment)

#Encrypt message with an encryptor using the client's public key and display it
# encryptor = PKCS1_OAEP.new(pub_key_B)
# nonce1_encrypted = encryptor.encrypt(nonce1.encode())
# id_server_encrypted = encryptor.encrypt(id_server.encode())

conn_purchaser.close()

print ('Client Disconnected')





