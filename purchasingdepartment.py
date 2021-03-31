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
nonce_pd = ''.join(secrets.choice(alphabet) for i in range(8))


print('\nSecure Purchase Order')


s = socket.socket()             # Create a socket object
port = 25000                    # Reserve a port for your service.

#Generate the purchaser's RSA key
rsa_key_pd = RSA.generate(2048)
#Generate the purchaser's public key from the RSA key
pub_key_pd = rsa_key_pd.publickey()
pubKeyPEM_pd = pub_key_pd.exportKey()
#Obtain purchaser's private key
privKeyPEM_pd = rsa_key_pd.exportKey()

print("Purchasing Department")
print("\nConnecting to Manager...")
time.sleep(1)
s.connect(('127.0.0.1', port))
print("Connected to Manager...\n")

#purchaser receives manager's public key
pub_key_manager_received = s.recv(524488)
pub_key_manager = RSA.importKey(pub_key_manager_received)

#pd sends pd's public key 
s.send(pubKeyPEM_pd)

#id of pd
id_pd = "PURCHASINGDEPARTMENT"
#step 1: encrypt the id of purchaser and the nonce with manager's public key
encryptor_m = PKCS1_OAEP.new(pub_key_manager)
nonce_pd_encrypted = encryptor_m.encrypt(nonce_pd.encode())
id_pd_encrypted = encryptor_m.encrypt(id_pd.encode())
message1_encrypted = [nonce_pd_encrypted, id_pd_encrypted]
message1_encrypted = pickle.dumps(message1_encrypted)
s.send(message1_encrypted)
print("Step 1:\nTo Manager: Purchasing Department's Nonce" + nonce_pd + " Purchasing Department's Id: " + id_pd)

#step 2
message2_pd_encrypted = s.recv(524288)
message2_pd_encrypted = pickle.loads(message2_pd_encrypted)
decryptor_pd = PKCS1_OAEP.new(rsa_key_pd)
decrypted_nonce_pd = decryptor_pd.decrypt(message2_pd_encrypted[0])
decrypted_nonce_m = decryptor_pd.decrypt(message2_pd_encrypted[1])
print("\nStep2:\nFrom Manager: Purchasing Department's Nonce: " + decrypted_nonce_pd.decode() + " Manager's Nonce" + decrypted_nonce_m.decode())

#step 3
nonce_m_encrypted = encryptor_m.encrypt(decrypted_nonce_m)
s.send(nonce_m_encrypted)
print("\nStep 3:\nTo Manager: Manager's Nonce: " + decrypted_nonce_m.decode())

s.close()
