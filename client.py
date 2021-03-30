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
nonce_p = ''.join(secrets.choice(alphabet) for i in range(8))


print('\nSecure Purchase Order')


s = socket.socket()             # Create a socket object
port = 60000                    # Reserve a port for your service.

#Generate the p's RSA key
rsa_key_p = RSA.generate(2048)
#Generate the p's public key from the RSA key
pub_key_p = rsa_key_p.publickey()
pubKeyPEM_p = pub_key_p.exportKey()
#Obtain p's private key
privKeyPEM_p = rsa_key_p.exportKey()

print("\np")
print("\nConnecting to m...")
time.sleep(1)
s.connect(('127.0.0.1', port))
print("Connected to m...\n")

#p receives m's public key
pub_key_m_received = s.recv(524488)
pub_key_m = RSA.importKey(pub_key_m_received)

#p sends ps's public key 
s.send(pubKeyPEM_p)

#id of p
id_p = "p"

#step 1: encrypt the id of p and the nonce with m's public key
encryptor_m = PKCS1_OAEP.new(pub_key_m)
nonce_p_encrypted = encryptor_m.encrypt(nonce_p.encode())
id_p_encrypted = encryptor_m.encrypt(id_p.encode())
message1_encrypted = [nonce_p_encrypted, id_p_encrypted]
message1_encrypted = pickle.dumps(message1_encrypted)
s.send(message1_encrypted)

#step 2
message2_p_encrypted = s.recv(524288)
message2_p_encrypted = pickle.loads(message2_p_encrypted)
decryptor_p = PKCS1_OAEP.new(rsa_key_p)
decrypted_nonce_p = decryptor_p.decrypt(message2_p_encrypted[0])
decrypted_nonce_m = decryptor_p.decrypt(message2_p_encrypted[1])
print("Step2: From m: " + decrypted_nonce_p.decode() + " " + decrypted_nonce_m.decode())

#step 3
nonce_m_encrypted = encryptor_m.encrypt(decrypted_nonce_m)
s.send(nonce_m_encrypted)
s.close()