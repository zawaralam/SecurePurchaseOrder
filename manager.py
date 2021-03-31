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
nonce_m = ''.join(secrets.choice(alphabet) for i in range(8))

print('\nSecure Purchase Order\n')

port_p = 60000                    # Reserve a port for your service.
port_pd = 25000
s_p = socket.socket()             # Create a socket object
s_pd = socket.socket()
host = socket.gethostname()     # Get local machine name
print(host)
s_p.bind(('127.0.0.1', port_p)) 
s_pd.bind(('127.0.0.1', port_pd))     # Bind to the port
print("Manager")
s_p.listen(1) 
s_pd.listen(1)                    # Now wait for client connection.

print("\nWaiting to connect...\n")


conn_p, addr_p = s_p.accept()     # Establish connection with client.
print("Connected to Purchaser...")
conn_pd, addr_pd = s_pd.accept()     # Establish connection with client.
print("Connected to Purchasing Department...\n")

#Generate the m's RSA key
rsa_key_m = RSA.generate(2048)

#Generate the m's public key from the m's RSA key
pub_key_m = rsa_key_m.publickey()
pubKeyPEM_m = pub_key_m.exportKey()

#Obtain m's private key
privKeyPEM_m = rsa_key_m.exportKey()

#m sends its public key
conn_p.send(pubKeyPEM_m)
conn_pd.send(pubKeyPEM_m)

#m receives p's public key and prints it
pub_key_received_p = conn_p.recv(524288)
pub_key_p = RSA.importKey(pub_key_received_p)

#m receives purchasing department's public key and prints it
pub_key_received_pd = conn_pd.recv(524288)
pub_key_pd = RSA.importKey(pub_key_received_pd)

#symmetric key distribution step 1
message1_p_encrypted = conn_p.recv(524288)
message1_p_encrypted = pickle.loads(message1_p_encrypted)
decryptor_m = PKCS1_OAEP.new(rsa_key_m)
decrypted_nonce_p = decryptor_m.decrypt(message1_p_encrypted[0])
decrypted_id_p = decryptor_m.decrypt(message1_p_encrypted[1])
print("Step1:\nFrom Purchaser: " + "Purchaser's nonce: " +
decrypted_nonce_p.decode() + " Purchaser's ID: " + decrypted_id_p.decode())

message1_pd_encrypted = conn_pd.recv(524288)
message1_pd_encrypted = pickle.loads(message1_pd_encrypted)
decrypted_nonce_pd = decryptor_m.decrypt(message1_pd_encrypted[0])
decrypted_id_pd = decryptor_m.decrypt(message1_pd_encrypted[1])
print("Step1:\nFrom Purchasing Department: " + "Purchasing Department's Nonce: " +
decrypted_nonce_pd.decode() + " Purchasing Department's ID: " + decrypted_id_pd.decode())

#symmetric key distribution step 2
encryptor_p = PKCS1_OAEP.new(pub_key_p)
nonce_p_encrypted = encryptor_p.encrypt(decrypted_nonce_p)
nonce_m_encrypted = encryptor_p.encrypt(nonce_m.encode())
message2_p_encrypted = [nonce_p_encrypted, nonce_m_encrypted]
message2_p_encrypted= pickle.dumps(message2_p_encrypted)
conn_p.send(message2_p_encrypted)

encryptor_pd = PKCS1_OAEP.new(pub_key_pd)
nonce_pd_encrypted = encryptor_pd.encrypt(decrypted_nonce_pd)
nonce_m_encrypted1 = encryptor_pd.encrypt(nonce_m.encode())
message2_pd_encrypted = [nonce_pd_encrypted, nonce_m_encrypted1]
message2_pd_encrypted= pickle.dumps(message2_pd_encrypted)
conn_pd.send(message2_pd_encrypted)

print("\nStep 2:\nTo Purchaser: Purchaser's Nonce: " + decrypted_nonce_p.decode())
print("Step 2:\nTo Purchasing Department: Purchasing Department's Nonce" + decrypted_nonce_pd.decode())

#step 3
message3_p_encrypted = conn_p.recv(524288)
message3_pd_encrypted = conn_pd.recv(524288)

decrypted_nonce_m = decryptor_m.decrypt(message3_p_encrypted)
decrypted_nonce_m1 = decryptor_m.decrypt(message3_pd_encrypted)
print("\nStep3:\nFrom purchaser: Manager's Nonce " + decrypted_nonce_m.decode())
print("Step3:\nFrom purchasing department: Manager's Nonce" + decrypted_nonce_m1.decode())
print("\nVerified Purchaser and Purchasing Department")

conn_p.close()
conn_pd.close()
print ('Client Disconnected')





