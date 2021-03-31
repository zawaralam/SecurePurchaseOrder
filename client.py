import socket,pickle, time, sys, string, secrets, base64, webbrowser                   # Import socket module

from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Signature import PKCS1_v1_5
import binascii
from time import ctime

def rsa_encrypt_message(key, message):
    encryptor = PKCS1_OAEP.new(key)
    encrypyted_message = encryptor.encrypt(message.encode())
    return encrypyted_message

def rsa_decrypt_message(key, ciphertext):
    decryptor = PKCS1_OAEP.new(key)
    decrypted_message = decryptor.decrypt(ciphertext)
    return decrypted_message.decode()

def sign_PO(privatekey, requisitioner):
    session_key_signed= SHA256.new(requisitioner.encode())
    signer = PKCS1_v1_5.new(privatekey)
    signature = signer.sign(session_key_signed)
    return signature

#Generate purchaser's nonce
alphabet = string.ascii_letters + string.digits
nonce_p = ''.join(secrets.choice(alphabet) for i in range(8))

print('\nSecure Purchase Order')
s = socket.socket()             # Create a socket object
port = 60000                    # Reserve a port for your service.

s_pd = socket.socket()             # Create a socket object
port_pd = 50000                    # Reserve a port for your service.

#Generate the purchaser's RSA key
rsa_key_p = RSA.generate(2048)
#Generate the purchaser's public key from the RSA key
pub_key_p = rsa_key_p.publickey()
pubKeyPEM_p = pub_key_p.exportKey()
#Obtain p's private key
privKeyPEM_p = rsa_key_p.exportKey()

print("Purchaser:")
print("\nConnecting to manager...")
print("Connecting to purchasing department...")
time.sleep(1)
s.connect(('127.0.0.1', port))
s_pd.connect(('127.0.0.1', port_pd))
print("Connected to manager...")
print("Connected to purchasing department...")

#purchaser receives manager's public key
pub_key_m_received = s.recv(524488)
pub_key_m = RSA.importKey(pub_key_m_received)

#purchaser sends purchaser's public key to manager
s.send(pubKeyPEM_p)
#purchaser sends purchaser's public key to purchasing department
#and receives the purchasing department's public key
s_pd.send(pubKeyPEM_p)
pub_key_pd_received = s_pd.recv(524488)
pub_key_pd = RSA.importKey(pub_key_pd_received)

#id of purchaser
id_p = "PURCHASER"

#step 1: encrypt the id of purchaser and the nonce with manager's public key
nonce_p_encrypted = rsa_encrypt_message(pub_key_m, nonce_p)
id_p_encrypted = rsa_encrypt_message(pub_key_m, id_p)
message1_encrypted = [nonce_p_encrypted, id_p_encrypted]
message1_encrypted = pickle.dumps(message1_encrypted)
s.send(message1_encrypted)
print("Step 1:\nTo Manager: Puchaser's Nonce: " + nonce_p + " Purchaser's ID: " + id_p)

nonce_p_encrypted1 = rsa_encrypt_message(pub_key_pd, nonce_p)
id_p_encrypted1 = rsa_encrypt_message(pub_key_pd, id_p)
message1_encrypted1 = [nonce_p_encrypted1, id_p_encrypted1]
message1_encrypted1 = pickle.dumps(message1_encrypted1)
s_pd.send(message1_encrypted1)
print("Step 1:\nTo Purchasing Department: Puchaser's Nonce: " + nonce_p + " Purchaser's ID: " + id_p)


#step 2
message2_p_encrypted = s.recv(524288)
message2_p_encrypted = pickle.loads(message2_p_encrypted)
decrypted_nonce_p = rsa_decrypt_message(rsa_key_p, message2_p_encrypted[0])
decrypted_nonce_m = rsa_decrypt_message(rsa_key_p, message2_p_encrypted[1])
print("\nStep2:\nFrom Manager: Purchaser's Nonce: " + decrypted_nonce_p +
" Manager's Nonce: " + decrypted_nonce_m)

message2_p_encrypted1 = s_pd.recv(524288)
message2_p_encrypted1 = pickle.loads(message2_p_encrypted1)
decrypted_nonce_p1 = rsa_decrypt_message(rsa_key_p, message2_p_encrypted1[0])
decrypted_nonce_pd = rsa_decrypt_message(rsa_key_p, message2_p_encrypted1[1])
print("\nStep2:\nFrom Purchasing Department: Purchaser's Nonce: " + decrypted_nonce_p1 +
"Purchasing Department's Nonce: " + decrypted_nonce_pd)


#step 3
nonce_m_encrypted = rsa_encrypt_message(pub_key_m, decrypted_nonce_m)
s.send(nonce_m_encrypted)
print("\nStep 3:\nTo Manager: Manager's Nonce: " + decrypted_nonce_m)

nonce_pd_encrypted = rsa_encrypt_message(pub_key_pd, decrypted_nonce_pd)
s_pd.send(nonce_pd_encrypted)
print("\nStep 3:\nTo Purchasing Department: Purchasing Department's Nonce: " + decrypted_nonce_m)
print("\nVerified Purchasing Department and Manager")
#Purchaser places an order 
CompanyName = input("Enter the Company Name: ")
POnumber = input("Enter the Purchase Order Number: ")
VendorName = input("Enter the Vendor's Name: ")
VendorAddress = input("Enter the Vendor's Address: ")
ShipToCompanyName = input("Enter the Company's Name that is placing the order: ")
ShipToCompanyAddress = input("Enter the Company's Address that is placing the order: ")
Requisitioner = input("Enter the name of the person ordering the products: ")
ShipVia = input("Enter the method of shipment: ")

#Encrypt Purchase Order with manager's public key
CompanyName_encrypted = rsa_encrypt_message(pub_key_m, CompanyName)
POnumber_encrypted = rsa_encrypt_message(pub_key_m, POnumber)
VendorName_encrypted = rsa_encrypt_message(pub_key_m, VendorName)
VendorAddress_encrypted = rsa_encrypt_message(pub_key_m, VendorAddress)
ShipToCompanyName_encrypted = rsa_encrypt_message(pub_key_m, ShipToCompanyName)
ShipToCompanyAddress_encrypted = rsa_encrypt_message(pub_key_m, ShipToCompanyAddress)
Requisitioner_encrypted = rsa_encrypt_message(pub_key_m, Requisitioner)
ShipVia_encrypted = rsa_encrypt_message(pub_key_m, ShipVia)

#Encrypt Purchase Order with purchasing department's public key
CompanyName_encrypted1 = rsa_encrypt_message(pub_key_pd, CompanyName)
POnumber_encrypted1 = rsa_encrypt_message(pub_key_pd, POnumber)
VendorName_encrypted1 = rsa_encrypt_message(pub_key_pd, VendorName)
VendorAddress_encrypted1 = rsa_encrypt_message(pub_key_pd, VendorAddress)
ShipToCompanyName_encrypted1 = rsa_encrypt_message(pub_key_pd, ShipToCompanyName)
ShipToCompanyAddress_encrypted1 = rsa_encrypt_message(pub_key_pd, ShipToCompanyAddress)
Requisitioner_encrypted1 = rsa_encrypt_message(pub_key_pd, Requisitioner)
ShipVia_encrypted1 = rsa_encrypt_message(pub_key_pd, ShipVia)

#set up signature with the requisitioner's name 
p_signature = sign_PO(rsa_key_p, Requisitioner)

#send the purchase order with signature and timestamp
PurchaseOrder = [CompanyName_encrypted, POnumber_encrypted, VendorName_encrypted,
VendorAddress_encrypted, ShipToCompanyName_encrypted,ShipToCompanyAddress_encrypted,
Requisitioner_encrypted, ShipVia_encrypted, p_signature, ctime()]

PurchaseOrder1 = [CompanyName_encrypted1, POnumber_encrypted1, VendorName_encrypted1,
VendorAddress_encrypted1, ShipToCompanyName_encrypted1,ShipToCompanyAddress_encrypted1,
Requisitioner_encrypted1, ShipVia_encrypted1, p_signature, ctime()]

PurchaseOrder = pickle.dumps(PurchaseOrder)
PurchaseOrder1 = pickle.dumps(PurchaseOrder1)
s.send(PurchaseOrder)
s_pd.send(PurchaseOrder1)

po_confirmtation_encrypted = s.recv(524288)
po_confirmtation = rsa_decrypt_message(rsa_key_p,po_confirmtation_encrypted)
if(po_confirmtation=="REJECTED"):
    print("Manager has rejected purchase order!")
if(po_confirmtation=="Purchase Order Approved"):
    print("Your purchase order is approved!")

s.close()