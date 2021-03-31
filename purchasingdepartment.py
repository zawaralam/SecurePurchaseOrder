import socket,pickle, time, sys, string, secrets, base64, webbrowser                   # Import socket module

from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Signature import PKCS1_v1_5
import binascii

def rsa_encrypt_message(key, message):
    encryptor = PKCS1_OAEP.new(key)
    encrypyted_message = encryptor.encrypt(message.encode())
    return encrypyted_message

def rsa_decrypt_message(key, ciphertext):
    decryptor = PKCS1_OAEP.new(key)
    decrypted_message = decryptor.decrypt(ciphertext)
    return decrypted_message.decode()

def verify_signature(pub_key_p, signature, requisitioner): 
    session_key_signed= SHA256.new(requisitioner.encode())
    verifier = PKCS1_v1_5.new(pub_key_p)
    verified = verifier.verify(session_key_signed, signature)
    return verified


#Generate nonce
alphabet = string.ascii_letters + string.digits
nonce_pd = ''.join(secrets.choice(alphabet) for i in range(8))


print('\nSecure Purchase Order')


s = socket.socket()             # Create a socket object
port = 25000                    # Reserve a port for your service.
s_p = socket.socket()             # Create a socket object
port_p = 50000                    # Reserve a port for your service.

#Generate the purchaser's RSA key
rsa_key_pd = RSA.generate(2048)
#Generate the purchaser's public key from the RSA key
pub_key_pd = rsa_key_pd.publickey()
pubKeyPEM_pd = pub_key_pd.exportKey()
#Obtain purchaser's private key
privKeyPEM_pd = rsa_key_pd.exportKey()

print("Purchasing Department")
print("\nConnecting to Manager...")
print("Connecting to Purchaser...")
host = socket.gethostname()     # Get local machine name
print(host)
s_p.bind(('127.0.0.1', port_p))
s.connect(('127.0.0.1', port)) 
time.sleep(1)
s_p.listen(1) 
conn_p, addr_p = s_p.accept()     # Establish connection with purchaser.
print("Connected to Manager...")
print("Connected to Purchaser...")

#purchasing department receives manager's public key
pub_key_manager_received = s.recv(524488)
pub_key_manager = RSA.importKey(pub_key_manager_received)

#purchasing department receives purchasor's public key
pub_key_p_received = conn_p.recv(524488)
pub_key_p= RSA.importKey(pub_key_p_received)

#purchasing department sends purchasing department's public key to purchasor and manager
s.send(pubKeyPEM_pd)
conn_p.send(pubKeyPEM_pd)

#id of pd
id_pd = "PURCHASINGDEPARTMENT"
#step 1: encrypt the id of purchaser and the nonce with manager's public key
nonce_pd_encrypted = rsa_encrypt_message(pub_key_manager, nonce_pd)
id_pd_encrypted = rsa_encrypt_message(pub_key_manager, id_pd)
message1_encrypted = [nonce_pd_encrypted, id_pd_encrypted]
message1_encrypted = pickle.dumps(message1_encrypted)
s.send(message1_encrypted)
print("Step 1:\nTo Manager: Purchasing Department's Nonce" + nonce_pd + " Purchasing Department's Id: " + id_pd)

message1_p_encrypted = conn_p.recv(524288)
message1_p_encrypted = pickle.loads(message1_p_encrypted)
decrypted_nonce_p = rsa_decrypt_message(rsa_key_pd, message1_p_encrypted[0])
decrypted_id_p = rsa_decrypt_message(rsa_key_pd, message1_p_encrypted[1])
print("Step1:\nFrom Purchaser: " + "Purchaser's nonce: " + decrypted_nonce_p + " Purchaser's ID: " + decrypted_id_p)

#step 2
message2_pd_encrypted = s.recv(524288)
message2_pd_encrypted = pickle.loads(message2_pd_encrypted)
decrypted_nonce_pd = rsa_decrypt_message(rsa_key_pd, message2_pd_encrypted[0])
decrypted_nonce_m = rsa_decrypt_message(rsa_key_pd, message2_pd_encrypted[1])
print("\nStep2:\nFrom Manager: Purchasing Department's Nonce: " + decrypted_nonce_pd + " Manager's Nonce" + decrypted_nonce_m)

nonce_p_encrypted= rsa_encrypt_message(pub_key_p, decrypted_nonce_p)
nonce_m_encrypted= rsa_encrypt_message(pub_key_p, nonce_pd)
message2_p_encrypted = [nonce_p_encrypted, nonce_m_encrypted]
message2_p_encrypted= pickle.dumps(message2_p_encrypted)
conn_p.send(message2_p_encrypted)
print("\nStep 2:\nTo Purchaser: Purchaser's Nonce: " + decrypted_nonce_p+
"Purchasing Department's Nonce: " + nonce_pd)

#step 3
nonce_m_encrypted = rsa_encrypt_message(pub_key_manager, decrypted_nonce_m)
s.send(nonce_m_encrypted)
print("\nStep 3:\nTo Manager: Manager's Nonce: " + decrypted_nonce_m)

message3_pd_encrypted = conn_p.recv(524288)
decrypted_nonce_pd1 = rsa_decrypt_message(rsa_key_pd, message3_pd_encrypted)
print("\nStep3:\nFrom purchaser: Purchasing Department's Nonce " + decrypted_nonce_pd1)
print("\nVerified Purchaser and Manager")

PO_request = conn_p.recv(524288)
PO_request = pickle.loads(PO_request)
CompanyName =  rsa_decrypt_message(rsa_key_pd, PO_request[0])
POnumber =  rsa_decrypt_message(rsa_key_pd, PO_request[1])
VendorName =  rsa_decrypt_message(rsa_key_pd, PO_request[2])
VendorAddress =  rsa_decrypt_message(rsa_key_pd, PO_request[3])
ShipToCompanyName =  rsa_decrypt_message(rsa_key_pd, PO_request[4])
ShipToCompanyAddress =  rsa_decrypt_message(rsa_key_pd, PO_request[5])
Requisitioner =  rsa_decrypt_message(rsa_key_pd, PO_request[6])
ShipVia =  rsa_decrypt_message(rsa_key_pd, PO_request[7])


verified = verify_signature(pub_key_p, PO_request[8] ,Requisitioner)
assert verified, ('Signature verification failed\n')
print ('\nSuccessfully verified purchase order from purchaser!')

PO_request_m = s.recv(524288)
PO_request_m = pickle.loads(PO_request_m)
CompanyName1 =  rsa_decrypt_message(rsa_key_pd, PO_request_m[0])
POnumber1 =  rsa_decrypt_message(rsa_key_pd, PO_request_m[1])
VendorName1 =  rsa_decrypt_message(rsa_key_pd, PO_request_m[2])
VendorAddress1 =  rsa_decrypt_message(rsa_key_pd, PO_request_m[3])
ShipToCompanyName1 =  rsa_decrypt_message(rsa_key_pd, PO_request_m[4])
ShipToCompanyAddress1 =  rsa_decrypt_message(rsa_key_pd, PO_request_m[5])
Requisitioner1 =  rsa_decrypt_message(rsa_key_pd, PO_request_m[6])
ShipVia1 =  rsa_decrypt_message(rsa_key_pd, PO_request_m[7])

verified = verify_signature(pub_key_manager, PO_request_m[8] ,Requisitioner1)
assert verified, ('Signature verification failed\n')
print ('Successfully verified purchase order from manager!')

if(CompanyName==CompanyName1 and POnumber==POnumber1 and VendorName==VendorName1):
    if(VendorAddress==VendorAddress1 and ShipToCompanyName==ShipToCompanyName1 and ShipToCompanyAddress==ShipToCompanyAddress1):
        if(Requisitioner==Requisitioner1 and ShipVia==ShipVia1):
            print("Contents Match between purchaser and manager!")
            po_approved = "Purchase Order Approved"
            po_approved_encrypted = rsa_encrypt_message(pub_key_manager, po_approved)
            s.send(po_approved_encrypted)
else:
    print("Contents Failed to Match!")

s.close()
