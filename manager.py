import socket,pickle, time, sys, string, secrets, base64, webbrowser
import webbrowser
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

def verify_signature(pub_key_p, signature, requisitioner): 
    session_key_signed= SHA256.new(requisitioner.encode())
    verifier = PKCS1_v1_5.new(pub_key_p)
    verified = verifier.verify(session_key_signed, signature)
    return verified

def sign_PO(privatekey, requisitioner):
    session_key_signed= SHA256.new(requisitioner.encode())
    signer = PKCS1_v1_5.new(privatekey)
    signature = signer.sign(session_key_signed)
    return signature

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
decrypted_nonce_p = rsa_decrypt_message(rsa_key_m, message1_p_encrypted[0])
decrypted_id_p = rsa_decrypt_message(rsa_key_m, message1_p_encrypted[1])
print("Step1:\nFrom Purchaser: " + "Purchaser's nonce: " + decrypted_nonce_p + " Purchaser's ID: " + decrypted_id_p)

message1_pd_encrypted = conn_pd.recv(524288)
message1_pd_encrypted = pickle.loads(message1_pd_encrypted)
decrypted_nonce_pd = rsa_decrypt_message(rsa_key_m, message1_pd_encrypted[0])
decrypted_id_pd = rsa_decrypt_message(rsa_key_m, message1_pd_encrypted[1])
print("Step1:\nFrom Purchasing Department: " + "Purchasing Department's Nonce: " +
decrypted_nonce_pd + " Purchasing Department's ID: " + decrypted_id_pd)

#symmetric key distribution step 2
nonce_p_encrypted= rsa_encrypt_message(pub_key_p, decrypted_nonce_p)
nonce_m_encrypted= rsa_encrypt_message(pub_key_p, nonce_m)
message2_p_encrypted = [nonce_p_encrypted, nonce_m_encrypted]
message2_p_encrypted= pickle.dumps(message2_p_encrypted)
conn_p.send(message2_p_encrypted)

nonce_pd_encrypted= rsa_encrypt_message(pub_key_pd, decrypted_nonce_pd)
nonce_m_encrypted1= rsa_encrypt_message(pub_key_pd, nonce_m)
message2_pd_encrypted = [nonce_pd_encrypted, nonce_m_encrypted1]
message2_pd_encrypted= pickle.dumps(message2_pd_encrypted)
conn_pd.send(message2_pd_encrypted)

print("\nStep 2:\nTo Purchaser: Purchaser's Nonce: " + decrypted_nonce_p + "Manager's Nonce: " +
nonce_m)
print("Step 2:\nTo Purchasing Department: Purchasing Department's Nonce" + decrypted_nonce_pd +
"Manager's Nonce: " +nonce_m)

#step 3
message3_p_encrypted = conn_p.recv(524288)
message3_pd_encrypted = conn_pd.recv(524288)
decrypted_nonce_m =  rsa_decrypt_message(rsa_key_m, message3_p_encrypted)
decrypted_nonce_m1 = rsa_decrypt_message(rsa_key_m, message3_pd_encrypted)
print("\nStep3:\nFrom purchaser: Manager's Nonce " + decrypted_nonce_m)
print("Step3:\nFrom purchasing department: Manager's Nonce" + decrypted_nonce_m1)
print("\nVerified Purchaser and Purchasing Department")

while True:
    #decrypt the purchase order with managers private key 
    PO_request = conn_p.recv(524288)
    PO_request = pickle.loads(PO_request)
    CompanyName =  rsa_decrypt_message(rsa_key_m, PO_request[0])
    if(CompanyName=="disconnect"):
        print("Purchaser is no longer placing an order")
        break
    else:
        POnumber =  rsa_decrypt_message(rsa_key_m, PO_request[1])
        VendorName =  rsa_decrypt_message(rsa_key_m, PO_request[2])
        VendorAddress =  rsa_decrypt_message(rsa_key_m, PO_request[3])
        ShipToCompanyName =  rsa_decrypt_message(rsa_key_m, PO_request[4])
        ShipToCompanyAddress =  rsa_decrypt_message(rsa_key_m, PO_request[5])
        Requisitioner =  rsa_decrypt_message(rsa_key_m, PO_request[6])
        ShipVia =  rsa_decrypt_message(rsa_key_m, PO_request[7])

        #verify the purchaser's signature with purchaser's public key
        verified = verify_signature(pub_key_p, PO_request[8] ,Requisitioner)
        assert verified, ('Signature verification failed\n')
        print ('\nSuccessfully verified purchase order!\n')

        #display the purchase order with the timestamp
        print("Timestamp: " +PO_request[9] + "\nPurchase Order Request:\nCompany Name: " +CompanyName + 
        "\nPurchase Order Number: " + POnumber + "\nVendor Name: " + VendorName +
        "\nVendor's Address: " + VendorAddress + "\nShip To: " + ShipToCompanyName + 
        "\n" + VendorAddress + "\nRequisitioner: " + Requisitioner + "\nShip VIA: " + ShipVia)

        #ask for manager's approval for purchase order
        while True:
            print("\nWaiting for purchase order..\n")
            PO_approval = input("Manager: Do you want to approve the Purchase Order,\n1.APPROVE\n2.REJECT\nResponse:")
            if(PO_approval == 'APPROVE'):
                print("Purchase Order Approved")
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
                p_signature = sign_PO(rsa_key_m, Requisitioner)

                PurchaseOrder1 = [CompanyName_encrypted1, POnumber_encrypted1, VendorName_encrypted1,
                VendorAddress_encrypted1, ShipToCompanyName_encrypted1,ShipToCompanyAddress_encrypted1,
                Requisitioner_encrypted1, ShipVia_encrypted1, p_signature, ctime()]
                PurchaseOrder1 = pickle.dumps(PurchaseOrder1)
                conn_pd.send(PurchaseOrder1)
                po_approved = conn_pd.recv(524288)
                po_approved =  rsa_decrypt_message(rsa_key_m, po_approved)
                po_approved_encrypted = rsa_encrypt_message(pub_key_p, po_approved)
                conn_p.send(po_approved_encrypted)

                break
            #if manager rejects, send encrypted rejection to purchaser
            if (PO_approval == 'REJECT'):
                print("Purchase Order Rejected")
                rejected = rsa_encrypt_message(pub_key_p, "REJECTED")
                conn_p.send(rejected)
                break
            else: 
                print("Response not recognized")



conn_p.close()
conn_pd.close()
print ('Purchaser Disconnected')





