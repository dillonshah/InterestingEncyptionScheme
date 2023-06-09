import socket
import os
import time

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

from keyGenerator import getKeys
from aes import encryptAES, decryptAES
from mac import getHMAC_SHA256
from signature import signature

HOST = "127.0.0.1" 
PORT = 65412

KEY = os.urandom(32)

MESSAGE = b"It\'s not a bug, it\'s a feature."
BREAK = b"0000"

#Generate Keys
privateKey, publicKey = getKeys("client")

# Connect to socket
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))

    # Get server's public key
    with open("keys/pub_server.pem","r") as f:
        server_public_key = RSA.importKey(f.read())
    
    # Encrypt session key using server's public key
    encryptor = PKCS1_OAEP.new(server_public_key)
    ek = encryptor.encrypt(KEY)
    s.sendall(ek)

    while True:
        MESSAGE = bytes(input("input message: "), 'utf-8')
        # Encrypt message
        encrypted_message = encryptAES(KEY, MESSAGE)
        print("Message encrypted")

        # Generate HMAC
        hmac = getHMAC_SHA256(encrypted_message)
        print("HMAC applied")

        # Generate signature of concatanated message and hmac
        sig = signature(encrypted_message + hmac, 2048, "client")
        print("Signature Calculated, sending Message")
        
        timestamp = str(time.time()).encode('utf-8')

        # Send result to server
        s.sendall(encrypted_message + BREAK + hmac + BREAK + sig + BREAK + timestamp)

        
