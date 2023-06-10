import socket
import time

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

from keyGenerator import getKeys
from aes import encryptAES
from mac import getHMAC_SHA256
from signature import signature

import secrets

HOST = "127.0.0.1" 
PORT = 65412
KEY = secrets.token_bytes(32)

MESSAGE = b"It\'s not a bug, it\'s a feature."
BREAK = b"0000"

#Generate Keys
privateKey, publicKey = getKeys("client")

# Connect to socket
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))

    # Get server's public key
    with open("keys/pub_server.pem","r") as f:
        pubKey = RSA.importKey(f.read())
    
    # Encrypt session key using server's public key
    encryptor = PKCS1_OAEP.new(pubKey)
    ek = encryptor.encrypt(KEY)
    s.sendall(ek)

    while True:
        MESSAGE = bytes(input("Input message: "), 'utf-8')
        # Encrypt message
        iv, ct = encryptAES(KEY, MESSAGE)
        print("Message encrypted")

        s.sendall(iv)
        # Generate HMAC
        hmac = getHMAC_SHA256(ct)
        print("HMAC applied")

        #generate timestamp
        timestamp = str(time.time()).encode('utf-8')

        # Generate signature of concatanated message and hmac
        sig = signature(ct + hmac + timestamp, 2048, "client")
        print("Signature Calculated, sending Message")
        

        # Send result to server
        s.sendall(ct + BREAK + hmac + BREAK + timestamp + BREAK + sig)
