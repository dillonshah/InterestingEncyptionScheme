import socket
from keyGenerator import getKeys
from signature import verify
from aes import decryptAES
from mac import getHMAC_SHA256
from Crypto.Cipher import PKCS1_OAEP

import time

HOST = "127.0.0.1"
PORT = 65412

privateKey, publicKey = getKeys("server")

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    conn, addr = s.accept()
    with conn:
        print(f"Connected by {addr}")

        # Recieve encrypted session key
        ek = conn.recv(1024)
        print("recieved encrypted session key")

        # Decrypt key using client's public key
        decryptor = PKCS1_OAEP.new(privateKey)
        key = decryptor.decrypt(ek)

        while True:
            # Receive IV
            iv = conn.recv(1024)
            print("IV Received")

            # Receive message
            data = conn.recv(4096)
            print("Recieved message")

            # Split message on BREAK constant, and decrypt
            ct, hmac, timeStamp, sig = data.split(b"0000")

            msg = decryptAES(key, ct, iv)
            print("Unencrypted message: ", msg)

            # Verify that HMACs work
            newHmac = getHMAC_SHA256(ct)
            if newHmac == hmac:
                print("MACs same, integrity guaranteed")
            else :
                print("MACS differ, message tampered with")
        
            #Verify signature
            print(verify(ct + hmac + timeStamp, sig, "client"))

            #Verify Timestamp
            rTimestamp = timeStamp.decode('utf-8')
            cTimeStamp = time.time()

            if time.time() - float(timeStamp.decode('utf-8')) <= 10:
                print("Time stamp is valid")
                
            else:
                print("Invalid time stamp")
