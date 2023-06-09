from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Hash import HMAC, SHA256 #for MAC

import random
import socket


msg = b"this is the message"
key = random.randbytes(16)  #randomly generate 16 bytes long key

print("key: ")
print(bytes(key).hex())

print("encrypted: ")
e = encryptAES(key, msg)
print(e.hex())

em = getHMAC_SHA256(e, key)
print("encrypted + MAC: ")
print(em.hex())


#why I used random.randbytes() https://realpython.com/python-random/#what-is-cryptographically-secure
#about padding - https://cryptography.io/en/latest/hazmat/primitives/padding/﻿

