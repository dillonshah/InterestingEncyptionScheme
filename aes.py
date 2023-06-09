from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

def encryptAES(key, pt):
    '''
    Creates an AES Cipher using ECB Mode.
    Retuens encrypted text.
    '''
    cipher = AES.new(key, AES.MODE_ECB)
    padded = pad(pt, 16)
    return cipher.encrypt(padded)  

def decryptAES(key, ct):
    '''
    Creates an AES Cipher using ECB Mode.
    Retuens encrypted text.
    '''
    cipher = AES.new(key, AES.MODE_ECB)
    return unpad(cipher.decrypt(ct), 16)