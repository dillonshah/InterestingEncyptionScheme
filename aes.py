from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

def encryptAES(key, pt):
    '''
    Creates an AES Cipher using ECB Mode.
    Retuens encrypted text.
    '''
    cipher = AES.new(key, AES.MODE_CBC)
    ct = cipher.encrypt(pad(pt, AES.block_size))
    iv = cipher.iv
    return iv, ct

def decryptAES(key, ct, iv):
    '''
    Creates an AES Cipher using ECB Mode.
    Retuens encrypted text.
    '''
    decrypt_cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(decrypt_cipher.decrypt(ct), AES.block_size)