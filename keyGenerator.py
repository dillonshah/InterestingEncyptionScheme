from Crypto.PublicKey import RSA

def getKeys(name):
    privateKey = RSA.generate(2048)
    publicKey = privateKey.publickey()
    with open(f"keys/pub_{name}.pem", 'wb') as content_file:
        content_file.write(publicKey.exportKey('PEM'))
    with open(f"keys/prv_{name}.pem", 'wb') as content_file:
        content_file.write(privateKey.exportKey('PEM'))
    return privateKey, publicKey