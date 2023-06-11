from Crypto.PublicKey import DSA
from Crypto.Hash import SHA256
from Crypto.Signature import DSS


def signature(msg, keysize, name):
    '''
    Creates key pair and returns signature
    '''
    #Create DSA Key Pairs
    keys = DSA.generate(keysize)
    publickey = keys.publickey()

    #Public Key
    with open(f"keys/pub_{name}.pem", "w") as publickey_file:
        publickey_file.write(publickey.exportKey().decode("utf-8"))

    #Sign
    msg_hashed = SHA256.new(msg)
    signature = DSS.new(keys, 'fips-186-3').sign(msg_hashed)
    return signature

def verify(msg, signature, name):
    '''
    Verifies the signature
    '''
    msg_hashed = SHA256.new(msg)
    with open(f"keys/pub_{name}.pem", "r") as keyfile:
        privatekey = DSA.import_key(keyfile.read(), 'fips-186-3')
    verifier = DSS.new(privatekey, 'fips-186-3')
    try:
        verifier.verify(msg_hashed, signature)
        return "The message is authentic."
    except ValueError:
        return "The message is not authentic."