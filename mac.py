from Crypto.Hash import HMAC, SHA256

def getHMAC_SHA256(msg):
    '''
    Uses the Hash-based Message Authentication Code function
    using a SHA-2 hash function. 
    Returns the result in bytes
    '''
    return bytes.fromhex(HMAC.new(msg, digestmod=SHA256).hexdigest())
