import os
import hashlib
from hashlib import sha256
import sys

# RIPEMD160
def ripemd160(x):
    d = hashlib.new("ripemd160")
    d.update(x)
    return d

# Constants
P = 2**256 - 2**32 - 2**9 - 2**8 - 2**7 - 2**6 - 2**4 - 1
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798, 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

# Addition on ECDSA
def point_add(p, q):
    xp, yp = p
    xq, yq = q

    if p == q:
        l = pow(2*yp%P, P-2, P)*(3*xp*xp) % P
    else:
        l = pow(xq-xp, P-2, P)*(yq-yp) % P

    xr = (l**2 - xp - xq) % P
    yr = (l*xp - l*xr - yp) % P

    return xr, yr

# Multiplication on ECDSA
def point_mul(p, d):
    n = p
    q = None

    for i in range(256):
        if d & (1<<i):
            if q is None:
                q = n
            else:
                q = point_add(q, n)

        n = point_add(n, n)

    return q

def point_bytes(p):
    x, y = p

    return b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big")

# Base58 Encoding
def b58_encode(d):
    out = ""
    p = 0
    x = 0

    while d[0] == 0:
        out += "1"
        d = d[1:]

    for i, v in enumerate(d[::-1]):
        x += v*(256**i)

    while x > 58**(p+1):
        p += 1

    while p >= 0:
        a, x = divmod(x, 58**p)
        out += B58[a]
        p -= 1

    return out

    # Get public and private key from files which are referenced using index 
    # Index == 0 is default : Index == -1 is last account created
    # If getAll is True, then return all public keys and private keys
def get_public_private_keys(index, getAll=False):
    # Reading into all keys and importing them into pub and priv lists
    pub = []
    priv = []

    with open('wallet_pubkeys.txt', 'r') as filehandle:
        filecontents = filehandle.readlines()
        for line in filecontents:
            temp = line[:-1]
            pub.append(temp)

    with open('wallet_privkeys.txt', 'r') as filehandle:
        filecontents = filehandle.readlines()
        for line in filecontents:
            temp = line[:-1]
            priv.append(temp)

    if getAll:
        return pub, priv
    if index == -1:
        index = len(pub)-1
    return pub[index], priv[index]

# Matching of public key and private keys are done against generated public and private keys
def match_sender_pub_priv_keys(sender_pub, sender_priv):
    pub, priv = get_public_private_keys(0, getAll=True)
    pub_index = -1
    for index, public in enumerate(pub):
        if public == sender_pub:
            pub_index = index
    
    if pub_index != -1:
        if sender_priv == priv[pub_index]:
            return True, "Public and private key matched"
        else:
            return False, "Invalid private key"
    return False, "Invalid public key"

# Returns public and private key, from random number
def make_address():
    privkey = os.urandom(32)
    q = point_mul(G, int.from_bytes(privkey, "big"))
    hash160 = ripemd160(sha256(point_bytes(q)).digest()).digest()
    addr = b"\x00" + hash160
    checksum = sha256(sha256(addr).digest()).digest()[:4]
    addr += checksum

    wif = b"\x80" + privkey
    checksum = sha256(sha256(wif).digest()).digest()[:4]
    wif += checksum

    addr = b58_encode(addr)
    wif = b58_encode(wif)

    # Saving public key in wallet_pubkeys.txt
    with open('wallet_pubkeys.txt', 'a') as filehandle:
        filehandle.write("%s\n" % addr)

    # Saving private keys in wallet_privkeys.txt
    with open('wallet_privkeys.txt', 'a') as filehandle:
        filehandle.write("%s\n" % wif)

    pub, priv = get_public_private_keys(-1)
    # Printing generated public/private keys to console
    print("Generated Public key is ",pub, file=sys.stderr)
    print("Generated Private key is ",priv, file=sys.stderr)

    return addr, wif