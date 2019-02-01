#!/usr/bin/python

# THIS WAS PROVIDED BY DR. ERIC WUDSTROW FOR ECEN5033 CLASS
#This library is meant for educational purposes only
# DO NOT USE THIS LIBRARY FOR SECURITY-CRITICAL APPLICATIONS
# YOU WILL REGRET DOING SO AND EVERYONE WILL LAUGH AT YOUR MISFORTUNE

# There are many simplifications this code makes
# for ease of understanding that will
# result in embarassing mistakes, including but not limited to:
# - non-constant time point multiplication,
# - no message padding,
# - non-standard truncation of hashes, and
# - other issues whose discovery is left as an exercise for the reader :)


#####################
# We'll use the Weierstrass form of elliptic curves:
# y**2 = x**3+ax+b (mod p)

import math
import hashlib
import os

def egcd(a, b):
    '''extended greatest common denominator (GCD)
    gcd is returned as first argument'''
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def modinv(a, m):
    '''
    Modular inverse. Given a and m, returns a**-1 mod m
    e.g. x*a mod m == 1, returns x
    '''
    g, x, y = egcd(a % m, m)
    if g != 1:
        # print('g:  ', g)
        raise Exception('modular inverse does not exist for %d, %d' % (a, m))
    else:
        # xmodm = (x % m)
        # print('x mod m:  ', xmodm)
        return x % m

def modular_sqrt(a, p):
    '''Finds the quadratic residue (mod p) of a.
    e.g. x^2 = a (mod p)
    and returns x. Note: p-x is also a root.

    Returns 0 if no square root exists
    '''
    """The Tonelli-Shanks algorithm is used (except
        for some simple cases in which the solution
        is known from an identity). This algorithm
        runs in polynomial time (unless the
        generalized Riemann hypothesis is false).
    """
    # Simple cases
    #
    if legendre_symbol(a, p) != 1:
        return 0
    elif a == 0:
        return 0
    elif p == 2:
        return p
    elif p % 4 == 3:
        return pow(a, (p + 1) / 4, p)

    # Partition p-1 to s * 2^e for an odd s (i.e.
    # reduce all the powers of 2 from p-1)
    #
    s = p - 1
    e = 0
    while s % 2 == 0:
        s /= 2
        e += 1

    # Find some 'n' with a legendre symbol n|p = -1.
    # Shouldn't take long.
    #
    n = 2
    while legendre_symbol(n, p) != -1:
        n += 1

    # Here be dragons!
    # Read the paper "Square roots from 1; 24, 51,
    # 10 to Dan Shanks" by Ezra Brown for more
    # information
    #

    # x is a guess of the square root that gets better
    # with each iteration.
    # b is the "fudge factor" - by how much we're off
    # with the guess. The invariant x^2 = ab (mod p)
    # is maintained throughout the loop.
    # g is used for successive powers of n to update
    # both a and b
    # r is the exponent - decreases with each update
    #
    x = pow(a, (s + 1) / 2, p)
    b = pow(a, s, p)
    g = pow(n, s, p)
    r = e

    while True:
        t = b
        m = 0
        for m in xrange(r):
            if t == 1:
                break
            t = pow(t, 2, p)

        if m == 0:
            return x

        gs = pow(g, 2 ** (r - m - 1), p)
        g = (gs * gs) % p
        x = (x * gs) % p
        b = (b * g) % p
        r = m

# Computes the Legendre symbol a|p using Euler's criterion.
# p is a prime, and a is relatively prime to it
# Returns 1 if a has a square root modulo p, -1 otherwise
def legendre_symbol(a, p):
    ls = pow(a, (p - 1) / 2, p)
    return -1 if ls == p - 1 else ls


class ECurve(object):
    '''Weierstrass form: y**2 = x**3 + ax + b mod p
    Gx (and Gt) specify the base/generator point
    n is the group order of G'''
    def __init__(self, name, p, a, b, Gx, Gt, n=None):
        self.name = name
        self.p = p
        self.a = a
        self.b = b
        self.Gx = Gx
        self.Gt = Gt
        self.n = n      # Group order of G

    def solve_Py(self, Px, twist):
        '''Given x, solve for y on the curve
        twist determines if it should take the odd or even coordinate'''
        beta = modular_sqrt(Px**3 + self.a*Px + self.b, self.p)
        if beta == None:
            raise ValueError()
        if (beta % 2) == twist:
            return beta
        else:
            return (self.p - beta) % self.p

    def on_curve(self, Px, Py):
        '''Returns True if (Px, Py) is on the curve'''
        return ((Py**2) % self.p) == ((Px**3 + self.a*Px + self.b) % self.p)

    def G(self):
        return ECPoint(self.Gx, curve=self, twist=self.Gt)

# Define some standard curves
secp256r1 = ECurve(name="secp256r1",
    p=115792089210356248762697446949407573530086143415290314195533631308867097853951,
    a=115792089210356248762697446949407573530086143415290314195533631308867097853948,
    b=41058363725152142129326129780047268409114441015993725554835256314039467401291,
    Gx=48439561293906451759052585252797914202762949526041747995844080717082404635286,
    Gt=1,
    n=0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC6325)

secp384r1 = ECurve(name="secp384r1",
    p=39402006196394479212279040100143613805079739270465446667948293404245721771496870329047266088258938001861606973112319,
    a=39402006196394479212279040100143613805079739270465446667948293404245721771496870329047266088258938001861606973112316,
    b=27580193559959705877849011840389048093056905856361568521428707301988689241309860865136260764883745107765439761230575,
    Gx=26247035095799689268623156744566981891852923491109213387815615900925518854738050089022388053975719786650872476732087,
    Gt=1,
    n=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52)

secp521r1 = ECurve(name="secp521r1",
    p=6864797660130609714981900799081393217269435300143305409394463459185543183397656052122559640661454554977296311391480858037121987999716643812574028291115057151,
    a=6864797660130609714981900799081393217269435300143305409394463459185543183397656052122559640661454554977296311391480858037121987999716643812574028291115057148,
    b=1093849038073734274511112390766805569936207598951683748994586394495953116150735016013708737573759623248592132296706313309438452531591012912142327488478985984,
    Gx=2661740802050217063228768716723360960729859168756973147706671368418802944996427808491545080627771902352094241225065558662157113545570916814161637315895999846,
    Gt=0,
    n=0x01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409)

# This is the curve used in Bitcoin / Ethereum:
secp256k1 = ECurve(name="secp256k1",
    p=0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f,
    a=0,
    b=7,
    Gx=55066263022277343669578718895168534326250603453777594175500187360389116729240,
    Gt=0,
    n=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141)

class ECPoint(object):
    def __init__(self, x, y=None, twist=1, curve=secp256k1, infinity=False):
        self.curve = curve
        self.x = x % self.curve.p
        self.y = None
        self.infinity = infinity
        if not(self.infinity):
            if y is None:
                self.y = self.curve.solve_Py(self.x, twist)
            else:
                self.y = y % self.curve.p
                if not(self.curve.on_curve(self.x, self.y)):
                    raise Exception("point x=%s, y=%s is not on specified curve" % (x, y))

    def add(self, Q):
        P = self
        if P.infinity:
            return ECPoint(Q.x, Q.y, curve=self.curve, infinity=Q.infinity)
        if Q.infinity:
            return ECPoint(P.x, P.y, curve=self.curve, infinity=P.infinity)

        prime = self.curve.p
        if Q.x == P.x:
            if Q.y == P.y:
                # Double
                la = ((3*P.x**2 + self.curve.a) * modinv(2*P.y, prime)) % prime
            else:
                # Point at infinity / identity
                return ECPoint(0, curve=self.curve, infinity=True)
        else:
            # point add
            la = ((Q.y - P.y) * modinv(Q.x - P.x, prime)) % prime

        x = (la**2 - P.x - Q.x) % prime
        y = (la*(P.x - x) - P.y) % prime

        return ECPoint(x, y, curve=self.curve)

    def double(self):
        '''Doubles this point (P+P)
        Returns a new point'''
        prime = self.curve.p
        la = ((3*self.x**2 + self.curve.a) * modinv(2*self.y)) % prime
        x = (la**2 - 2*self.x) % prime
        y = (la*(self.x - x) - self.y) % prime

        return ECPoint(x, y, curve=self.curve)

    def mult(self, n):
        '''Point multiplication by (integer) n
        Returns a new point which is this point
        added to itself n times'''
        P = self
        Q = ECPoint(x=0, curve=self.curve, infinity=True)
        bits_n = int(math.ceil(math.log(n+1)/math.log(2)))
        for i in xrange(bits_n, -1, -1):
            Q = Q.add(Q)
            if n & (1<<i):
                Q = Q.add(P)
        return Q


def ecdsa_sign(msg, sk, curve=secp256k1, hash_fn=hashlib.sha256, k=None):
    '''
    Signs a message with a secret key (sk)
    msg must be a string,
    sk must be an integer of order curve.n
    optionally, nonce k (as an integer) can be provided, otherwise it's generated randomly
    '''
    # Get hash of the message as an integer
    e = hash_fn(msg).hexdigest()
    z = int(e, 16)

    # Generate random k
    if k == None:
        k = int(os.urandom(32).encode('hex'), 16) % curve.p

    # compute kG on the curve
    G = curve.G()   # group Generator
    kG = G.mult(k)

    # Compute r (x coordinate of kG mod n)
    r = kG.x % curve.n

    # Compute s = k^-1 * (z + r*priv_key) mod n
    s = (modinv(k, curve.n) * (z + r*sk)) % curve.n

    
    return (r, s)

# ecdsa_verify provided in another file
# You'll have to implement this!!
from verify import ecdsa_verify

def publickey(sk, curve=secp256k1):
    '''
    Takes an integer sk, returns an ECPoint public key corresponding to the secret key
    '''
    G = ECPoint(secp256k1.Gx, curve=secp256k1, twist=secp256k1.Gt)
    pk = G.mult(sk)
    return pk


def encode_pk(pk, bits=256):
    '''
    Encode public key from ECPoint -> (hex) string
    Uses compressed form.
    '''
    pre = '02'
    if (pk.y % 2) == 1:
        pre = '03'
    return pre + hex(pk.x)[2:-1].zfill(bits/4)

def decode_pk(pk, curve=secp256k1):
    '''
    Decode public key (hex) string -> ECPoint
    Currently only implements compressed form.
    '''
    if pk.startswith('02') or pk.startswith('03'):
        x = int(pk[2:], 16)
        y = curve.solve_Py(x, 0 if pk.startswith('02') else 1)
        return ECPoint(x, y=y, curve=curve)
    else:
        # TODO: non-compressed...
        pass
    return None

def encode_sig((r, s), bits=256):
    '''
    Encode a signature (r, s) tuple into a (hex) string
    '''
    return hex(r)[2:-1].zfill(bits/4) + \
           hex(s)[2:-1].zfill(bits/4)

def decode_sig(sig, bits=256):
    '''
    Decodes a signature (hex) string to a tuple (r, s)
    '''
    r = int(sig[:bits/4], 16)
    s = int(sig[bits/4:], 16)
    return (r, s)


if __name__=='__main__':
    import sys

    # Generate random private key
    sk = int(os.urandom(32).encode('hex'), 16)

    if len(sys.argv) > 1:
        # Or input from command line in hex
        sk = int(sys.argv[1], 16)

    print 'private_key =', hex(sk)[2:-1]

    # Compute (and display) public key
    pk = publickey(sk)
    print 'public_key =', encode_pk(pk)
    # Sign a message
    msg = 'Test message'
    sig = ecdsa_sign(msg, sk)
    print 'Signature: ', encode_sig(sig)

    # Verify signature
    if ecdsa_verify(msg, pk, sig) == True:
        print 'Signature is Valid!'
    else:
        print 'Error: Signature is Invalid!!!'

    # Testing invalid signature...
    if ecdsa_verify(msg + 'x', pk, sig) == False:
        print 'Correctly rejected invalid signature'
    else:
        print 'Error: verify did not reject incorrect signature'


    sys.exit(0)
