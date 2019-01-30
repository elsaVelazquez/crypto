#!/usr/bin/python

import math
import hashlib
import os


def ecdsa_verify(msg, pk, (r, s), curve=None, hash_fn=hashlib.sha256):
    '''Verifies a signature on a message.
    msg is a string,
    pk is an ecdsa.ECPoint representing the public key
    (r, s) is the signature tuple (use ecdsa.decode_sig to extract from hex)
    '''
    # Boilerplate, leave this alone
    import ecdsa
    if curve is None:
        curve = ecdsa.secp256k1

    # *********************************************************
    # TODO: Remove the raise Exception() and implement your ecdsa_verify function here:
    # Refer to ecdsa.ecdsa_sign() for examples in hashing the message,
    # and doing point multiplication.
    # See https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm#Signature_verification_algorithm
    # for the algorithm.


    
    #BOB'S VALIDATION OF ALICE'S PUBLIC CURVE POINT, Qa
    #####idk if we have to do this part of validating

    #Qa != O

    #(Ox, Oy)= isValid


    #If x * Qa = O return True


    #this is how O is found in ecdsa.py on line 211





    #PRETEND BOB VALIDATED ALICE'S PUBLIC CURVE POINT, Qa
    #1. verification that r and s are int > 1
    #help from https://stackoverflow.com/questions/33112377/python-verifying-if-input-is-int-and-greater-than-0
    check_r = True
    while check_r == True:
        #valid_r = input(r)
        #print('This is rrrrrrrrr:   ', r)
        try:
          
            if r >= 1:
                break
            else:
                print("Not implemented! Amount can't be negative, try again")
        except ValueError:
            print("Not implemented! Amount must be a number, try again")


    check_s = True
    while check_s == True:
        #valid_r = input(r)
        #print('This is ssssssss:   ', s)
        try:
          
            if s >= 1:
                break
            else:
                print("Not implemented! Amount can't be negative, try again")
        except ValueError:
            print("Not implemented! Amount must be a number, try again")
    

    #2. calculate e = hash(m)
    #e = hashlib.sha256(msg).hexdigest
    e = hash_fn(msg).hexdigest()

    #3. let z be the left-most bit
    z1 = str((e)[:1])
    z = int(ord(z1))
   

    #4. calculate--->   (w = s^-1 % n)
    w = (ecdsa.modinv(s, curve.n) % curve.n)


    #5.  calculate u1 and u2
    #have to redo z for some reason
    
    u1 = ((z * w) % curve.n)
    u2 = ((r * w) % curve.n)

    #6. if Curve point = O it is valid
    #Find (x1, y1) by doing u1 * G + u2 *Qa
    #print("pk =     ", ecdsa.encode_pk(pk))
    print('\n')
    G = curve.G()   # group Generator
    #This is alice Q_a which is alice public key
    Q_a = pk


    u1_G = G.mult(u1)
    u2_Q_a = Q_a.mult(u2)

    #u2_Qa = u2 * Qa   #NOT YET SURE WHICH IS Qa OR HOW TO EXTRACT IT
    
    #add the calculated curve points together
    calculated_curve_point = (u1_G.x + u2_Q_a.x, u1_G.y + u2_Q_a.y)


    #create O to check if this is valid
    O = Q_a.mult(curve.n)
    #print("O-x",O.x)
    #print("*********msg, pk, s to verify if valid", msg, pk, s)
    

    #conditional statement to check if signature is valid
    print("*************r: ", r)
    print("***********O.x:",O.x)      

    #make x_1
    x_1 = u1_G.x + u2_Q_a.x
    print("*********  x_1:", x_1)

    if r == ecdsa.modinv(x_1, curve.n):
        print("valid signature")
        return True
    
    #    print('valid signature')
    if O == calculated_curve_point:
        #print('Correctly rejected invalid signature')
        return True
    else:
        return False




    #raise Exception('Not implemented!')


if __name__ == '__main__':
    import ecdsa

    msgs = [
    'Hello, world',
    'The Magic Words are Squeamish Ossifrage.',
    'Attack at Dawn',
    'Attack at Dusk',
    'Create nonces randomly!',
    'Create nonces deterministically!']

    sigs = [
    'e1ca8ca322e963a24e2f2899e21255f275c2889e89adc14e225de6f338d7295aa9ab4ba5ddaa4366c4b32fb2b32371d768431b9c2cd7eee487215370a1196b49',
    'a86f5a5539e9ac49311c610f120e173ce8cb45f9493fe6a27dd81a1a22b08a2ce26a64013af4a894ab6e71df3dc3b775c8805de7c802f2e43791828be31a330c',
    'e1ca8ca322e963a24e2f2899e21255f275c2889e89adc14e225de6f338d7295ae556841b91642ea868014a9616e8ae6a8ae35bacf2e85f6e556d4bda910374f1',
    '64a70a19b87fe1c418964fe1751bbe641ea3d2f1cd70e346c722b59cdac587d857974c4683faa977789a78db471fc0cc7fafd20f31d67097e77b110789593029',
    '5b1a427f8d61345b15c716203c1e15b4370a1c841a92e88d61e021b794a209962f342d6467ae8c29a7fb25619e107381b5b252df90fe8d54bc6ecd2f41d66b83',
    'd580841c6864728bcf664a62c3ed552974c252badbecc53c53fe14e1ee922fb0b5186168ffd3cc798186660d5afadab9e088ac9f3397b64c7437bf2926d871a9']

    pub_key = '0220b6617270f57c3cd2bc3f14f5c7c37390ca790c4e30e65f77d4d9af7e6e14fb'
    pk = ecdsa.decode_pk(pub_key)
    # *******************************************************
    # TODO: Write your code for pairing messages to signatures here


    # *******************************************************
    # TODO: (Graduate students only, optional for undergrad)
    #       Write your code for extracting the private key
    #       and signing your own message here


