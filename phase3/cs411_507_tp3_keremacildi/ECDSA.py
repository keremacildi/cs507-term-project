import random
from ecpy.curves import Curve, Point
from Crypto.Hash import SHA3_256

def KeyGen(E):
    """
    Generate a secret/public key pair (sA, QA) for the elliptic curve E.
    """
    n = E.order
    P = E.generator
    sA = random.randint(1, n - 1)
    QA = sA * P
    return sA, QA

def SignGen(message, E, sA):
    """
    This is the elliptic curve analogue of the custom DSA variant described
    in the project. We do:

      1)  k ← [1..n-1] random
      2)  R = k*P
      3)  r = R.x mod n
      4)  h = SHA3_256(m || r) mod n
      5)  s = (k - sA * h) mod n

      The signature is (s, h).
    """
    n = E.order
    P = E.generator

    # Step 1: Random nonce k
    k = random.randint(1, n - 1)

    # Step 2: Compute R = k * P
    R = k * P
    r = R.x % n

    # Step 3 & 4: Compute h = SHA3_256(m || r) mod n
    #    Convert r to bytes and append to the message
    r_bytes = r.to_bytes((r.bit_length() + 7) // 8, byteorder='big')
    h_obj = SHA3_256.new(message + r_bytes)
    h_val = int.from_bytes(h_obj.digest(), byteorder='big') % n

    # Step 5: s = (k - sA*h) mod n
    s = (k - sA * h_val) % n

    return s, h_val

def SignVer(message, s, h, E, QA):
    """
    Signature verification for the same custom scheme:

      1)  v = sP + hQA
      2)  r' = v.x mod n
      3)  u = SHA3_256(m || r') mod n
      4)  Accept if u == h, else reject.

    Returns 0 if the signature verifies, -1 otherwise.
    """
    n = E.order
    P = E.generator

    # Quick checks on signature range
    if not (1 <= h < n) or not (1 <= s < n):
        return -1

    # Step 1: v = sP + hQA
    v = s * P + h * QA

    # Step 2: r' = v.x mod n
    r_prime = v.x % n

    # Step 3: u = SHA3_256(m || r') mod n
    r_prime_bytes = r_prime.to_bytes((r_prime.bit_length() + 7) // 8, byteorder='big')
    h_obj = SHA3_256.new(message + r_prime_bytes)
    u = int.from_bytes(h_obj.digest(), byteorder='big') % n

    # Step 4: compare u with h
    if u == h:
        return 0
    else:
        return -1
