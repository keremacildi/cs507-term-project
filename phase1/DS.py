import os
import secrets
import hashlib
import sympy

def random_string(length):
    # Generate a random string of given length
    alphabet = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
    return ''.join(secrets.choice(alphabet) for _ in range(length))

def GenerateOrRead(filename):
    # If pubparams.txt exists, read q, p, g from it
    if os.path.exists(filename):
        with open(filename, 'r') as f:
            q = int(f.readline().strip())
            p = int(f.readline().strip())
            g = int(f.readline().strip())
        return (q, p, g)
    else:
        # Generate q, p, g
        # 1. Generate q: a 224-bit prime
        #    bit_length(q) = 224 means q ~ 2^223
        q = sympy.randprime(2**223, 2**224)

        # 2. Generate p: a 2048-bit prime s.t (p-1) divisible by q
        # We'll try random k until p = k*q + 1 is prime and 2048-bit
        # 2048 bits means p ~ 2^2047
        # We must ensure p is prime and has bit_length = 2048
        while True:
            # Generate k as a random integer of approximately 1824 bits
            # (because p is about 2048 bits and q is about 224 bits, so 2048 - 224 ≈ 1824)
            k = secrets.randbits(1824)
            if k == 0:
                continue
            p = k * q + 1
            if p.bit_length() == 2048 and sympy.isprime(p):
                break

        # 3. Find g
        # We want a generator g of the subgroup of order q.
        # Typically: pick h at random in [2, p-2], g = h^((p-1)/q) mod p
        # If g == 1, try another h
        # Also ensure g^q = 1 mod p
        # We need to ensure that g != 1 and g^q mod p = 1.
        k_val = (p-1)//q
        while True:
            h = secrets.randbelow(p-2) + 2
            g = pow(h, k_val, p)
            if g != 1 and pow(g, q, p) == 1:
                break

        # Save parameters to file
        with open(filename, 'w') as f:
            f.write(str(q)+'\n')
            f.write(str(p)+'\n')
            f.write(str(g)+'\n')

        return (q, p, g)

def KeyGen(q, p, g):
    # alpha in [1, q-1]
    alpha = secrets.randbelow(q-1) + 1
    beta = pow(g, alpha, p)
    return (alpha, beta)

def SignGen(m, q, p, g, alpha):
    # k in [1, q-2]
    k = secrets.randbelow(q-2) + 1
    r = pow(g, k, p)

    # h = SHA3_256(m||r) mod q
    h_input = m + r.to_bytes((r.bit_length()+7)//8, 'big')
    h_val = int.from_bytes(hashlib.sha3_256(h_input).digest(), 'big') % q

    # s = k - alpha*h mod q
    s = (k - alpha*h_val) % q

    return (s, h_val)

def SignVer(m, s, h, q, p, g, beta):
    # v = g^s * beta^h mod p
    v = (pow(g, s, p)*pow(beta, h, p)) % p

    # u = SHA3_256(m||v) mod q
    v_bytes = v.to_bytes((v.bit_length()+7)//8, 'big')
    u_val = int.from_bytes(hashlib.sha3_256(m+v_bytes).digest(), 'big') % q

    if u_val == h:
        return 0
    else:
        return -1
