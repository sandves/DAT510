def encrypt(e, n, m):
    return pow_mod(m, e, n)


def encrypt_list(e, n, l):
    return [encrypt(e, n, m) for m in l]


def encrypt_str(e, n, s):
    return encrypt_list(e, n, [ord(c) for c in list(s)])


def decrypt(d, n, c):
    return pow_mod(c, d, n)


def decrypt_list(d, n, l):
    return [pow_mod(x, d, n) for x in l]


def gcd(a, b):
    while b != 0:
        (a, b) = (b, a % b)
    return a


def phi(p, q):
    return (p - 1) * (q - 1)


def egcd(a, b):
    """
    Returns pair (x, y) such that ax + by = gcd(a, b)
    """
    x, y, u, v = 0, 1, 1, 0
    while a != 0:
        q, r = b // a, b % a
        m, n = x - u * q, y - v * q
        b, a, x, y, u, v = a, r, u, v, m, n
    gcd = b
    return gcd, x, y


def modulo_inverse(a, m):
    gcd, x, y = egcd(a, m)
    if gcd != 1:
        return None
    else:
        return x % m


def generate_random_prime(bits, primality_test):
    """
    Generate random prime number with n bits.
    """
    import random
    import itertools

    # Always set the most significant bit to one to ensure that the
    # number is large enough.
    get_random_number = lambda: random.getrandbits(bits) | 1 << bits | 1
    p = get_random_number()
    for i in itertools.count(1):
        if primality_test(p):
            return p
        else:
            if i % (bits * 2) == 0:
                p = get_random_number()
            else:
                p += 2


def pow_mod(a, b, n):
    """
    Compute (a ** b) % n efficiently.
    """
    f = 1
    while b:
        if b & 1:
            f = f * a % n
        b >>= 1
        a = a * a % n
    return f


def probably_prime(n, k=20):
    """
    Return True if n passes k rounds of the Rabin-Miller primality
    test. Return False if n is proved to be
    composite.
    """
    from random import randrange
    from primes import first_thousand_primes

    if n < 2:
        return False
    for p in first_thousand_primes:
        if n < p * p:
            return True
        if n % p == 0:
            return False
    r, s = 0, n - 1
    while s % 2 == 0:
        r += 1
        s //= 2
    for _ in range(k):
        a = randrange(2, n - 1)
        x = pow_mod(a, s, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow_mod(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_keys(length):
    import random

    p = generate_random_prime(length // 2, probably_prime)
    #print 'P: %d' % p
    q = generate_random_prime(length // 2, probably_prime)
    #print 'Q: %d' % q
    # Ensure that p != q
    while q == p:
        q = generate_random_prime(length // 2, probably_prime)
    n = p * q
    #print 'N: %d' % n
    phi_n = phi(p, q)
    while True:
        e = random.randint(3, phi_n - 1)
        if gcd(e, phi_n) == 1:
            break
    #e = 65537
    d = modulo_inverse(e, phi_n)
    #print 'D: %d' % d
    return e, d, n
