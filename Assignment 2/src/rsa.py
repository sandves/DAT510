def encrypt(e, n, m):
    """
    Given e, n, and m return a number
    """
    return pow_mod(m, e, n)


def encryptlist(e, n, lon):
    """
    Given e, n (the modulus, and a list of numbers, encrypt each number
    in the list and return a list of encrypted values.
    """

    return [encrypt(e, n, m) for m in lon]


def encryptstr(e, n, s):
    """
    given e, and n, select a number (c) return the decrypted value.
    """
    return encryptlist(e, n, [ord(c) for c in list(s)])


def decrypt(d, n, c):
    """
    Given d and n are given, select a number (c) and return the decrypted value.
    """
    return pow_mod(c, d, n)


def decryptlist(d, n, dalist):
    return [x ** d % n for x in dalist]


def gcd(a, b):
    """
    given a and b, return the greatest common divisor
    """
    while b != 0:
        (a, b) = (b, a % b)
    return a


def phi(p, q):
    return (p - 1) * (q - 1)


def liste(p, q):
    """
    generates a list of available encryption exponents from p and q
    """
    phii = phi(p, q)
    alpha = []
    for i in range(2, 100):
        if gcd(i, phii) == 1:
            alpha.append(i)
    return alpha


def finde(p, q):
    """
    takes p and q and selects a random number from a generated list
    """
    date = liste(p, q)
    from random import choice
    return choice(date)


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


def modinv(a, m):
    gcd, x, y = egcd(a, m)
    if gcd != 1:
        return None  # modular inverse does not exist
    else:
        return x % m


def generate_random_prime(bits, primality_test):
    """
    Generate random prime number with n bits.
    """
    import random
    import itertools

    get_random_t = lambda: random.getrandbits(bits) | 1 << bits | 1
    p = get_random_t()
    for i in itertools.count(1):
        if primality_test(p):
            return p
        else:
            if i % (bits * 2) == 0:
                p = get_random_t()
            else:
                p += 2  # Add 2 since we are only interested in odd numbers


def findd(e, p, q):
    """
    finds the value of d with the values of p and q
    """
    phiin = phi(p, q)
    for d in range(1, 10000):
        if e * d % phiin == 1:
            return d


def pow_mod(x, y, z):
    "Calculate (x ** y) % z efficiently."
    number = 1
    while y:
        if y & 1:
            number = number * x % z
        y >>= 1
        x = x * x % z
    return number


def probably_prime(n, k=20):
    """Return True if n passes k rounds of the Miller-Rabin primality
    test (and is probably prime). Return False if n is proved to be
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
        x = pow(a, s, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def genkeys(p, q):
    """
    generates random keys from p and q
    """
    phin = phi(p, q)
    alpha = []
    for i in range(2, 100):
        if gcd(i, phin) == 1:
            alpha.append(i)
    date = liste(p, q)
    from random import choice
    e = choice(date)
    for d in range(1, 10000):
        if e * d % phin == 1:
            return (e, d, phin)


def generate_keys(length):
    import random

    p = generate_random_prime(length / 2, probably_prime)
    q = generate_random_prime(length / 2, probably_prime)
    while q == p:
        q = generate_random_prime(length / 2, probably_prime)
    n = p * q
    phi = (p - 1) * (q - 1)
    while True:
        e = random.randit(3, phi - 1)
        if gcd(e, phi) == 1:
            break
    d = modinv(e, phi)
    return e, d, n
