#!/usr/bin/env python
# encoding: utf-8


# This program generates RSA-algorithm public and secret key info, encrypts and decrypts a given integer


from Crypto.Random import random


def generate_key_info():
    """
    This method generates the key-information for RSA encryption and decryption

    :return: RSA-key info
    """

    p = int(random.randint(1000, 5000))
    q = int(random.randint(1000, 5000))
    d = -1

    while not primetest(p):
        p = int(random.randint(1000, 5000))

    while not primetest(q):
        q = int(random.randint(1000, 5000))

    n = p * q
    Yn = (p - 1) * (q - 1)
    e = 0

    while d < 0:
        e = int(random.randint(2, Yn - 1))  # Create a random integer that is between 1<e<Y(n) #test 73
        d = eea(Yn, e)[0]  # eea only returns a negative integer if GCD (Y(n),e) is not 1

    return n, e, d, p, q, Yn


def encrypt(m, public_key):
    """
    This method performs the RSA encryption method for the given ciphertext
    with the given public key

    :param m: message to encrypt
    :param public_key: public key for the encryption
    :return: encrypted message aka ciphertext
    """

    n = public_key[0]
    e = public_key[1]


    return str(fast_mod_exp(int(m), e, n)).zfill(6)



def decrypt(c, key_info):
    """
    This method performs the RSA decryption method for the given ciphertext
    with the given secret key

    :param c: ciphertext to decrypt
    :param key_info: key info for the decryption
    :return: decrypted message aka plaintext
    """

    q = key_info[4]
    p = key_info[3]
    d = key_info[2]
    n = key_info[0]

    y1, y2 = eea(p, q)

    if y1 == -1:
        raise RuntimeError("EEA: Common divisor not 1")

    m1 = fast_mod_exp(int(c), d % (p - 1), p)
    m2 = fast_mod_exp(int(c), d % (q - 1), q)

    return str((y1 * q * m1 + y2 * p * m2) % n).zfill(6)


def eea(a, b):
    """
    This method performs the Extended Euclidean Algorithm on the given values and
    returns the d or -1 if the greatest common divisor of the given values is not 1

    :rtype:tuple
    :param a: first value to the comparison
    :param b: second value to the comparison
    :return:  positive integer from the same residue class of x,y for 1=x*a+y*b.
              Returns -1 if the GCD(a,b) is not 1
    """

    rk = [a, b]
    qk = [0]
    xk = [1, 0]
    yk = [0, 1]
    i = 1

    while rk[i] is not 0:
        qk.append(rk[i - 1] // rk[i])
        rk.append(rk[i - 1] % rk[i])  # "The modulo operator always yields a result with the same
        # sign as its second operand." source: docs.python.org
        if i > 1:
            xk.append(xk[i - 1] * qk[i - 1] + xk[i - 2])
            yk.append(qk[i - 1] * yk[i - 1] + yk[i - 2])
        i += 1

    if rk[-2] is not 1:  # Return a negative x if the GCD (Y(n),e) is not 1
        return -1, 0

    y = (-1) ** i * yk[-1]
    x = (-1) ** (i + 1) * xk[-1]

    # Here we add the modulus if x or y is negative so method returns the smallest
    # positice integer from the same residue class

    if y < 0:
        y += a
    else:
        x += b

    return y, x


def primetest(n):
    """
    Return True if a passes 5 rounds of the Miller-Rabin primality
    test (and so is probably prime). Return False if n is proved to be
    composite.

    :param n: integer number to be tested
    :return: boolean stating if n is almost certainly a prime number
    """

    if n == 2:  # Special case
        return True

    if n < 2 or n % 2 == 0:  # check if n is not 0, 1 or even number
        return False

    s = 0
    d = n - 1

    while d % 2 == 0:  # keep halving d while it's even
        d //= 2
        s += 1  # count the rounds

    for __ in xrange(5):  # test the number 5 times
        a = int(random.randint(2, n - 1))
        y = fast_mod_exp(a, d, n)  # a^d (mod n)
        i = 0

        while y != n - 1 and y != 1:  # Check if a^d is congruent to 1 or -1 (mod n)
            if i == s - 1:
                return False
            else:
                i += 1
                y = pow(y, 2, n)  # y^2 mod n

    return True


def fast_mod_exp(a, b, c):
    """
    This method calculates a^b (mod c)
    :rtype: int
    :param a: base
    :param b: exponent
    :param c: modulo
    :return: modular exponentiation of a^b (mod c)
    """

    r = 1

    for i in xrange(b.bit_length()):
        if b % 2 == 1:
            r = (r * a) % c
        a = pow(a, 2, c)  # a^2 mod c
        b //= 2

    return int(r % c)


def chop(a):
    """
    This method chops given string into a list of strings maximum 6 characters long.
    The last block can be shorter than 6 characters, previous ones are 6.
    :param a: string to be chopped
    :return: list of string max 6 characters long
    """
    i=0
    r=[]

    while i<len(a)-6:
        r.append(a[i:i+6])
        i+=6

    r.append(a[i:])

    return r


def text2int(t):
    """
    This method converts a string x into a string y that is the same string represented in
    ascii charcodes. Every char is presented in a charcode that has a length of 3. Charcodes
    less than 100 are padded with leading zeros to the length of 3.
    :param t: string to be converted
    :return: string that is t represented in ascii charcodes
    """
    n = []

    for letter in t:
        n.append(str(ord(letter)).zfill(3))

    return "".join(n)


def int2text(n):
    """
    This method converts given string of ascii charcodes into a string of the characters.
    The charcodes must be of the length of 3. Codes less than 100 padded with leading zeros
    :param n: string of charcodes to be converted
    :return: n converted into ascii characters
    """
    t = []
    i = 0

    while i < len(n):
        t.append(chr(int(n[i:i+3])))
        i+=3

    return "".join(t)


##########################################################################


def main():
    key_info = generate_key_info()
    print "p:    {3}\nq:    {4}\ne:    {1}\nn:    {0}\nY(n): {5}\nd:    {2}".format(*key_info)

    print "\n","-" * 50

    print "Secret key: ", key_info[0:3:2]

    public_key = key_info[:2]
    print "Public key: ", public_key

    print "-" * 50,"\n"

    print "Please input plaintext that you want to encrypt and press Enter." \
          "You may enter any amount of ascii character."
    orig_plaintext = raw_input()

    print "\n","-" * 50

    print "Original plaintext:  ", orig_plaintext

    chipertext = [encrypt(plaintext, public_key) for plaintext in chop(text2int(orig_plaintext))]
    print "Chipertext:          ", "".join(chipertext)

    new_plaintext = int2text("".join([decrypt(chiper, key_info) for chiper in chipertext]))
    print "Decrypted plaintext: ", new_plaintext

    print "-" * 50, "\n"

    if orig_plaintext == new_plaintext:
        print "Congratulations on a successful RSA key generation, encryption and decryption! :)"
    else:
        print "OMG! Something went wrong! :( Please contact someone who understands these things."
    print ""


if __name__ == '__main__':
    main()

