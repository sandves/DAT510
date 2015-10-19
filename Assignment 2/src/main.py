# !/usr/bin/python

##############################################################################
# @file    main.py
# @author  Stian Sandve
# @version V1.0.0
# @date    19-Oct-2015
# @brief   The main script provides a console user interface for encryption
# and decryption utilizing the RSA cryptosystem.
###############################################################################

import rsa
from bitarray import bitarray
import sys


def main():
    length = 32
    if len(sys.argv) > 1:
        length = int(sys.argv[1])

    e, d, n = rsa.generate_keys(length)

    while True:
        encrypt = raw_input('\nChoose method:\n1. Encrypt binary\n2. '
                            'Encrypt characters\n3. Decrypt binary\n4. Decrypt characters\n5. Exit\n')

        if encrypt == '5':
            break

        m = raw_input('Enter plaintext or ciphertext: ')

        if encrypt == '1' or encrypt == '3':
            binary = True
            for c in m:
                if c is not "0" and c is not "1":
                    binary = False

            if binary:
                parsed = bitarray(m)
                m = 0
                for b in parsed:
                    m = (m << 1) | b
            else:
                print 'Input is not binary!'
        elif encrypt == '4':
            m = m.split(',')
            m = [bitarray(c) for c in m]

        if encrypt == '1':
            cipher = rsa.encrypt(e, n, int(m))
            print 'Cipher: %d' % cipher
            print 'Cipher binary: %s' % bitarray("{0:b}".format(cipher)).to01()
        elif encrypt == '2':
            cipher = rsa.encrypt_str(e, n, m)
            cipher_str = [str(c) for c in cipher]
            print 'Cipher: %s' % ''.join(cipher_str)
            binary_str = [bitarray("{0:b}".format(int(number))).to01() for number in cipher_str]
            print 'Cipher binary: %s' % ','.join(binary_str)
        elif encrypt == '3':
            plaintext = rsa.decrypt(d, n, m)
            print 'Plaintext: %d' % plaintext
            b = bitarray("{0:b}".format(plaintext))
            print 'Plaintext binary: %s' % b.to01()
        elif encrypt == '4':
            numberic_cipher = []
            for c in m:
                i = 0
                for b in c:
                    i = (i << 1) | b
                numberic_cipher.append(i)
            decrypted_list = rsa.decrypt_list(d, n, numberic_cipher)
            print ''.join([chr(c) for c in decrypted_list])

if __name__ == '__main__':
    main()
