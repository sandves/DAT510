# !/usr/bin/python

##############################################################################
# @file    main.py
# @author  Stian Sandve
# @version V1.0.0
# @date    9-Sep-2014
# @brief   The main script provides a console user interface for encryption
# and decryption utilizing the FeistelCipher.
###############################################################################

from feistel_cipher import FeistelCipher


def main():

    feistel = FeistelCipher()

    while True:
        encrypt = raw_input('\nChoose method:\n1. Encrypt\n2. '
                            'Decrypt\n3. Exit\n')

        if encrypt == '3':
            break

        text = raw_input('Enter plaintext or ciphertext: ')
        key = raw_input('Enter 168 bit key (21 characters): ')

        if encrypt == '1':
            result = feistel.triple_encrypt(text, key)
            print 'encrypting ...\n\n'
        elif encrypt == '2':
            result = feistel.triple_decrypt(text, key)
            print 'decrypting ...\n\n'

        print ('Binary: ' + result.to01())
        print ('UTF-8: ' + result.tobytes())


if __name__ == '__main__':
    main()
