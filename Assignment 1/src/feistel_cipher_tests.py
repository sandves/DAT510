# !/usr/bin/python

##############################################################################
# @file    feistel_cipher_tests.py
# @author  Stian Sandve
# @version V1.0.0
# @date    9-Sep-2014
# @brief   Simple unit tests to verify the correctness of the symmetric block
# cipher algorithm in FeisteCipher.
###############################################################################


import unittest
import time

from bitarray import bitarray

from feistel_cipher import FeistelCipher


def encrypt_ascii(text_to_encrypt):
    f = FeistelCipher()
    cipher = f.encrypt(text_to_encrypt, 'sandvest')
    decrypted = f.decrypt(cipher.tobytes(), 'sandvest')
    decrypted_text = decrypted.tobytes()
    decrypted_text = decrypted_text.replace('\x00', '')
    return decrypted_text


def triple_encrypt_ascii(text_to_encrypt):
    f = FeistelCipher()
    key = 'stiansandvestiansandv'
    cipher = f.triple_encrypt(text_to_encrypt, key)
    decrypted = f.triple_decrypt(cipher.to01(), key)
    decrypted_text = decrypted.tobytes()
    decrypted_text = decrypted_text.replace('\x00', '')
    return decrypted_text


def parse_decrypted_cipher(length, result):
    if length < 64:
        leading_zeros = length % 64
    else:
        leading_zeros = 64 - (length % 64)

    last_block_start = len(result) - leading_zeros

    leading_blocks = result[:-64]
    last_block = result[last_block_start:]

    result = leading_blocks + last_block

    return result


class FeistelCipherTestCase(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        super(FeistelCipherTestCase, self).__init__(*args, **kwargs)

        self.long_string = (
            'Lorem ipsum dolor sit amet, consectetur adipisicing elit, '
            'sed do eiusmod tempor incididunt ut labore et dolore magna '
            'aliqua. Ut enim ad minim veniam, quis nostrud exercitation '
            'ullamco laboris nisi ut aliquip ex ea commodo consequat. '
            'Duis aute irure dolor in reprehenderit in voluptate velit '
            'esse cillum dolore eu fugiat nulla pariatur. Excepteur sint '
            'occaecat cupidatat non proident, sunt in culpa qui officia '
            'deserunt mollit anim id est laborum.'
        )

    def test_ascii_encryption(self):
        """
        Simple test to verify that the decrypted ciphertext is equal to the
        plaintext provided to the encryption method.
        """

        text_to_encrypt = self.long_string
        decrypted_text = encrypt_ascii(text_to_encrypt)
        self.assertEquals(text_to_encrypt, decrypted_text)

    def test_triple_ascii_encryption(self):
        text_to_encrypt = self.long_string
        decrypted_text = triple_encrypt_ascii(text_to_encrypt)
        self.assertEquals(text_to_encrypt, decrypted_text)

    def test_duration_of_ascii_encryption(self):
        """
        Ensure that the encryption time is kept fairly low.
        """

        f = FeistelCipher()
        key = 'sandvest'
        start = time.time()
        f.encrypt(self.long_string, key)
        end = time.time()
        print ('Long string single encryption: %fms' % ((end - start)*1000))
        self.assertLess((end - start), 0.2)

    def test_duration_of_triple_ascii_encryption(self):

        f = FeistelCipher()
        key = 'stiansandvestiansandv'
        start = time.time()
        f.triple_encrypt(self.long_string, key)
        end = time.time()
        print ('Long string triple encryption: %fms' % ((end - start)*1000))
        self.assertLess((end - start), 0.4)

    def test_duration_of_single_block_encryption(self):
        f = FeistelCipher()
        key = 'stiansandvestiansandv'
        start = time.time()
        f.triple_encrypt('ssssssss', key)
        end = time.time()
        print ('Single block triple encryption: %fms' % ((end - start)*1000))
        self.assertLess((end - start), 0.015)

    def test_binary_encryption(self):
        """
        Verify that encryption/decryption works for binary input as well.
        """

        des = FeistelCipher()
        text_to_encrypt = '1010010100101010100001'
        cipher = des.encrypt(text_to_encrypt, "sandvest")
        decrypted = des.decrypt(cipher.to01(), "sandvest")
        decrypted = parse_decrypted_cipher(len(bitarray(text_to_encrypt)),
                                           decrypted.to01())
        self.assertEquals(text_to_encrypt, decrypted)

    def test_avalanche(self):
        """
        A change of one bit in the plaintext, results in 26-42 bit flips in the
        ciphertext using the data below.

        The function iterates the initial binary plaintext, flips the bit at the
        current index, performs an encryption of the new plaintext and counts
        the number of bits that has flipped in the new ciphertext compared to
        the initial ciphertext. The bit that was flipped in the plaintext gets
        flipped back before the next iteration.

        The test also stores the minimum and maximum number of bit flips
        observed during the process.
        """

        key = 'stiansandvestiansandv'

        des = FeistelCipher()
        text_to_encrypt = '10101101001011110100101111010010'
        cipher1 = des.triple_encrypt(text_to_encrypt, key)

        text_to_encrypt = bitarray(text_to_encrypt)
        min = None
        max = 0

        for idx, val in enumerate(text_to_encrypt):
            if val:
                text_to_encrypt[idx] = False
            else:
                text_to_encrypt[idx] = True

            cipher2 = des.triple_encrypt(text_to_encrypt.to01(), key)
            number_of_bit_flips = 0
            for i, bit in enumerate(cipher1):
                if bit != cipher2[i]:
                    number_of_bit_flips += 1

            if idx == 0:
                min = number_of_bit_flips

            if number_of_bit_flips < min:
                min = number_of_bit_flips

            if number_of_bit_flips > max:
                max = number_of_bit_flips

            if val:
                text_to_encrypt[idx] = False
            else:
                text_to_encrypt[idx] = True

        print ('Lowest number of bit flips: %d' % min)
        print ('Highest number of bit flips: %d' % max)

        self.assertGreaterEqual(min, 20)


if __name__ == '__main__':
    unittest.main()
