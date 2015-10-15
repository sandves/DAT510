# !/usr/bin/python

##############################################################################
# @file    feistel_cipher.py
# @author  Stian Sandve
# @version V1.0.0
# @date    9-Sep-2014
# @brief   This class provides encryption and depcryption functions for a
# Feistel cipher.
###############################################################################


from bitarray import bitarray

from des import DES
import bitutils


class FeistelCipher(object):
    def __init__(self, number_of_rounds=16, block_size=64, key_size=56):

        self.number_of_rounds = number_of_rounds
        self.block_size = block_size
        self.key_size = key_size

    def triple_encrypt(self, text, key):
        cipher1 = self.encrypt(text, key[:7])
        cipher2 = self.encrypt(cipher1.to01(), key[7:14])
        cipher3 = self.encrypt(cipher2.to01(), key[14:21])
        return cipher3

    def triple_decrypt(self, text, key):
        plaintext1 = self.decrypt(text, key[14:21])
        plaintext2 = self.decrypt(plaintext1.to01(), key[7:14])
        plaintext3 = self.decrypt(plaintext2.to01(), key[:7])
        return plaintext3

    def encrypt(self, text, key, encrypt=True):
        """
        This is where every part of the encryption/decryption process is tied
        together.

        Following is a brief explanation of the algorithm:

            1. Plaintext/cipher gets parsed.
            2. Input is split into chunks of 64 bits (zero padding is applied
               to the last block if needed.
            3. A list of sub keys are generated. The will be one unique key per
               round.
            4. If decryption should be applied, the list of sub keys will be
               reversed.
            5. Apply a 16 round encryption to every block of data.

        :param text: Data that will be encrypted/decrypted. Could be either
        plaintext or ciphertext.
        :param key: key used to encrypt/decrypt the data.
        :param encrypt: If set to False, decryption will be applied. Default
        value is True.
        :return: a bitarray of the encrypted/decrypted data.
        """

        result = bitarray()

        bits = self.parse_text(text)

        blocks = FeistelCipher.chunks(bits, self.block_size)

        sub_keys = self.generate_sub_keys(self.parse_text(key))

        if not encrypt:
            sub_keys.reverse()

        for i in range(len(blocks)):
            block = blocks[i]

            for rnd in range(self.number_of_rounds):
                block = self.encrypt_round(block, sub_keys[rnd])

            block = bitutils.swap_list(block)

            result.extend(block)

        return result

    def decrypt(self, ciphertext, key):
        """
        Decrypts ciphertext that has been encrypted with the encrypt() funtion.

        :param ciphertext: text to be decrypted.
        :param key: key that should be used for decryption. Must be the
        same as the key used for encryption.
        :return: a bitarray of the decrypted ciphertext, which should be equal
        to the plaintext that was passed to the encryption function.
        """

        return self.encrypt(ciphertext, key, encrypt=False)

    def encrypt_round(self, block, round_key):
        """
        Encrypts a block of 64 bits using a Feistel network of n rounds. The
        number of rounds is specified in the constructor.

        :param block: block to be encrypted.
        :param round_key: key to be used in the current round.
        :return: the encrypted block.
        """

        left, right = bitutils.split_list(block)

        f = self.round_function(right, round_key)

        next_left = right
        next_right = left ^ f

        return next_left + next_right

    def round_function(self, bits, sub_key):
        """
        Applies confusion and diffusion techniques to the input data.

        :param bits: data to be processed.
        :param sub_key: Will be used in an XOR operation with an expansion of
        the data.
        :return: confused and diffused bitarray of the input data.
        """

        # 32 bit => 48 bit
        bits = self.permute(bits, DES.E)
        # 48 bit XOR 48 bit
        bits ^= sub_key
        # 48 bit => 32 bit
        bits = self.substitute(bits)
        # 32 bit => 32 bit
        bits = self.permute(bits, DES.P)

        return bits

    def substitute(self, bits):
        """
        This is the "heart" of the algorithm. The function applies
        substitution to the data according to the well defined S-boxes used in
        DES.

        :param bits: the data to substitute.
        :return: diffused data.
        """

        blocks = self.chunks(bits, 6)
        new_bits = bitarray()

        for i, block in enumerate(blocks):
            left_outer_bit = block[0]
            right_outer_bit = block[5]
            outer_bits = bitarray([left_outer_bit, right_outer_bit])
            inner_bits = block[1:4]

            row = bitutils.bin_to_int(outer_bits)
            col = bitutils.bin_to_int(inner_bits)

            s = DES.S[i][row][col]
            b = '{0:04b}'.format(s)
            new_bits.extend(b)

        return new_bits

    def generate_sub_keys(self, key):
        """
        Generate 48 bit sub keys from the provided 56 bit key. The function
        will generate a list of length n, where n is the number of rounds,
        containing the sub keys.

        :param key: 56 bit key.
        :return: list of length n, where n is the number of rounds,
        containing the sub keys.
        """

        sub_keys = []

        left, right = bitutils.split_list(key)

        for i in range(self.number_of_rounds):
            left = bitutils.rotate(left, -DES.key_shifts[i])
            right = bitutils.rotate(right, DES.key_shifts[i])

            shifted_key = left + right

            sub_key = self.permute(shifted_key, DES.PC2)

            sub_keys.append(sub_key)

        return sub_keys

    @staticmethod
    def chunks(l, n):
        """
        Splits a list into chunks of a given length. If we are unable to split
        the list into equal sized lists, the function will append leading zeros
        to the last chunk so that every chunk will be of the same length.

        :param l: list to split.
        :param n: size of each chunk.
        :return: list of chunks.
        """

        padding_required = (len(l) % n) != 0
        n = max(1, n)
        c = [l[i:i + n] for i in range(0, len(l), n)]
        if padding_required:
            zeros = [False] * (n - len(c[len(c) - 1]))
            c[len(c) - 1] = bitarray(zeros) + c[len(c) - 1]
        return c

    @staticmethod
    def permute(data, permutation_table):
        """
        Apply permutation to a list according to a permutation table.

        :param data: list to be permuted.
        :param permutation_table: permutation lookup table.
        :return: permuted list.
        """

        permuted_key = bitarray(len(permutation_table))

        for i, p in enumerate(permutation_table):
            permuted_key[i] = data[p - 1]

        return permuted_key

    @staticmethod
    def parse_text(plaintext):
        """
        This function may be used for prepared the plaintext for encryption.

        :param plaintext: text to be parsed.
        :return: a bitarray of the parsed plaintext.
        """

        binary = True

        for c in plaintext:
            if c is not "0" and c is not "1":
                binary = False

        if binary:
            parsed = bitarray(plaintext)
        else:
            parsed = bitarray()
            parsed.frombytes(plaintext)

        return parsed
