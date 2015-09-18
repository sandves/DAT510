# !/usr/bin/python

##############################################################################
# @file    feistel_cipher.py
# @author  Stian Sandve
# @version V1.0.0
# @date    9-Sep-2014
# @brief   This class provides encryption and depcryption functions for
# Feistel cipher.
###############################################################################

from bitarray import bitarray
from des import DES
import bitutils


class FeistelCipher(object):
    def __init__(self, number_of_rounds=16, block_size=64, key_size=64):

        self.number_of_rounds = number_of_rounds
        self.block_size = block_size
        self.key_size = key_size

    @staticmethod
    def parse_plaintext(plaintext):
        """
        This function may be used for prepared the plaintext for encryption.

        :param plaintext: text to be parsed.
        :return: a bitarray of the parsed plaintext.
        """

        binary = True

        for c in plaintext:
            if c is not "0" and c is not "1":
                binary = False

        print("Input is binary? %s" % binary)

        if binary:
            parsed = bitarray(plaintext)
        else:
            parsed = bitarray()
            parsed.frombytes(plaintext)

        return parsed

    def encrypt(self, plaintext, key, encrypt=True):

        result = bitarray()

        bits = plaintext

        blocks = FeistelCipher.chunks(bits, self.block_size)

        sub_keys = self.generate_sub_keys(self.parse_plaintext(key))

        if not encrypt:
            sub_keys.reverse()

        for i in range(len(blocks)):
            block = blocks[i]

            block = self.permute_block(block, DES.IP)

            for rnd in range(self.number_of_rounds):
                block = self.encrypt_round(block, sub_keys[rnd])

            block = bitutils.swap_list(block)

            block = self.permute_block(block, DES.IP_inverse)

            result.extend(block)

        #if not encrypt:
        #    result = self.parse_decrypted_cipher(40, result)

        return result

    def parse_decrypted_cipher(self, length, result):

        if length < self.block_size:
            leading_zeros = length % self.block_size
        else:
            leading_zeros = self.block_size - (length % self.block_size)

        last_block_start = len(result) - leading_zeros

        leading_blocks = result[:-self.block_size]
        last_block = result[last_block_start:]

        result = leading_blocks + last_block

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

    def encrypt_block(self, block):
        """
        Encrypts a block of 64 bits using a Feistel network of n rounds. The
        number of rounds is specified in the constructor.

        :param block: block to be encrypted.
        """

        round_key = []

        for i in range(self.number_of_rounds):
            block = self.encrypt_round(block, round_key[i])

    def encrypt_round(self, block, round_key):
        """
        Encrypts a block of 64 bits using a Feistel network of n rounds. The
        number of rounds is specified in the constructor.

        :param block: block to be encrypted.
        :param round_key: key to be used in the current round.
        :return: the encrypted block.
        """

        left = block[0:32]
        right = block[32:64]

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

            # should maybe convert to 4 bits before adding
            s = DES.S[i][row][col]
            b = '{0:04b}'.format(s)
            new_bits.extend(b)

        return new_bits

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
    def permute(key, permutation_table):
        """
        Apply permutation to a list according to a permutation table.

        :param key: list to be permuted.
        :param permutation_table: permutation lookup table.
        :return: permuted list.
        """

        permuted_key = bitarray(len(permutation_table))

        for i, p in enumerate(permutation_table):
            permuted_key[i] = key[p - 1]

        return permuted_key

    def generate_sub_keys(self, key):
        """
        Generate 48 bit sub keys from the provided 64 bit key. The function
        will generate a list of length n, where n is the number of rounds,
        containing the sub keys.

        :param key: 64 bit key.
        :return: list of length n, where n is the number of rounds,
        containing the sub keys.
        """

        sub_keys = []

        permuted_key = self.permute(key, DES.PC1)

        left, right = bitutils.split_list(permuted_key)

        for i in range(self.number_of_rounds):
            left = bitutils.rotate(left, -DES.key_shifts[i])
            right = bitutils.rotate(right, DES.key_shifts[i])

            shifted_key = left + right

            sub_key = self.permute(shifted_key, DES.PC2)

            sub_keys.append(sub_key)

        return sub_keys

    @staticmethod
    def permute_block(block, permutation_table):
        """


        :param block:
        :param permutation_table:
        :return:
        """

        permuted_block = bitarray(len(block))

        for i, b in enumerate(block):
            permuted_block[i] = block[permutation_table[i] - 1]

        return permuted_block
