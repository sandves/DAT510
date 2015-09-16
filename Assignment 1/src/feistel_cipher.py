#!/usr/bin/python

##############################################################################
# @file    feistel_cipher.py
# @author  Stian Sandve
# @version V1.0.0
# @date    9-Sep-2014
# @brief   This class provides encryption and depcryption functions for
# Feistel cipher.
###############################################################################

import ConfigParser
import time
import logging
from bitarray import bitarray
import math
from des import DES
import bitutils


class FeistelCipher(object):
    def __init__(self, number_of_rounds=16, block_size=64, key_size=56):

        self.number_of_rounds = number_of_rounds
        self.block_size = block_size
        self.key_size = key_size

        self.plaintext = ""
        self.key = ""
        self.cipher = ""
        self.logger = None
        self.init_logging()

    def init_logging(self):
        cfg = ConfigParser.ConfigParser()
        cfg.read('config.cfg')
        logging_enabled = cfg.getboolean('Logging', 'enabled')
        logging_level = cfg.get('Logging', 'level')
        log_to_file = cfg.getboolean('Logging', 'log_to_file')
        log_to_console = cfg.getboolean('Logging', 'log_to_console')

        if logging_level.lower() == "critical":
            level = logging.CRITICAL
        elif logging_level.lower() == "info":
            level = logging.INFO
        elif logging_level.lower() == "warning":
            level = logging.WARNING
        elif logging_level.lower() == "error":
            level = logging.ERROR
        else:
            level = logging.DEBUG

        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(level)
        log_formatter = logging.Formatter("[%(levelname)s]: %(message)s")

        if log_to_file:
            # Truncate existing log.
            with open('feistel_cipher.log', 'w'):
                pass
            file_handler = logging.FileHandler("feistel_cipher.log")
            file_handler.setFormatter(log_formatter)
            self.logger.addHandler(file_handler)
        if log_to_console:
            console_handler = logging.StreamHandler()
            console_handler.setFormatter(log_formatter)
            self.logger.addHandler(console_handler)

        if not logging_enabled:
            logging.disable(logging.CRITICAL)

        self.logger.info("---------- Logging started %s, %s ----------\n",
                         time.strftime("%d.%m.%y"), time.strftime("%H:%M:%S"))

    def parse_plaintext(self, plaintext):

        binary = True

        for c in plaintext:
            if c is not "0" or c is not "1":
                binary = False

        self.logger.debug("Input is binary? %s", binary)

        if binary:
            parsed = bitarray(plaintext)
        else:
            parsed = bitarray()
            parsed.frombytes(plaintext)

        return parsed

    def encrypt(self, plaintext, key, encrypt=True):

        result = bitarray()

        bits = self.parse_plaintext(plaintext)

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

        return result

    @staticmethod
    def chunks(l, n):
        padding_required = (len(l) % n) != 0
        n = max(1, n)
        c = [l[i:i + n] for i in range(0, len(l), n)]
        if padding_required:
            zeros = [False] * (n - len(c[len(c) - 1]))
            c[len(c) - 1] = bitarray(zeros) + c[len(c) - 1]
        return c

    def decrypt(self, ciphertext, key):
        return self.encrypt(ciphertext, key, encrypt=False)

    def encrypt_block(self, block):

        round_key = []

        for i in range(self.number_of_rounds):
            block = self.encrypt_round(block, round_key[i])

    def encrypt_round(self, block, round_key):

        left = block[0:32]
        right = block[32:64]

        f = self.apply_function(right, round_key)

        next_left = right
        next_right = left ^ f

        return next_left + next_right

    def apply_function(self, bits, sub_key):
        # 32 bit => 48 bit
        bits = self.expand(bits)
        # 48 bit XOR 48 bit
        bits ^= sub_key
        # 48 bit => 32 bit
        bits = self.substitute(bits)
        # 32 bit => 32 bit
        bits = self.permute(bits)

        return bits

    @staticmethod
    def expand(bits):
        expanded = bitarray(len(DES.E))

        for i, e in enumerate(expanded):
            expanded[i] = bits[DES.E[i] - 1]

        return expanded

    def substitute(self, bits):
        blocks = self.split_bits(bits, 6)
        new_bits = []

        for i, block in enumerate(blocks):
            left_outer_bit = block[0]
            right_outer_bit = block[5]
            outer_bits = bitarray([left_outer_bit, right_outer_bit])
            inner_bits = block[1:4]

            row = bitutils.bin_to_int(outer_bits)
            col = bitutils.bin_to_int(inner_bits)

            # should maybe convert to 4 bits before adding
            s = DES.S[i][row][col]
            new_bits.append(s)

        return new_bits

    @staticmethod
    def permute(bits):
        permuted = bitarray(len(DES.P))

        for i, b in enumerate(permuted):
            permuted[i] = bits[b - 1]

        return permuted

    def PC1_key(self, key):
        assert (len(key) == 64)
        permuted_key = bitarray(56)

        for i, p in enumerate(DES.PC1):
            permuted_key[i] = key[p - 1]

        assert (len(permuted_key) == 56)
        return permuted_key


    @staticmethod
    def PC2_key(key):
        permuted_key = bitarray(len(DES.PC2))

        for i, p in enumerate(DES.PC2):
            permuted_key[i] = key[p - 1]

        return permuted_key

    @staticmethod
    def split_bits(bits, number_of_bits=6):

        # blocks = []

        #for i in range(0, bits, number_of_bits):
        #    blocks.append(bits[i:i+number_of_bits])

        chunks = [bits[x:x + number_of_bits] for x in xrange(0, len(bits),
                                                             number_of_bits)]

        return chunks

    def generate_sub_keys(self, key):
        sub_keys = []

        permuted_key = self.PC1_key(key)

        left, right = bitutils.split_list(permuted_key)

        for i in range(self.number_of_rounds):
            left = bitutils.rotate(left, -DES.key_shifts[i])
            right = bitutils.rotate(right, DES.key_shifts[i])

            shifted_key = left + right

            sub_key = self.PC2_key(shifted_key)

            sub_keys.append(sub_key)

        return sub_keys

    @staticmethod
    def permute_block(block, permutation_table):
        permuted_block = bitarray(len(block))

        for i, b in enumerate(block):
            permuted_block[i] = block[permutation_table[i] - 1]

        return permuted_block
