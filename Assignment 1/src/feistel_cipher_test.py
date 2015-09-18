import unittest
from feistel_cipher import FeistelCipher
from bitarray import bitarray


class FeistelCipherTestCase(unittest.TestCase):

    def test_ascii_encryption(self):
        des = FeistelCipher()
        text_to_encrypt = 'stian sandve'
        bits = bitarray()
        bits.frombytes(text_to_encrypt)
        cipher = des.encrypt(bits, "sandvest")
        decrypted = des.decrypt(cipher, "sandvest")
        decrypted_text = decrypted.tobytes()
        decrypted_text = decrypted_text.replace('\x00', '')
        self.assertEquals(text_to_encrypt, decrypted_text)

    def test_binary_encryption(self):
        des = FeistelCipher()
        text_to_encrypt = '1010010100101010100001'
        bits = bitarray(text_to_encrypt)
        cipher = des.encrypt(bits, "sandvest")
        decrypted = des.decrypt(cipher, "sandvest")
        decrypted = self.parse_decrypted_cipher(len(bits), decrypted.to01())
        self.assertEquals(text_to_encrypt, decrypted)

    def parse_decrypted_cipher(self, length, result):

        if length < 64:
            leading_zeros = length % 64
        else:
            leading_zeros = 64 - (length % 64)

        last_block_start = len(result) - leading_zeros

        leading_blocks = result[:-64]
        last_block = result[last_block_start:]

        result = leading_blocks + last_block

        return result

if __name__ == '__main__':
    unittest.main()