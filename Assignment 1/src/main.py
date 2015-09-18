#!/usr/bin/python

'''
Created on Sep 9, 2015

@author: Stian Sandve
'''

from feistel_cipher import FeistelCipher


def main():

    des = FeistelCipher()
    cipher = des.encrypt("stian sandve", "sandvest")
    plaintext = des.decrypt(cipher.tobytes(), "sandvest")
    print(plaintext.tobytes())

if __name__ == '__main__':
    main()
