#!/usr/bin/python

'''
Created on Sep 9, 2015

@author: Stian Sandve
'''

from feistel_cipher import FeistelCipher
from bitarray import bitarray


def main():

    a = bitarray()
    a.frombytes("stian")

    des = FeistelCipher()
    cipher = des.encrypt("ssssssss", "sandvest")
    print(cipher)

if __name__ == '__main__':
    main()
