#!/usr/bin/python

'''
Created on Sep 9, 2015

@author: Stian Sandve
'''

from feistel_cipher import FeistelCipher
from bitarray import bitarray


def main():
    a = bitarray('10001011')
    a ^= bitarray('11111011')
    f = FeistelCipher()
    print(a)
    print(a.to01())


if __name__ == '__main__':
    main()
