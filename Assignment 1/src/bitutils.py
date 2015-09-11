#!/usr/bin/python

'''
Created on Sep 9, 2015

@author: Stian Sandve
'''


def int_to_bin(s):
    return str(s) if s <= 1 else bin(s >> 1) + str(s & 1)
