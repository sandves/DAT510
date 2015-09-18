#!/usr/bin/python

'''
Created on Sep 9, 2015

@author: Stian Sandve
'''


def int_to_bin(s):
    return str(s) if s <= 1 else bin(s >> 1) + str(s & 1)


def bin_to_int(bits):
    out = 0
    for bit in bits:
        out = (out << 1) | bit
    return out


def rotate(arr, places):
    if places >= 0:
        return shift_right(arr, places)
    else:
        return shift_left(arr, -places)


# http://stackoverflow.com/questions/19372771/shifting-list-circularly-python
def shift_left(arr, n=0):
    return arr[n::] + arr[:n:]


def shift_right(arr, n=0):
    return arr[n:len(arr):] + arr[0:n:]


def split_list(a_list):
            half = len(a_list)/2
            return a_list[:half], a_list[half:]


def swap_list(a_list):
    left, right = split_list(a_list)
    return right + left
