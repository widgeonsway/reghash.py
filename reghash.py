import sys
import re

HASH_TYPES = {
    'MD5': r'^[a-f0-9]{32}$',
    'MD4': r'^[a-f0-9]{32}$',
    'SHA1': r'^[a-f0-9]{40}$',
    'SHA224': r'^[a-f0-9]{56}$',
    'SHA256': r'^[a-f0-9]{64}$',
    'SHA384': r'^[a-f0-9]{96}$',
    'SHA512': r'^[a-f0-9]{128}$',
    'RIPEMD-160': r'^[a-f0-9]{40}$',
    'Whirlpool': r'^[a-f0-9]{128}$',
    'Tiger-160': r'^[a-f0-9]{40}$',
    'Tiger-192': r'^[a-f0-9]{48}$',
    'Tiger-128': r'^[a-f0-9]{32}$',
    'Snefru-128': r'^[a-f0-9]{32}$',
    'Snefru-256': r'^[a-f0-9]{64}$',
    'GOST': r'^[a-f0-9]{64}$',
    'Adler-32': r'^[a-f0-9]{8}$',
    'CRC-32': r'^[a-f0-9]{8}$',
    'CRC-32B': r'^[a-f0-9]{8}$',
    'Haval-128': r'^[a-f0-9]{32}$',
    'Haval-160': r'^[a-f0-9]{40}$',
    'Haval-192': r'^[a-f0-9]{48}$',
    'Haval-224': r'^[a-f0-9]{56}$',
    'Haval-256': r'^[a-f0-9]{64}$',
    'MD2': r'^[a-f0-9]{32}$',
    'MD5Crypt': r'^\$1\$.{0,8}\$[a-f0-9]{22}$',
    'BCrypt': r'^\$2[ayb]\$.{0,12}\$[a-zA-Z0-9/.]{53}$',
    'SHA256Crypt': r'^\$5\$.{0,22}\$[a-zA-Z0-9/.]{43}$',
    'SHA512Crypt': r'^\$6\$.{0,22}\$[a-zA-Z0-9/.]{86}$',
    'DES': r'^[a-zA-Z0-9./]{0,13}$',
    'LM': r'^[a-f0-9]{32}$',
    'NTLM': r'^[a-f0-9]{32}$',
}

def identify_hash_type(hash_str):
    for hash_type, pattern in HASH_TYPES.items():
        if re.match(pattern, hash_str):
            return hash_type
    return None




hashstring=sys.argv[1]

print(hashstring)

print(identify_hash_type(hashstring))
