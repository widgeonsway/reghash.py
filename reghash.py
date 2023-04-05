import sys
import re

def identify_hash_type(hash_str):
    hash_type = None
    # Regex patterns for different hash types
    md5_pattern = re.compile(r'^[a-f0-9]{32}$')
    md4_pattern = re.compile(r'^[a-f0-9]{32}$')
    sha1_pattern = re.compile(r'^[a-f0-9]{40}$')
    sha224_pattern = re.compile(r'^[a-f0-9]{56}$')
    sha256_pattern = re.compile(r'^[a-f0-9]{64}$')
    sha384_pattern = re.compile(r'^[a-f0-9]{96}$')
    sha512_pattern = re.compile(r'^[a-f0-9]{128}$')
    ripemd160_pattern = re.compile(r'^[a-f0-9]{40}$')
    whirlpool_pattern = re.compile(r'^[a-f0-9]{128}$')
    tiger160_pattern = re.compile(r'^[a-f0-9]{40}$')
    tiger192_pattern = re.compile(r'^[a-f0-9]{48}$')
    tiger128_pattern = re.compile(r'^[a-f0-9]{32}$')
    snefru128_pattern = re.compile(r'^[a-f0-9]{32}$')
    snefru256_pattern = re.compile(r'^[a-f0-9]{64}$')
    gost_pattern = re.compile(r'^[a-f0-9]{64}$')
    adler32_pattern = re.compile(r'^[a-f0-9]{8}$')
    crc32_pattern = re.compile(r'^[a-f0-9]{8}$')
    crc32b_pattern = re.compile(r'^[a-f0-9]{8}$')
    haval128_pattern = re.compile(r'^[a-f0-9]{32}$')
    haval160_pattern = re.compile(r'^[a-f0-9]{40}$')
    haval192_pattern = re.compile(r'^[a-f0-9]{48}$')
    haval224_pattern = re.compile(r'^[a-f0-9]{56}$')
    haval256_pattern = re.compile(r'^[a-f0-9]{64}$')
    md2_pattern = re.compile(r'^[a-f0-9]{32}$')
    md5crypt_pattern = re.compile(r'^\$1\$.{0,8}\$[a-f0-9]{22}$')
    bcrypt_pattern = re.compile(r'^\$2[ayb]\$.{0,12}\$[a-zA-Z0-9/.]{53}$')
    sha256crypt_pattern = re.compile(r'^\$5\$.{0,22}\$[a-zA-Z0-9/.]{43}$')
    sha512crypt_pattern = re.compile(r'^\$6\$.{0,22}\$[a-zA-Z0-9/.]{86}$')
    des_pattern = re.compile(r'^[a-zA-Z0-9./]{0,13}$')
    lm_pattern = re.compile(r'^[a-f0-9]{32}$')
    ntlm_pattern = re.compile(r'^[a-f0-9]{32}$')
    
    if md5_pattern.match(hash_str):
        hash_type = 'MD5'
    elif md4_pattern.match(hash_str):
        hash_type = 'MD4'
    elif sha1_pattern.match(hash_str):
        hash_type = 'SHA1'
    elif sha224_pattern.match(hash_str):
        hash_type = 'SHA224'
    elif sha256_pattern.match(hash_str):
        hash_type = 'SHA256'
    elif sha384_pattern.match(hash_str):
        hash_type = 'SHA384'
    elif sha512_pattern.match(hash_str):
        hash_type = 'SHA512'
    elif ripemd160_pattern.match(hash_str):
        hash_type = 'RIPEMD-160'
    elif whirlpool_pattern.match(hash_str):
        hash_type = 'Whirlpool'
    elif tiger160_pattern.match(hash_str):
        hash_type = 'Tiger-160'
    elif tiger192_pattern.match(hash_str):
        hash_type = 'Tiger-192'
    elif tiger128_pattern.match(hash_str):
        hash_type = 'Tiger-128'
    elif snefru128_pattern.match(hash_str):
        hash_type = 'Snefru-128'
    elif snefru256_pattern.match(hash_str):
        hash_type = 'Snefru-256'
    elif gost_pattern.match(hash_str):
        hash_type = 'GOST'
    elif adler32_pattern.match(hash_str):
        hash_type = 'Adler-32'
    elif crc32_pattern.match(hash_str):
        hash_type = 'CRC-32'
    elif crc32b_pattern.match(hash_str):
        hash_type = 'CRC-32B'
    elif haval128_pattern.match(hash_str):
        hash_type = 'Haval-128'
    elif haval160_pattern.match(hash_str):
        hash_type = 'Haval-160'
    elif haval192_pattern.match(hash_str):
        hash_type = 'Haval-192'
    elif haval224_pattern.match(hash_str):
        hash_type = 'Haval-224'
    elif haval256_pattern.match(hash_str):
        hash_type = 'Haval-256'
    elif md2_pattern.match(hash_str):
        hash_type = 'MD2'
    elif md5crypt_pattern.match(hash_str):
        hash_type = 'MD5Crypt'
    elif bcrypt_pattern.match(hash_str):
        hash_type = 'BCrypt'
    elif sha256crypt_pattern.match(hash_str):
        hash_type = 'SHA256Crypt'
    elif sha512crypt_pattern.match(hash_str):
        hash_type = 'SHA512Crypt'
    elif des_pattern.match(hash_str):
        hash_type = 'DES'
    elif lm_pattern.match(hash_str):
        hash_type = 'LM'
    elif ntlm_pattern.match(hash_str):
        hash_type = 'NTLM'
    else:
        hash_type = 'Unknown'
    
    return hash_type
    


hashstring=sys.argv[1]

print(hashstring)

print(identify_hash_type(hashstring))
