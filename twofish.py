import binascii
import struct

from Twofish.helpers import TWI, set_key, decrypt, encrypt

block_size = 16
key_size = 32


class Twofish:

    def __init__(self, default_vectors, key=None):

        self.context = TWI()

        self.default_vectors = default_vectors

        self.init_vectors = default_vectors

        if key is not None:
            key = binascii.unhexlify(key)
            self.set_key(key)

    def set_key(self, key):

        key_len = len(key)
        if key_len not in [16, 24, 32]:
            raise KeyError("key must be 16, 24 or 32 bytes")
        if key_len % 4:
            raise KeyError("key not a multiple of 4")
        if key_len > 32:
            raise KeyError("key_len > 32")

        key_word32 = [0] * 32
        i = 0
        while key:
            key_word32[i] = struct.unpack("<L", key[0:4])[0]
            key = key[4:]
            i += 1

        set_key(self.context, key_word32, key_len)

    def mod_bc_func(self, a, b, c, d):

        a = a ^ self.init_vectors[0]
        b = b ^ self.init_vectors[1]
        c = c ^ self.init_vectors[2]
        d = d ^ self.init_vectors[3]

        return [a, b, c, d]

    def set_default_vectors(self):

        self.init_vectors = self.default_vectors

    def decrypt(self, block):

        block = binascii.unhexlify(block)

        if len(block) % 16:
            raise ValueError("block size must be a multiple of 16")

        plaintext = b''

        while block:
            a, b, c, d = struct.unpack("<4L", block[:16])
            temp = [a, b, c, d]
            decrypt(self.context, temp)
            temp = self.mod_bc_func(*temp)
            plaintext += struct.pack("<4L", *temp)
            self.init_vectors = self.mod_bc_func(a, b, c, d)
            block = block[16:]

        return plaintext.hex()

    def encrypt(self, block):

        block = binascii.unhexlify(block)

        if len(block) % 16:
            raise ValueError("block size must be a multiple of 16")

        ciphertext = b''

        while block:
            a, b, c, d = struct.unpack("<4L", block[0:16])
            temp = self.mod_bc_func(a, b, c, d)
            encrypt(self.context, temp)
            self.init_vectors = self.mod_bc_func(*temp)
            ciphertext += struct.pack("<4L", *temp)
            block = block[16:]

        self.set_default_vectors()

        return ciphertext.hex()


init_vectors = [
    3812828313,
    3486531825,
    2996344758,
    3660737698,
]

__testkey = '4424C63AD029CE873895B02E0425D372'
__testdat = '992443E3EC40D0CF909598B29B6C32DA'

twofish = Twofish(init_vectors, __testkey)

encrypted_data = twofish.encrypt(__testdat)
decrypted_data = twofish.decrypt(encrypted_data)

print(encrypted_data)
print(decrypted_data)

# Генерируем вектора
# import random
# inf = open('vectors.txt', 'w')
# for i in range(100):
#     __testkey = hex(random.getrandbits(128)).replace('0x', '')
#     __testdat = hex(random.getrandbits(128)).replace('0x', '')
#
#     twofish = Twofish(init_vectors, __testkey)
#     encrypted_data = twofish.encrypt(__testdat)
#     decrypted_data = twofish.decrypt(encrypted_data)
#
#     inf.write('Key: ' + str(__testkey) + '\n')
#     inf.write('Data: ' + str(__testdat) + '\n')
#     inf.write('Encrypted: ' + str(encrypted_data) + '\n')
#     inf.write('Decrypted: ' + str(decrypted_data) + '\n')
#     inf.write('\n')

