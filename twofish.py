import binascii
import struct

from Twofish.helpers import TWI, set_key, decrypt, encrypt

block_size = 16
key_size = 32
init_vectors = [
    3812828313,
    3486531825,
    2996344758,
    3660737698,
]


class Twofish:

    def __init__(self, default_vectors, key=None, mode='ECB'):

        self.context = TWI()

        self.default_vectors = default_vectors

        self.init_vectors = default_vectors

        self.mode = mode

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
        """Функция для режима сцепления блоков"""
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
            temp = self.mod_bc_func(*temp) if self.mode == 'BC' else temp
            plaintext += struct.pack("<4L", *temp)
            if self.mode == 'BC':
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
            temp = self.mod_bc_func(a, b, c, d) if self.mode == 'BC' else [a, b, c, d]
            encrypt(self.context, temp)
            if self.mode == 'BC':
                self.init_vectors = self.mod_bc_func(*temp)
            ciphertext += struct.pack("<4L", *temp)
            block = block[16:]

        if self.mode == 'BC':
            self.set_default_vectors()

        return ciphertext.hex()


def twofish_all_test(filename, mode):
    """
    Функция для проверки всех тестов
    :param filename: из какого файла читаем
    :param mode: encrypt/decrypt
    :return: Количество пройденных тестов и общее количество
    """
    inf = open(filename, 'r')
    key = ''
    c_text = ''
    p_text = ''
    all_tests = 0
    passed_tests = 0
    for line in inf.readlines():
        if line.startswith('KEY='):
            key = line.replace('KEY=', '').replace('\n', '')
        if line.startswith('CT='):
            c_text = line.replace('CT=', '').replace('\n', '')
        if line.startswith('PT='):
            p_text = line.replace('PT=', '').replace('\n', '')

        if key and c_text and p_text:
            all_tests += 1
            twofish = Twofish(init_vectors, key, mode='ECB')
            if mode == 'encrypt':
                encrypted_data = twofish.encrypt(p_text)
                if encrypted_data == c_text:
                    passed_tests += 1
            elif mode == 'decrypt':
                decrypted_data = twofish.decrypt(c_text)
                if decrypted_data == p_text:
                    passed_tests += 1

            key = ''
            c_text = ''
            p_text = ''

    return all_tests, passed_tests


print('Encryption tests:')
all_tests, passed_tests = twofish_all_test('encrypt_test.txt', 'encrypt')
print('All tests: {}, passed tests: {}'.format(all_tests, passed_tests))

print('Decryption tests:')
all_tests, passed_tests = twofish_all_test('decrypt_test.txt', 'decrypt')
print('All tests: {}, passed tests: {}'.format(all_tests, passed_tests))

# Режим сцепления блоков
# __testkey = '282BE7E4FA1FBDC29661286F1F310B7E'
# __testdat = '282BE7E4FA1FBDC29661286F1F310B7E'

# twofish = Twofish(init_vectors, __testkey, mode='BC')
#
# encrypted_data = twofish.encrypt(__testdat)
# decrypted_data = twofish.decrypt(encrypted_data)
#
# print(encrypted_data)
# print(decrypted_data)

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
