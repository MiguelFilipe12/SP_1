from os import urandom
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def aes_encrypt_file(input_file, key):


    with open(input_file, 'rb') as f:
        text = f.read()


    nonce = urandom(16)

    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
    encryptor = cipher.encryptor()

    ciphertext = encryptor.update(text) + encryptor.finalize()

    return nonce, ciphertext


nonce, ciphertext = aes_encrypt_file('file_8.txt', urandom(16))

print(f'\nCiphertext: {ciphertext.hex()}')