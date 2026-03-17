import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def aes_encrypt_file(input_file, key):


    with open(input_file, 'rb') as f:                             #rb = read binary
        text = f.read()                                           #passa a texto


    nonce = urandom(16)                                           #numero aleatório de 16 bytes

    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))        #modo de cifrar (o algorítmo: (AES) e o modo: (CTR))
    encryptor = cipher.encryptor()                                #??????????????

    ciphertext = encryptor.update(text) + encryptor.finalize()    #encriptar o texto

    return nonce, ciphertext                                      #return texto encriptado


nonce, ciphertext = aes_encrypt_file('file_8.txt', urandom(32))    #teste

print(f'\nCiphertext: {ciphertext.hex()}')
