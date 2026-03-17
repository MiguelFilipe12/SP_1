from os import urandom
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import timeit

#_____________________ENCRIPTAR_____________________#
def aes_encrypt_file(input_file, key):

    with open(input_file, 'rb') as f:                           #rb = read binary
        text = f.read()                                         #passa a texto

    nonce = urandom(16)                                         #numero aleatório de 16 bytes

    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))      #modo de cifrar (o algorítmo: (AES) e o modo: (CTR))
    encryptor = cipher.encryptor()                              #??????????????

    ciphertext = encryptor.update(text) + encryptor.finalize()  #encriptar o texto + termina o processo

    with open(input_file + ".enc", 'wb') as f:                   #criar ifcheiro com o texto encriptado
        f.write(ciphertext)

    with open(input_file + "nonce", "wb") as f:                  #criar ficheiro para guardar o nonce
        f.write(nonce)

    return nonce, ciphertext                                    #return texto encriptado

nonce, ciphertext = aes_encrypt_file('file_8.txt', urandom(32)) #teste
print(f'\nCiphertext: {ciphertext.hex()}')
print(f'Tempo: {timeit.timeit(lambda: aes_encrypt_file('file_8.txt', urandom(32)), number=10)}')

#_____________________DESENCRIPTAR_____________________#


