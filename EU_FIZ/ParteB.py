import os
import timeit
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def aes_encrypt_file(input_file, key):
    """
    Função de encriptação com AES em Counter Mode
    """
    with open(input_file, 'rb') as f:
        text = f.read()

    nonce = os.urandom(16) # Gera número não-pseudo-aleatório com 16 bytes
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(text) + encryptor.finalize()

    # Cria o nome do ficheiro de output
    output_file = input_file + '.encriptado'
    
    # Escreve os dados encriptados no ficheiro
    # Guardando ambos o nonce e o texto encriptado
    with open(output_file, 'wb') as f:
        f.write(nonce + ciphertext)
    
    return nonce, ciphertext, output_file

def aes_decrypt_file(encrypted_file, key, nonce):
    """
    Função de decriptação com AES Counter Mode
    
    Argumentos:
        encrypted_file: Ficheiro encriptado
        key: Mesma usada para a encriptação
        nonce: Mesmo valor aleatório usado na encriptação (16 bytes)
    """

    with open(encrypted_file, 'rb') as f:
        data = f.read()
    
    stored_nonce = data[:16]           # Extrai o nonce
    ciphertext = data[16:]      # Extrai o texto encriptado
    cipher = Cipher(algorithms.AES(key), modes.CTR(stored_nonce))
    decryptor = cipher.decryptor()
    
    # Decripta os dados
    decrypted_text = decryptor.update(ciphertext) + decryptor.finalize()
    
    return decrypted_text

# Pré-preparação dos arguemntos
key = os.urandom(32) # Chave de 32 bytes/256 bits
input_file =  'file_8.txt' # Exemplo
nonce, ciphertext, output_file = aes_encrypt_file(input_file, key)

# Medição de tempo para encriptação e decriptação dos ficheiros

# E
# R
# R
# A
# D
# O DAQUI PARA BAIXO

# Tempo de Encriptação
encryption_time = timeit.timeit(
    lambda: aes_encrypt_file(input_file, key), 
    number=1000  # Run 1000 times
)
avg_encryption_ms = (encryption_time / 1000) * 1000  # Convert to milliseconds
print(f"   Average time: {avg_encryption_ms:.4f} ms per encryption")

decryption_time = timeit.timeit(
    lambda: aes_decrypt_file(output_file, key, nonce), 
    number=1000  # Run 1000 times
)
avg_decryption_ms = (decryption_time / 1000) * 1000  # Convert to milliseconds
print(f"   Average time: {avg_decryption_ms:.4f} ms per decryption")

# Verify
decrypted = aes_decrypt_file(output_file, key, nonce)
with open(input_file, 'rb') as f:
    original = f.read()

print(f"\nEncryption/Decryption Verification: {'True' if decrypted == original else 'False'}")
