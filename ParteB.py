from os import urandom
import timeit
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def aes_encrypt_file(input_file, key):
    with open(input_file, 'rb') as f:
        text = f.read()

    nonce = urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(text) + encryptor.finalize()

    # Create output filename (add .enc extension)
    output_file = input_file + '.enc'
    
    # Write the encrypted data to the new file
    # We save both nonce and ciphertext (nonce first, then ciphertext)
    with open(output_file, 'wb') as f:
        f.write(nonce + ciphertext)
    
    return nonce, ciphertext, output_file

def aes_decrypt_file(encrypted_file, key, nonce):
    """
    Decrypt a file that was encrypted with AES-CTR mode
    
    Args:
        encrypted_file: Path to the encrypted file
        key: The same AES key used for encryption (32 bytes for AES-256)
        nonce: The same nonce used for encryption (16 bytes)
    
    Returns:
        decrypted_text: The decrypted bytes
    """
    # Read the encrypted file
    with open(encrypted_file, 'rb') as f:
        data = f.read()
    
    nonce = data[:16]           # ✅ Extract nonce
    ciphertext = data[16:] 
    # Create cipher in CTR mode with the same key and nonce
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
    decryptor = cipher.decryptor()
    
    # Decrypt the data
    decrypted_text = decryptor.update(ciphertext) + decryptor.finalize()
    
    return decrypted_text

# Prepare the arguments
key = urandom(32)
input_file = 'file_8.txt'
nonce, ciphertext, output_file = aes_encrypt_file(input_file, key)


# Using lambda to pass arguments
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

print(f"\nVerification: {'✅ PASSED' if decrypted == original else '❌ FAILED'}")