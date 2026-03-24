import os
import hashlib
import math
import timeit
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

class SecureRSAHybrid:
    """
    Implements Enc(m; r) = (RSA(r), H(0,r)⊕m₀, ..., H(n,r)⊕mₙ)
    where H = SHA256
    """
    
    def __init__(self, key_size=2048):
        # Generate RSA key pair
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size
        )
        self.public_key = self.private_key.public_key()
        self.hash_size = 32  # SHA256 outputs 32 bytes
        self.key_size = key_size
    
    def _hash(self, block_index, r):
        """
        H(block_index, r) using SHA256
        
        Args:
            block_index: integer block number
            r: random seed (bytes)
        
        Returns: 32-byte hash value
        """
        # Convert block index to bytes
        index_bytes = block_index.to_bytes(8, byteorder='big')
        # Hash the combination
        return hashlib.sha256(index_bytes + r).digest()
    
    def encrypt(self, message):
        """
        Encrypt message using Enc(m; r) = (RSA(r), H(0,r)⊕m₀, ..., H(n,r)⊕mₙ)
        
        Args:
            message: bytes to encrypt
            
        Returns:
            (encrypted_r, encrypted_blocks)
            - encrypted_r: RSA-encrypted random seed
            - encrypted_blocks: list of XOR-encrypted blocks
        """
        # Generate uniform random r (size for RSA encryption)
        # RSA can encrypt up to (key_size/8 - padding) bytes
        # For OAEP with SHA256, max message size = key_size/8 - 2*hash_size - 2
        max_r_size = (self.key_size // 8) - 2 * 32 - 2
        r = os.urandom(max_r_size)
        
        # Compute RSA(r) - encrypt r with RSA public key
        encrypted_r = self.public_key.encrypt(
            r,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Calculate number of blocks: n = ⌈|m|/ℓ⌉
        n = math.ceil(len(message) / self.hash_size)
        
        # Encrypt each block: cipher_block_i = H(i, r) ⊕ message_block_i
        encrypted_blocks = []
        for i in range(n):
            # Extract message block
            start = i * self.hash_size
            end = min(start + self.hash_size, len(message))
            message_block = message[start:end]
            
            # Compute H(i, r)
            hash_value = self._hash(i, r)
            
            # XOR with hash (truncate hash for last block if needed)
            cipher_block = bytes(
                a ^ b for a, b in zip(message_block, hash_value[:len(message_block)])
            )
            encrypted_blocks.append(cipher_block)
        
        return encrypted_r, encrypted_blocks
    
    def decrypt(self, encrypted_r, encrypted_blocks):
        """
        Decrypt message encrypted with the encrypt method
        
        Args:
            encrypted_r: RSA-encrypted random seed
            encrypted_blocks: list of XOR-encrypted blocks
            
        Returns:
            Decrypted message (bytes)
        """
        # Decrypt r using RSA private key
        r = self.private_key.decrypt(
            encrypted_r,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Decrypt each block: message_block_i = H(i, r) ⊕ cipher_block_i
        decrypted_message = b''
        for i, cipher_block in enumerate(encrypted_blocks):
            # Compute H(i, r)
            hash_value = self._hash(i, r)
            
            # XOR to recover message block
            message_block = bytes(
                a ^ b for a, b in zip(cipher_block, hash_value[:len(cipher_block)])
            )
            decrypted_message += message_block
        
        return decrypted_message
    
    def encrypt_file(self, input_file):
        """Encrypt a file"""
        with open(input_file, 'rb') as f:
            message = f.read()
        
        encrypted_r, encrypted_blocks = self.encrypt(message)
        
        # Save encrypted data
        output_file = input_file + '.enc'
        with open(output_file, 'wb') as f:
            # Save encrypted_r length and value
            f.write(len(encrypted_r).to_bytes(4, 'big'))
            f.write(encrypted_r)
            
            # Save number of blocks
            f.write(len(encrypted_blocks).to_bytes(4, 'big'))
            
            # Save each block
            for block in encrypted_blocks:
                f.write(block)
        
        return output_file
    
    def decrypt_file(self, encrypted_file):
        """Decrypt a file"""
        with open(encrypted_file, 'rb') as f:
            # Read encrypted_r
            r_len = int.from_bytes(f.read(4), 'big')
            encrypted_r = f.read(r_len)
            
            # Read number of blocks
            num_blocks = int.from_bytes(f.read(4), 'big')
            
            # Read each block
            encrypted_blocks = []
            for _ in range(num_blocks):
                # Read block (32 bytes each except possibly last)
                # For simplicity, we need to know block sizes
                pass  # Would need to store block sizes in file
            
            # Alternative: read remaining data and split into 32-byte blocks
            remaining = f.read()
            encrypted_blocks = [
                remaining[i:i+32] for i in range(0, len(remaining), 32)
            ]
        
        return self.decrypt(encrypted_r, encrypted_blocks)

# Benchmark function
def benchmark_construction():
    """
    Measure execution time for files generated in point A
    """
    rsa_cipher = SecureRSAHybrid(key_size=2048)
    
    # File sizes from point A (adjust as needed)
    file_sizes = [1024, 10240, 102400, 1048576]  # 1KB, 10KB, 100KB, 1MB
    
    print("=" * 80)
    print("RSA Hybrid Construction Benchmark (2048-bit, SHA256)")
    print("Construction: Enc(m; r) = (RSA(r), H(0,r)⊕m₀, ..., H(n,r)⊕mₙ)")
    print("=" * 80)
    
    results = []
    
    for size in file_sizes:
        # Create test file
        filename = f'test_file_{size}.bin'
        with open(filename, 'wb') as f:
            f.write(os.urandom(size))
        
        print(f"\n📁 File: {filename} ({size:,} bytes / {size/1024:.2f} KB)")
        print("-" * 60)
        
        # Measure encryption time
        def encrypt_test():
            return rsa_cipher.encrypt_file(filename)
        
        # Run multiple times for average
        num_runs = 10
        encrypt_times = []
        for _ in range(num_runs):
            time_taken = timeit.timeit(encrypt_test, number=1)
            encrypt_times.append(time_taken)
        
        avg_encrypt = sum(encrypt_times) / num_runs
        
        # Get sample for decryption test
        enc_file = rsa_cipher.encrypt_file(filename)
        
        # Measure decryption time
        def decrypt_test():
            return rsa_cipher.decrypt_file(enc_file)
        
        decrypt_times = []
        for _ in range(num_runs):
            time_taken = timeit.timeit(decrypt_test, number=1)
            decrypt_times.append(time_taken)
        
        avg_decrypt = sum(decrypt_times) / num_runs
        
        # Calculate throughput
        encrypt_throughput = size / avg_encrypt / 1024  # KB/s
        decrypt_throughput = size / avg_decrypt / 1024  # KB/s
        
        results.append({
            'size': size,
            'encrypt_time': avg_encrypt * 1000,  # ms
            'decrypt_time': avg_decrypt * 1000,  # ms
            'encrypt_throughput': encrypt_throughput,
            'decrypt_throughput': decrypt_throughput
        })
        
        print(f"   Encryption: {avg_encrypt*1000:.4f} ms avg")
        print(f"   Decryption: {avg_decrypt*1000:.4f} ms avg")
        print(f"   Encrypt throughput: {encrypt_throughput:.2f} KB/s")
        print(f"   Decrypt throughput: {decrypt_throughput:.2f} KB/s")
        
        # Verify correctness
        decrypted = rsa_cipher.decrypt_file(enc_file)
        with open(filename, 'rb') as f:
            original = f.read()
        
        if decrypted == original:
            print(f"   ✅ Verification: PASSED")
        else:
            print(f"   ❌ Verification: FAILED")
    
    # Print summary
    print("\n" + "=" * 80)
    print("SUMMARY")
    print("=" * 80)
    print(f"{'File Size':<15} {'Encrypt (ms)':<15} {'Decrypt (ms)':<15} {'Encrypt (KB/s)':<15}")
    print("-" * 60)
    for r in results:
        print(f"{r['size']:<15,} {r['encrypt_time']:<15.4f} {r['decrypt_time']:<15.4f} {r['encrypt_throughput']:<15.2f}")
    
    return results

if __name__ == "__main__":
    results = benchmark_construction()