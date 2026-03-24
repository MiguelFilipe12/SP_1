import os
import hashlib
import math
import timeit
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

class SecureRSAHybrid:
    """
    Implementa a função de encriptação dada: Enc(m; r) = (RSA(r), H(0,r)⊕m₀, ..., H(n,r)⊕mₙ)
    com H = SHA256
    """
    
    def __init__(self, key_size=2048):
        # Gera par de chaves RSA
        self.private_key = rsa.generate_private_key(
            public_exponent=65537, # Valor padrão
            key_size=key_size
        )
        self.public_key = self.private_key.public_key()
        self.hash_size = 32  # SHA256 tem 32 bytes de output
        self.key_size = key_size
    
    def _hash(self, block_index, r):
        """
        H(block_index, r) com SHA256
        
        Argumentos:
            block_index: Número do bloco
            r: random seed
        
        Retorna hash value de 32 bytes
        """
        # Converte indíce do bloco para bytes
        index_bytes = block_index.to_bytes(8, byteorder='big')
        # Faz hash na combinação
        return hashlib.sha256(index_bytes + r).digest()
    
    def encrypt(self, message):
        """
        Encripta a mensagem
        
        Argumentos:
            message: bytes a encriptar
            
        Retorna:
            (encrypted_r, encrypted_blocks)
            - encrypted_r: random seed encriptada com RSA
            - encrypted_blocks: lista de blocos encriptados com XOR
        """
        max_r_size = (self.key_size // 8) - 2 * 32 - 2
        r = os.urandom(max_r_size)
        
        # Encripta r com chave pública de RSA
        encrypted_r = self.public_key.encrypt(
            r,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Calcula o número de blocos: n = ⌈|m|/ℓ⌉
        n = math.ceil(len(message) / self.hash_size)
        
        # Encripta cada bloco
        encrypted_blocks = []
        for i in range(n):
            # Extrai o bloco da mensagem
            start = i * self.hash_size
            end = min(start + self.hash_size, len(message))
            message_block = message[start:end]
            
            # H(i, r)
            hash_value = self._hash(i, r)
            
            # XOR com hash
            cipher_block = bytes(
                a ^ b for a, b in zip(message_block, hash_value[:len(message_block)])
            )
            encrypted_blocks.append(cipher_block)
        
        return encrypted_r, encrypted_blocks
    
    def decrypt(self, encrypted_r, encrypted_blocks):
        """
        Decripta mensagens encriptadas com o método anterior
        
        Argumentoss:
            encrypted_r: Random seed encriptada com RSA
            encrypted_blocks: lista de blocos encriptados com XOR
            
        Retorna:
            Mensagem decriptada
        """
        # Decripta r usando chave privada de RSA
        r = self.private_key.decrypt(
            encrypted_r,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Decripta cada bloco
        decrypted_message = b''
        for i, cipher_block in enumerate(encrypted_blocks):
            hash_value = self._hash(i, r)
            
            # XOR para recuperar o bloco da mensagem
            message_block = bytes(
                a ^ b for a, b in zip(cipher_block, hash_value[:len(cipher_block)])
            )
            decrypted_message += message_block
        
        return decrypted_message
    
    def encrypt_file(self, input_file):
        """Encripta um ficheriro"""
        with open(input_file, 'rb') as f:
            message = f.read()
        
        encrypted_r, encrypted_blocks = self.encrypt(message)
        
        output_file = input_file + '.encriptado'
        with open(output_file, 'wb') as f:
            # Guarda comprimento encrypted_r e o valor
            f.write(len(encrypted_r).to_bytes(4, 'big'))
            f.write(encrypted_r)
            
            # Guarda o número de blocos
            f.write(len(encrypted_blocks).to_bytes(4, 'big'))
            
            for block in encrypted_blocks:
                f.write(block)
        
        return output_file
    
    def decrypt_file(self, encrypted_file):
        """Decripta um ficheiro"""
        with open(encrypted_file, 'rb') as f:
            r_len = int.from_bytes(f.read(4), 'big')
            encrypted_r = f.read(r_len)
            
            # Ler o número de blocos
            num_blocks = int.from_bytes(f.read(4), 'big')
            
            encrypted_blocks = []
            remaining = f.read()
            encrypted_blocks = [
                remaining[i:i+32] for i in range(0, len(remaining), 32)
            ]
        
        return self.decrypt(encrypted_r, encrypted_blocks)

def benchmark_construction():
    """
    Mede tempo de execução para ficheiros gerados na Parte A
    """
    rsa_cipher = SecureRSAHybrid(key_size=2048)
    
    file_sizes = [1024, 10240, 102400, 1048576]  
    
    results = []
    
    for size in file_sizes:
        filename = f'test_file_{size}.bin'
        with open(filename, 'wb') as f:
            f.write(os.urandom(size))
        
        # Mede tempo de encriptação
        def encrypt_test():
            return rsa_cipher.encrypt_file(filename)
        
        num_runs = 10
        encrypt_times = []
        for _ in range(num_runs):
            time_taken = timeit.timeit(encrypt_test, number=1)
            encrypt_times.append(time_taken)
        
        avg_encrypt = sum(encrypt_times) / num_runs
        
        # Amostra para teste de decriptação
        enc_file = rsa_cipher.encrypt_file(filename)
        
        # Mede tempo de decriptação
        def decrypt_test():
            return rsa_cipher.decrypt_file(enc_file)
        
        decrypt_times = []
        for _ in range(num_runs):
            time_taken = timeit.timeit(decrypt_test, number=1)
            decrypt_times.append(time_taken)
        
        avg_decrypt = sum(decrypt_times) / num_runs
        
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
        
    print(f"{'File Size':<15} {'Encrypt (ms)':<15} {'Decrypt (ms)':<15} {'Encrypt (KB/s)':<15}")
    print("-" * 60)
    for r in results:
        print(f"{r['size']:<15,} {r['encrypt_time']:<15.4f} {r['decrypt_time']:<15.4f} {r['encrypt_throughput']:<15.2f}")
    
    return results

if __name__ == "__main__":
    results = benchmark_construction()
