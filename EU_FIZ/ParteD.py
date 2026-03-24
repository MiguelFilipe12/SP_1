import hashlib
import os
import time

# Tamanhos dos ficheiros dados em A
file_sizes = [8, 64, 512, 4096, 32768, 262144, 2097152]

for size in file_sizes:
    # Cria dados aleatórios
    data = os.urandom(size)
    
    # Mede a duração do hash
    start = time.perf_counter()
    hash_result = hashlib.sha256(data).hexdigest()
    end = time.perf_counter()
    
    time_ms = (end - start) * 1000
    
    print(f"{size:>8} bytes ({size/1024:>5.1f} KB): {time_ms:.4f} ms")
    print(f"  Hash: {hash_result[:32]}...")
