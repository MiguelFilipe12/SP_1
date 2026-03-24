import hashlib
import os
import time

# File sizes (adjust as needed)
file_sizes = [8, 64, 512, 4096, 32768, 262144, 2097152]

print("SHA-256 HASH TIME MEASUREMENT")
print("=" * 50)

for size in file_sizes:
    # Create random data
    data = os.urandom(size)
    
    # Time the hash
    start = time.perf_counter()
    hash_result = hashlib.sha256(data).hexdigest()
    end = time.perf_counter()
    
    time_ms = (end - start) * 1000
    
    print(f"{size:>8} bytes ({size/1024:>5.1f} KB): {time_ms:.4f} ms")
    print(f"  Hash: {hash_result[:32]}...")