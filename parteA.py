import os

def generate_files (sizes):
    for size in sizes:
        nome_file = f'file_{size}.txt'
        
        with open(nome_file, 'wb') as f:
            f.write(os.urandom(size))


size_list = [8, 64, 512, 4096, 32768, 262144, 2097152]
generate_files(size_list)
