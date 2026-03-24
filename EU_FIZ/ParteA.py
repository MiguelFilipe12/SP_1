import os

def generate_files(sizes, do=False):
    """
    Gera ficheiros com os tamanhos dados
    Passar do=True para imprimir os primeiros 20 bytes gerados
    """
    
    for size in sizes:
        nome_file = f'file_{size}.txt'
        dados = os.urandom(size)
        
        with open(nome_file, 'wb') as f:
            f.write(dados)
        
        if do: 
            print(f"\n{nome_file} ({size} bytes):")
            print(f"  Bytes: {dados[:100]}")  # Primeiros 64 caracteres

size_list = [8, 64, 512, 4096, 32768, 262144, 2097152]
generate_files(size_list, True)
