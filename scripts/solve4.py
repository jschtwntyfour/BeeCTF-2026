import socket
import time

HOST = "103.185.52.197"
PORT = 3254
BLOCK_SIZE = 16

# Timeout dipangkas jadi 3 detik biar nggak nunggu lama
def recv_until(sock, marker, timeout=3):
    sock.settimeout(timeout)
    data = b''
    while marker not in data:
        try:
            chunk = sock.recv(4096)
            if not chunk: break
            data += chunk
        except socket.timeout:
            return data
    return data

def get_ciphertext(sock, payload):
    # Marker ">" TANPA spasi, jadi lebih fleksibel
    recv_until(sock, b'>') 
    sock.sendall(b'1\n')
    
    recv_until(sock, b'bumbu (hex):')
    sock.sendall(payload.hex().encode() + b'\n')
    
    data = recv_until(sock, b'cilok: ')
    try:
        ct_hex = data.split(b'cilok: ')[1].split(b'\n')[0].decode().strip()
        if len(ct_hex) % 2 != 0:
            ct_hex = '0' + ct_hex
        return bytes.fromhex(ct_hex)
    except Exception:
        return b''

def find_secret_length(sock):
    len0 = len(get_ciphertext(sock, b''))
    print(f"[*] Panjang ciphertext awal: {len0} bytes")
    for i in range(1, 200):
        ct = get_ciphertext(sock, b'A' * i)
        if len(ct) > len0:
            secret_len = len0 - i
            print(f"[*] Ketemu lompatan di prefix {i}, panjang secret: {secret_len}")
            return secret_len
    return None

def decrypt_secret(sock, secret_len):
    known_secret = b''
    for i in range(secret_len):
        block_index = i // BLOCK_SIZE
        offset = i % BLOCK_SIZE
        prefix_len = BLOCK_SIZE - 1 - offset
        
        payload = b'A' * prefix_len
        ct_target = get_ciphertext(sock, payload)
        target_block = ct_target[block_index * BLOCK_SIZE : (block_index + 1) * BLOCK_SIZE]
        
        found = False
        for g in range(256):
            guess_payload = payload + known_secret + bytes([g])
            ct_guess = get_ciphertext(sock, guess_payload)
            guess_block = ct_guess[block_index * BLOCK_SIZE : (block_index + 1) * BLOCK_SIZE]
            
            if guess_block == target_block:
                known_secret += bytes([g])
                char = chr(g) if 32 <= g <= 126 else '.'
                print(f"\r[+] Byte {i}/{secret_len}: {known_secret.decode(errors='ignore')}", end='', flush=True)
                found = True
                break
        
        if not found:
            print(f"\n[!] Gagal di byte {i}. Coba ulangi lagi.")
            break
            
    print()
    return known_secret

print(f"[*] Connecting to {HOST}:{PORT}...")
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(10)
s.connect((HOST, PORT))

# TANPA DOUBLE READ DI SINI
secret_len = find_secret_length(s)
if secret_len is None:
    print("[!] Gagal cari panjang secret.")
    exit()

print("[*] Mulai bongkar flag byte demi byte... (Ini bakal makan waktu 5-15 menit)")
secret = decrypt_secret(s, secret_len)

print("\n" + "="*50)
print("[*] RESEP RAHASIA (FLAG):")
print(secret.decode(errors='ignore'))
print("="*50)

s.close()
