#!/usr/bin/env python3
import socket
import re
import binascii
import base64
import sys

HOST = "103.185.52.197"
PORT = 3254

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))

def recv_until(pat=b"\n"):
    data = b""
    while pat not in data:
        c = s.recv(1)
        if not c:
            break
        data += c
    return data

def read_initial():
    data = b""
    s.settimeout(1.0)
    try:
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
    except socket.timeout:
        pass
    s.settimeout(None)
    return data

def oracle(iv, ct):
    # Kirim ciphertext ke oracle
    payload = iv.hex() + ct.hex()
    s.send((payload + "\n").encode())
    resp = recv_until(b"\n").decode().lower()

    # Sesuaikan kata kunci valid/invalid dari server
    return any(k in resp for k in ["valid", "benar", "ok", "success", "true"])

def decrypt_block(prev, block):
    n = len(block)
    inter = [0] * n
    plain = [0] * n

    for pad in range(1, n + 1):
        pos = n - pad
        found = False

        for guess in range(256):
            test_iv = bytearray(prev)

            for j in range(pos, n):
                if j == pos:
                    test_iv[j] = guess
                else:
                    test_iv[j] = inter[j] ^ pad

            if oracle(bytes(test_iv), block):
                inter[pos] = guess ^ pad
                plain[pos] = inter[pos] ^ prev[pos]
                found = True
                break

        if not found:
            raise Exception(f"Gagal di pad {pad}, pos {pos}")

    return bytes(plain)

def main():
    data = read_initial()
    print("=== SERVER OUTPUT ===")
    print(data.decode(errors="ignore"))

    # Cari hex ciphertext
    hex_match = re.search(b"[0-9a-fA-F]{32,}", data)

    if not hex_match:
        print("Tidak ditemukan hex ciphertext.")
        print("Kirim output server ke saya biar dibantu.")
        return

    raw = bytes.fromhex(hex_match.group(0).decode())

    if len(raw) < 32:
        print("Ciphertext terlalu pendek.")
        return

    iv = raw[:16]
    ct = raw[16:]

    if len(ct) % 16 != 0:
        print("Ciphertext tidak kelipatan 16, mungkin format beda.")
        return

    blocks = [ct[i:i+16] for i in range(0, len(ct), 16)]
    plain_blocks = []

    prev = iv
    for i, block in enumerate(blocks):
        print(f"[*] Decrypt block {i+1}/{len(blocks)}")
        p = decrypt_block(prev, block)
        plain_blocks.append(p)
        prev = block

    plaintext = b"".join(plain_blocks)

    # Hapus padding PKCS#7
    pad = plaintext[-1]
    if 1 <= pad <= 16:
        plaintext = plaintext[:-pad]

    print("\n[+] Plaintext:")
    print(plaintext.decode(errors="replace"))

if __name__ == "__main__":
    main()
