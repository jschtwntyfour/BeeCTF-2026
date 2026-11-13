import subprocess

# Daftar tebakan awal (termasuk hex dan tahun film)
guesses = [
    "0x12c", "12c", "300", "0x300",
    "6868530F5C540A48", "480A545C0F536868", 
    "0x6868530F5C540A48", "0x480A545C0F536868",
    "1985", "1955", "2015", "88", "121"
]

# Tambahkan semua angka desimal 0 - 100000
for i in range(100000):
    guesses.append(str(i))

print(f"Mulai ngebrute force total {len(guesses)} percobaan...")

for idx, val in enumerate(guesses):
    # Print progress setiap 1000 percobaan biar tau masih jalan
    if idx % 1000 == 0:
        print(f"[*] Lagi nyoba... {idx} / {len(guesses)} (Current guess: {val})")

    input_data = f"1.21\n300\n{val}\n".encode()
    
    try:
        # timeout 2 detik biar nggak nge-hang
        result = subprocess.run(['./chall'], input=input_data, capture_output=True, timeout=2)
        out = result.stdout.decode(errors='ignore')

        # Kalau output TIDAK mengandung "Temporal Hash Mismatch", berarti KETEMU!
        if "Temporal Hash Mismatch" not in out:
            print("\n=========================================")
            print(f"🎉 HASH KETEMU! Nilainya: {val}")
            print("=========================================")
            print(out)
            break
    except subprocess.TimeoutExpired:
        # Program ke-hang, lanjut aja ke tebakan berikutnya
        continue
else:
    print("Yah, ga ketemu di 100000 angka. Mungkin hash-nya bukan angka bulat, tapi string tertentu.")
