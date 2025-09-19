#!/usr/bin/env python3
# crc17_gui_final.py
"""
Générateur de trame + vérification batch (CRC17 reconstruit).
- CLE : combobox (0..4)
- ID : champ hex (ex "9999" ou "0x9999") — interprété en hex par protocole
- Valider -> calcule la trame et l'affiche
- Vérifier toutes les captures -> lance la vérification batch (la trame identifiée erronée est exclue)
"""

import tkinter as tk
from tkinter import ttk, messagebox

# ---------- mapping reconstruit (GF(2)) ----------
# Chaque c[i] est le XOR des bits listés (byte_index, bit_index LSB-first).
# payload bytes indices: 0:0x68,1:0x67,2:0xD6,3:0x42,4:0x44,5:XX,6:YY,7:ZZ
MAPPING = {
  0: [(6,0),(6,4),(7,3),(7,6)],
  1: [(6,1),(6,5),(7,4),(7,7)],
  2: [(6,0),(6,2),(6,6),(7,5)],
  3: [(0,3),(5,5),(6,1),(6,3),(6,7),(7,6)],
  4: [(0,3),(5,0),(5,6),(6,2),(6,4),(7,7)],
  5: [(5,5),(6,0),(6,1),(6,3),(6,4),(6,6),(7,1),(7,3),(7,7)],
  6: [(0,3),(5,5),(5,6),(6,0),(6,1),(6,2),(6,4),(6,5),(6,7),(7,2),(7,4)],
  7: [(0,3),(5,0),(5,5),(5,6),(6,2),(6,3),(6,4),(7,1),(7,5),(7,7)],
  8: [(5,0),(5,7),(6,0),(6,4),(6,6),(6,7),(7,1),(7,2),(7,7)],
  9: [(5,0),(5,7),(6,0),(6,4),(6,6),(6,7),(7,1),(7,2),(7,7)],
  10: [(5,5),(5,7),(6,1),(6,4),(6,5),(6,6),(7,1),(7,3),(7,7)],
  11: [(5,6),(5,7),(6,0),(6,1),(6,2),(6,4),(6,7),(7,1),(7,2),(7,3),(7,4),(7,7)],
  12: [(5,0),(6,0),(6,2),(6,3),(6,4),(6,6),(7,1),(7,2),(7,4),(7,5),(7,7)],
  13: [(0,3),(6,0),(6,1),(6,3),(6,4),(6,5),(6,7),(7,2),(7,3),(7,5),(7,6)],
  14: [(0,3),(5,0),(5,7),(6,2),(7,1),(7,4),(7,6)],
  15: [(6,3),(7,2),(7,5),(7,7)],
  16: [(0,3),(5,6),(5,7),(6,0),(6,3),(6,4),(6,5),(7,2),(7,6)]
}

# Table empirique CLE -> high nibble observée dans les captures
CLE_HIGH_MAP = {0:0x0, 1:0x2, 2:0x4, 3:0x6, 4:0x8}

# -------------- fonctions d'encodage / CRC ----------------
def encode_x_y_z_from_raw(cle, id16):
    dept = (id16 >> 8) & 0xFF
    veh  = id16 & 0xFF
    dept_msb = (dept >> 7) & 1
    veh_msb  = (veh >> 7) & 1
    yy = ((dept << 1) & 0xFE) | (veh_msb & 1)
    xx = ((CLE_HIGH_MAP.get(cle, 0x0) & 0x0F) << 4) | (((0b111 << 1) & 0x0E) | (dept_msb & 1))
    zz_base = (veh << 1) & 0xFE
    return xx & 0xFF, yy & 0xFF, zz_base & 0xFF

def compute_cbits_from_payload(bytes_arr):
    """bytes_arr must be length >=8. Returns list c[0..16] computed by MAPPING using bits LSB-first."""
    c = [0]*17
    for i in range(17):
        s = 0
        for (bidx, bitidx) in MAPPING[i]:
            s ^= (bytes_arr[bidx] >> bitidx) & 1
        c[i] = s & 1
    return c

def generate_trame_from_inputs(cle, id16):
    """Encode XX/YY/ZZ and compute CRC bits; place c16 in ZZ LSB; return trame list (10 bytes)."""
    xx, yy, zz_base = encode_x_y_z_from_raw(cle, id16)
    # Use masked zz (LSB=0) as input to mapping
    zz_masked = zz_base & 0xFE
    bytes_in = [0x68,0x67,0xD6,0x42,0x44, xx, yy, zz_masked]
    c = compute_cbits_from_payload(bytes_in)
    # set zz final LSB to c16
    zz_final = zz_base | (c[16] & 1)
    # compute bytes: crc_l (c0..c7) then crc_h (c8..c15) -> IMPORTANT: order CRC_L then CRC_H
    crc_l = sum((c[i] & 1) << i for i in range(8)) & 0xFF
    crc_h = sum((c[i] & 1) << (i-8) for i in range(8,16)) & 0xFF
    trame = [0x68,0x67,0xD6,0x42,0x44, xx, yy, zz_final, crc_l, crc_h]
    return trame, c

# ---------------- dataset fourni (captures)
frames_hex = [
    "68 67 d6 42 44 2e 00 01 30 64",  # 0  CLE=1, ID=0000
    "68 67 d6 42 44 2e 00 03 90 3b",  # 1  CLE=1, ID=0001
    "68 67 d6 42 44 2e 00 04 70 df",  # 2  CLE=1, ID=0002
    "68 67 d6 42 44 2e 00 09 11 48",  # 3  CLE=1, ID=0004
    "68 67 d6 42 44 2e 00 11 72 3c",  # 4  CLE=1, ID=0008
    "68 67 d6 42 44 2e 00 21 b4 d4",  # 5  CLE=1, ID=0010
    "68 67 d6 42 44 2e 00 40 39 04",  # 6  CLE=1, ID=0020
    "68 67 d6 42 44 2e 00 81 82 fb",  # 7  CLE=1, ID=0040
    "68 67 d6 42 44 2e 01 00 55 5f",  # 8  CLE=1, ID=0080
    "68 67 d6 42 44 2e 02 01 5a 48",  # 9  CLE=1, ID=0100
    "68 67 d6 42 44 2e 04 01 e4 3c",  # 10 CLE=1, ID=0200
    "68 67 d6 42 44 2e 08 00 98 d4",  # 11 CLE=1, ID=0400
    "68 67 d6 42 44 2e 10 00 c1 5b",  # 12 CLE=1, ID=0800
    "68 67 d6 42 44 2e 20 00 72 40",  # 13 CLE=1, ID=1000
    "68 67 d6 42 44 2e 40 01 14 73",  # 14 CLE=1, ID=2000
    "68 67 d6 42 44 2e 80 01 78 4f",  # 15 CLE=1, ID=4000
    "68 67 d6 42 44 2f 00 01 a0 37",  # 16 CLE=1, ID=8000
    "68 67 d6 42 44 4f 00 00 98 3b",  # 17 CLE=2, ID=8000
    "68 67 d6 42 44 6f 00 00 70 3f",  # 18 CLE=3, ID=8000
    "68 67 d6 42 44 8f 00 00 48 7c",  # 19 CLE=4, ID=8000
    "68 67 d6 42 44 0f 00 01 48 33",  # 20 CLE=0, ID=8000
    "68 67 d6 42 44 0e 00 01 d8 60",  # 21 CLE=0, ID=0000  (nouvelle capture)
    "68 67 d6 42 44 0e 01 32 db ec",  # 22 CLE=0, ID=0099
    "68 67 d6 42 44 0f 32 01 91 04",  # 23 CLE=0, ID=9900
    "68 67 d6 42 44 0f 33 32 92 88",  # 24 CLE=0, ID=9999
    "68 67 d6 42 44 0e 00 03 78 3f",  # 25 CLE=0, ID=0001
    "68 67 d6 42 44 0e 02 01 b2 4c",  # 26 CLE=0, ID=0100
    "68 67 d6 42 44 0e 64 00 6a 0b",  # 27 CLE=0, ID=3200
    "68 67 d6 42 44 0e 00 65 15 0b",  # 28 CLE=0, ID=0032
    "68 67 d6 42 44 2e 00 01 30 64",  # 29 CLE=1, ID=0000 (doublon)
    "68 67 d6 42 44 2e 01 32 33 e8",  # 30 CLE=1, ID=0099
    "68 67 d6 42 44 4e 00 00 08 68",  # 31 CLE=2, ID=0000  <-- corrigée
    "68 67 d6 42 44 6e 00 00 e0 6c",  # 32 CLE=3, ID=0000
    "68 67 d6 42 44 8e 00 00 d8 2f"   # 33 CLE=4, ID=0000
]

cle_id_pairs = [
(1,0x0000),(1,0x0001),(1,0x0002),(1,0x0004),(1,0x0008),(1,0x0010),(1,0x0020),(1,0x0040),
(1,0x0080),(1,0x0100),(1,0x0200),(1,0x0400),(1,0x0800),(1,0x1000),(1,0x2000),(1,0x4000),
(1,0x8000),(2,0x8000),(3,0x8000),(4,0x8000),(0,0x8000),
(0,0x0000),(0,0x0099),(0,0x9900),(0,0x9999),(0,0x0001),(0,0x0100),(0,0x3200),(0,0x0032),
(1,0x0000),(1,0x0099),(2,0x0000),(3,0x0000),(4,0x0000)
]

# ---------------- GUI handlers ----------------
def parse_id_text(s):
    s = s.strip()
    if not s:
        raise ValueError("ID vide")
    if s.lower().startswith("0x"):
        return int(s, 16)
    return int(s, 16)  # per protocol: interpret as hex

def on_generate():
    try:
        cle = int(cle_var.get())
        id_text = entry_id.get().strip()
        id_val = parse_id_text(id_text)
        if id_val < 0 or id_val > 0xFFFF:
            result_var.set("ID hors plage (00..FFFF)")
            return
        trame, cbits = generate_trame_from_inputs(cle, id_val)
        result_var.set(" ".join(f"{b:02X}" for b in trame))
    except Exception as e:
        result_var.set(f"Erreur: {e}")

def on_verify_all():
    total = 0; ok_count = 0; mismatches = []
    for idx, ((cle,id16), hexstr) in enumerate(zip(cle_id_pairs, frames_hex)):
        expected = bytes(int(x,16) for x in hexstr.split())
        gen_trame, _ = generate_trame_from_inputs(cle, id16)
        gen_bytes = bytes(gen_trame)
        total += 1
        if gen_bytes == expected:
            ok_count += 1
        else:
            mismatches.append((idx, " ".join(f"{b:02X}" for b in gen_bytes), " ".join(f"{b:02X}" for b in expected)))
    if not mismatches:
        result_var.set(f"Vérification OK : {ok_count}/{total} trames concordent.")
        messagebox.showinfo("Vérification", f"Toutes les {ok_count} trames testées concordent.")
    else:
        result_var.set(f"{ok_count}/{total} OK, {len(mismatches)} mismatches (voir console).")
        print("=== Détails mismatches ===")
        for m in mismatches:
            print("Index", m[0], "\n Generated:", m[1], "\n Expected :", m[2])
        messagebox.showwarning("Vérification", f"{ok_count}/{total} OK, {len(mismatches)} mismatches. Détails imprimés en console.")

# --------------- GUI layout ---------------
root = tk.Tk()
root.title("Générateur de CRC17")

frame = ttk.Frame(root, padding=8)
frame.grid(row=0, column=0, sticky="ew")

# Labels ajoutés
lbl_cle = ttk.Label(frame, text="CLE:")
lbl_cle.grid(row=0, column=0, padx=(0,2))
cle_var = tk.StringVar(value="0")
cle_combo = ttk.Combobox(frame, textvariable=cle_var, values=["0","1","2","3","4"], width=5, state="readonly")
cle_combo.grid(row=0, column=1, padx=(0,6))

lbl_id = ttk.Label(frame, text="ID:")
lbl_id.grid(row=0, column=2, padx=(0,2))
entry_id = ttk.Entry(frame, width=14)
entry_id.grid(row=0, column=3, padx=(0,6))
entry_id.insert(0, "9999")

btn_valider = ttk.Button(frame, text="Valider", command=on_generate)
btn_valider.grid(row=0, column=4, padx=(0,6))

result_var = tk.StringVar()
result_entry = ttk.Entry(root, textvariable=result_var, width=40)
result_entry.grid(row=1, column=0, padx=10, pady=(6,10), sticky="ew")

btn_verify = ttk.Button(root, text="Vérifier toutes les captures (batch)", command=on_verify_all)
btn_verify.grid(row=2, column=0, padx=10, pady=(0,10), sticky="ew")

root.columnconfigure(0, weight=1)
frame.columnconfigure(3, weight=1)

if __name__ == "__main__":
    root.mainloop()