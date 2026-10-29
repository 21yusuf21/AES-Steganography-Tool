"""
Doku-Uyarlamalı (Content-Adaptive) DCT-QIM Steganografi  —  v2
================================================================
* Veri yalnızca MAVİ (B) kanalın 8x8 DCT bloklarına (2 orta frekans katsayısı) gömülür.
* "Karışık / dokulu" bölge skoru, HİÇ DEĞİŞTİRİLMEYEN R ve G kanallarından hesaplanır
  → çözücü aynı doku haritasını stego görüntüde yeniden üretebilir.
* Bit → yuva eşlemesi şifreden türetilen SABİT bir haritadır (doku seçimi buna karışmaz).
  Kodlayıcı her bitin yuvalarından yalnızca dokulu olanlara gömer, düz bloklara dokunmaz.
  Çözücü doku ağırlıklı yumuşak oylama yapar: düz blokların oyu ≈ 0.
  Böylece doku skoru biraz değişse bile (gürültü vb.) senkronizasyon kaybolmaz.
* Şifreleme: PBKDF2 (200k iterasyon, tuzlu) + AES-256-GCM (kimlik doğrulamalı).

Gereksinimler: pip install opencv-python numpy pycryptodome
"""

import os
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext

import cv2
import numpy as np
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes

# ==========================================
# AYARLAR
# ==========================================
BLOCK = 8
COEFS = [(4, 1), (1, 4)]   # Blok başına kullanılan orta frekans katsayıları (satır, sütun)
SLOTS_PER_BIT = 3          # Her bit için ayrılan (blok, katsayı) yuvası sayısı
TEXTURE_PERCENTILE = 50    # Skoru bu yüzdeliğin altındaki bloklara normalde DOKUNULMAZ
Q_STEP = 24.0              # QIM kuantizasyon adımı (sadece dokulu bloklara uygulanır)
MIN_MARGIN = 0.6           # Kodlayıcının istediği en düşük ağırlıklı oy farkı
HEADER_BITS = 32           # Yük uzunluğu (bit) başlığı
KDF_ITER = 200_000
MAP_SALT = b"stego-dct-map-v2"
SALT_LEN, NONCE_LEN, TAG_LEN = 16, 12, 16
OVERHEAD = SALT_LEN + NONCE_LEN + TAG_LEN


# ==========================================
# 1) DOSYA G/Ç (Unicode güvenli)
# ==========================================
def read_image_unicode(path):
    """Türkçe karakterli yollarda da çalışır. Her zaman 8-bit BGR döndürür."""
    try:
        data = np.fromfile(path, dtype=np.uint8)
        return cv2.imdecode(data, cv2.IMREAD_COLOR)   # alfa/16-bit/gri → 3 kanal 8-bit
    except Exception as e:
        print(f"Image Read Error: {e}")
        return None


def save_image_unicode(path, img):
    ext = os.path.splitext(path)[1].lower()
    if ext not in (".png", ".bmp", ".tif", ".tiff"):
        raise ValueError("Stego görüntü kayıpsız formatta (PNG/BMP/TIFF) kaydedilmeli; "
                         "JPEG sıkıştırması gömülü veriyi bozar.")
    ok, buf = cv2.imencode(ext, img)
    if ok:
        buf.tofile(path)
    return ok


# ==========================================
# 2) KRİPTO  (PBKDF2 + AES-256-GCM)
# ==========================================
def _kdf(password, salt, n=32, it=KDF_ITER):
    return PBKDF2(password, salt, dkLen=n, count=it, hmac_hash_module=SHA256)


def encrypt_payload(plain_text, password):
    """Çıktı: salt | nonce | tag | ciphertext"""
    salt, nonce = get_random_bytes(SALT_LEN), get_random_bytes(NONCE_LEN)
    cipher = AES.new(_kdf(password, salt), AES.MODE_GCM, nonce=nonce)
    ct, tag = cipher.encrypt_and_digest(plain_text.encode("utf-8"))
    return salt + nonce + tag + ct


def decrypt_payload(blob, password):
    if len(blob) < OVERHEAD:
        return None
    salt, nonce = blob[:SALT_LEN], blob[SALT_LEN:SALT_LEN + NONCE_LEN]
    tag, ct = blob[SALT_LEN + NONCE_LEN:OVERHEAD], blob[OVERHEAD:]
    try:
        cipher = AES.new(_kdf(password, salt), AES.MODE_GCM, nonce=nonce)
        return cipher.decrypt_and_verify(ct, tag).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return None


# ==========================================
# 3) DOKU HARİTASI
# ==========================================
def block_texture(img):
    """
    Her 8x8 blok için 'karmaşıklık' skoru. SADECE R ve G kanalları kullanılır
    (veri B kanalına gömüldüğü için R,G stego görüntüde aynen kalır).

        skor = std(G) + std(R) + std(R - G)
               └ parlaklık dokusu ┘   └ renk karışıklığı
    """
    h, w = img.shape[:2]
    bh, bw = h // BLOCK, w // BLOCK
    crop = img[:bh * BLOCK, :bw * BLOCK].astype(np.float32)
    G, R = crop[:, :, 1], crop[:, :, 2]

    def blocks(ch):
        return ch.reshape(bh, BLOCK, bw, BLOCK).swapaxes(1, 2)

    g, r = blocks(G), blocks(R)
    score = (g.std(axis=(2, 3)) + r.std(axis=(2, 3)) + (r - g).std(axis=(2, 3))).reshape(-1)
    return score, bw


def texture_params(score):
    """Eşik T, her blok için oy ağırlığı w ve kuantizasyon adımı Q."""
    T = max(float(np.percentile(score, TEXTURE_PERCENTILE)), 1.0)
    rel = score / T
    w = np.where(rel >= 1.0, 1.0, rel ** 4)            # düz blokların oyu ≈ 0
    q = np.full(score.shape, Q_STEP)
    return T, w, q


def slot_map(n_blocks, password):
    """
    Şifreden türetilmiş SABİT yuva haritası: (blok, katsayı) çiftlerinin karışık sırası.
    Doku haritasından bağımsız olduğu için gürültü vs. senkronizasyonu bozamaz.
    """
    seed = _kdf(password, MAP_SALT, n=16, it=KDF_ITER // 4)
    rng = np.random.default_rng(int.from_bytes(seed, "big"))
    slots = np.arange(n_blocks * len(COEFS))
    rng.shuffle(slots)
    return slots   # slot -> blok = s // len(COEFS), katsayı = COEFS[s % len(COEFS)]


# ==========================================
# 3b) HATA DÜZELTME: Hamming(7,4)  — her 7 bitlik kod sözcüğünde 1 hatayı düzeltir
# ==========================================
_G = np.array([[1,1,0,1],[1,0,1,1],[1,0,0,0],[0,1,1,1],[0,1,0,0],[0,0,1,0],[0,0,0,1]], np.uint8)
_H = np.array([[1,0,1,0,1,0,1],[0,1,1,0,0,1,1],[0,0,0,1,1,1,1]], np.uint8)
_DATA_POS = [2, 4, 5, 6]


def hamming_encode(bits):
    bits = np.concatenate([bits, np.zeros((-len(bits)) % 4, np.uint8)])
    return (bits.reshape(-1, 4) @ _G.T % 2).astype(np.uint8).ravel()


def hamming_decode(code):
    c = code.reshape(-1, 7).copy()
    syn = (c @ _H.T % 2) @ np.array([1, 2, 4])          # hatalı bitin konumu (1..7), 0 = hata yok
    rows = np.where(syn > 0)[0]
    c[rows, syn[rows] - 1] ^= 1
    return c[:, _DATA_POS].ravel()


def coded_len(n_bits):
    return -(-n_bits // 4) * 7


# ==========================================
# 4) QIM
# ==========================================
def _qim_embed(c, bit, q):
    if bit == 0:
        return np.round(c / q) * q
    return np.round((c - q / 2) / q) * q + q / 2


def _qim_detect(c, q):
    d0 = abs(c - np.round(c / q) * q)
    d1 = abs(c - (np.round((c - q / 2) / q) * q + q / 2))
    return 1 if d1 < d0 else 0


def _block_xy(b, bw):
    return (b // bw) * BLOCK, (b % bw) * BLOCK


def _detect_slot(chan, s, bw, q):
    b, k = divmod(int(s), len(COEFS))
    y, x = _block_xy(b, bw)
    u, v = COEFS[k]
    return _qim_detect(cv2.dct(chan[y:y + BLOCK, x:x + BLOCK].astype(np.float32))[u, v], q[b])


def _read_bit(chan, row, bw, w, q):
    """Doku ağırlıklı yumuşak oylama. Düz (dokunulmamış) blokların oyu neredeyse sıfır."""
    acc = 0.0
    for s in row:
        b = int(s) // len(COEFS)
        acc += w[b] * (1 if _detect_slot(chan, s, bw, q) else -1)
    return 1 if acc > 0 else 0


def _write_block(chan, b, bw, targets, q):
    """targets: {katsayı_indeksi: bit}. Bloğun tüm hedef katsayıları tek seferde yazılır."""
    y, x = _block_xy(b, bw)
    d = cv2.dct(chan[y:y + BLOCK, x:x + BLOCK].astype(np.float32))
    for k, bit in targets.items():
        u, v = COEFS[k]
        d[u, v] = _qim_embed(d[u, v], bit, q)
    out = np.clip(np.round(cv2.idct(d)), 0, 255)   # ← orijinal kodda eksikti (taşma hatası)
    chan[y:y + BLOCK, x:x + BLOCK] = out.astype(np.uint8)


# ==========================================
# 5) ENCODER / DECODER
# ==========================================
def capacity_bytes(img):
    n_slots = (img.shape[0] // BLOCK) * (img.shape[1] // BLOCK) * len(COEFS)
    raw_bits = (n_slots // SLOTS_PER_BIT) * 4 // 7 - HEADER_BITS
    return max(0, raw_bits // 8 - OVERHEAD)


def embed_bytes(img, blob, password):
    """Bellekte gömme. (stego, kullanılan_bloklar, istatistik) döndürür."""
    bits = np.unpackbits(np.frombuffer(blob, np.uint8))
    header = np.array([int(c) for c in format(bits.size, f"0{HEADER_BITS}b")], np.uint8)
    all_bits = hamming_encode(np.concatenate([header, bits]))

    score, bw = block_texture(img)
    T, w, q = texture_params(score)
    slots = slot_map(score.size, password)
    if all_bits.size * SLOTS_PER_BIT > slots.size:
        raise ValueError(f"Message is too long! Capacity ≈ {capacity_bytes(img)} bytes of text.")

    stego = img.copy()
    chan = stego[:, :, 0]                          # B kanalı
    plan = {}                                      # blok -> {katsayı: bit}
    forced = 0
    for i, bit in enumerate(all_bits):
        row = slots[i * SLOTS_PER_BIT:(i + 1) * SLOTS_PER_BIT]
        blocks = [int(s) // len(COEFS) for s in row]
        # 1) Dokulu yuvalara göm
        chosen = [j for j, b in enumerate(blocks) if score[b] >= T]
        # 2) Kodlayıcı, çözücünün ağırlıklı oyunu simüle eder; fark yetersizse
        #    kalan yuvaları en dokuludan başlayarak ekler (nadiren düz bloğa dokunur).
        rest = sorted(set(range(len(row))) - set(chosen), key=lambda j: -score[blocks[j]])
        while True:
            tot = sum(w[b] for b in blocks)
            agree = sum(w[blocks[j]] for j in chosen)
            for j in rest:                          # dokunulmayan yuvaların doğal oyu
                if j in chosen:
                    continue
                agree += w[blocks[j]] * (1 if _detect_slot(img[:, :, 0], row[j], bw, q) == bit else 0)
            margin = (2 * agree - tot) / tot if tot > 0 else -1
            if margin >= MIN_MARGIN or len(chosen) == len(row):
                break
            j = next(j for j in rest if j not in chosen)
            chosen.append(j)
            forced += score[blocks[j]] < T
        for j in chosen:
            b, k = divmod(int(row[j]), len(COEFS))
            plan.setdefault(b, {})[k] = int(bit)

    for b, targets in plan.items():
        _write_block(chan, b, bw, targets, q[b])

    return stego, np.array(sorted(plan)), {"used": len(plan), "total": score.size, "forced_flat": forced}


def extract_bytes(img, password):
    score, bw = block_texture(img)      # R,G değişmediği için aynı (veya çok yakın) harita
    _, w, q = texture_params(score)
    slots = slot_map(score.size, password)
    chan = img[:, :, 0]

    def bit_at(i):
        return _read_bit(chan, slots[i * SLOTS_PER_BIT:(i + 1) * SLOTS_PER_BIT], bw, w, q)

    hc = coded_len(HEADER_BITS)                       # başlık 4'ün katı → kendi kod sözcükleri
    header = hamming_decode(np.array([bit_at(i) for i in range(hc)], np.uint8))
    L = int("".join(map(str, header)), 2)
    total = coded_len(HEADER_BITS + L)
    if L < OVERHEAD * 8 or L % 8 or total * SLOTS_PER_BIT > slots.size:
        return None
    code = np.array([bit_at(i) for i in range(total)], np.uint8)
    bits = hamming_decode(code)[HEADER_BITS:HEADER_BITS + L]
    return np.packbits(bits).tobytes()


def embed_data(image_path, output_path, secret_text, password, map_path=None):
    img = read_image_unicode(image_path)
    if img is None:
        return f"ERROR: Could not read image!\nPath: {image_path}"
    try:
        stego, used, st = embed_bytes(img, encrypt_payload(secret_text, password), password)
    except ValueError as e:
        return f"ERROR: {e}"

    ok = extract_bytes(stego, password) is not None and \
        decrypt_payload(extract_bytes(stego, password), password) == secret_text
    if not save_image_unicode(output_path, stego):
        return f"ERROR: Could not save image!\nPath: {output_path}"
    if map_path:
        _, bw = block_texture(img)
        save_usage_map(img, used, bw, map_path)
    return (f"Success\nModified blocks: {st['used']}/{st['total']} "
            f"(%{100 * st['used'] / st['total']:.1f}); low-texture blocks touched: {st['forced_flat']}\n"
            f"Self-check: {'OK' if ok else 'FAILED'}")


def extract_data(image_path, password):
    img = read_image_unicode(image_path)
    if img is None:
        return f"ERROR: Could not read image!\nPath: {image_path}"
    blob = extract_bytes(img, password)
    if blob is None:
        return "ERROR: Wrong password or no hidden data in this image."
    result = decrypt_payload(blob, password)
    if result is None:
        return "ERROR: Authentication failed (wrong password or corrupted image)."
    return result


# ==========================================
# 6) GÖRSELLEŞTİRME (rapor/sunum için)
# ==========================================
def save_usage_map(img, used_idx, bw, path):
    """Değiştirilen blokları yeşil ile işaretleyen bindirme görüntüsü."""
    vis = (img.astype(np.float32) * 0.45).astype(np.uint8)
    for idx in np.unique(used_idx):
        y, x = (idx // bw) * BLOCK, (idx % bw) * BLOCK
        vis[y:y + BLOCK, x:x + BLOCK] = (0.5 * img[y:y + BLOCK, x:x + BLOCK]
                                         + 0.5 * np.array([0, 255, 0])).astype(np.uint8)
    ok, buf = cv2.imencode(".png", vis)
    if ok:
        buf.tofile(path)


def psnr(a, b):
    mse = np.mean((a.astype(np.float64) - b.astype(np.float64)) ** 2)
    return float("inf") if mse == 0 else 10 * np.log10(255 ** 2 / mse)


# ==========================================
# 7) GUI
# ==========================================
METER_COLORS = {"ok": "#2e7d32", "warn": "#f9a825", "over": "#c62828"}


def message_bytes(text):
    """Mesajın UTF-8 bayt sayısı (Türkçe harfler 2 bayt). run() ile aynı şekilde strip edilir."""
    return len(text.strip().encode("utf-8"))


def capacity_level(used, cap):
    """'ok' (<%80), 'warn' (%80-100), 'over' (sığmıyor)."""
    if used > cap:
        return "over"
    return "warn" if cap and used / cap >= 0.8 else "ok"


class CapacityMeter(tk.Frame):
    """Mesaj yazılırken canlı güncellenen kapasite çubuğu."""

    def __init__(self, master):
        super().__init__(master, bg="#252526")
        self.bar = tk.Canvas(self, height=12, bg="#333", highlightthickness=0)
        self.bar.pack(fill="x")
        self.label = tk.Label(self, text="", fg="#aaa", bg="#252526", font=("Arial", 9))
        self.label.pack(anchor="e")
        self.used = self.cap = None
        self.bar.bind("<Configure>", lambda e: self._draw())

    def update_meter(self, used, cap):
        """cap None ise henüz görüntü seçilmemiştir."""
        self.used, self.cap = used, cap
        if cap is None:
            self.label.config(text="Select an image to see its capacity", fg="#aaa")
        elif used > cap:
            self.label.config(text=f"{used} / {cap} bytes — {used - cap} bytes over the limit",
                              fg=METER_COLORS["over"])
        else:
            level = capacity_level(used, cap)
            self.label.config(text=f"{used} / {cap} bytes — {cap - used} left",
                              fg=METER_COLORS["warn"] if level == "warn" else "#aaa")
        self._draw()

    def _draw(self):
        self.bar.delete("all")
        if self.cap is None:
            return
        ratio = min(self.used / self.cap, 1.0) if self.cap else 1.0
        w, h = self.bar.winfo_width(), self.bar.winfo_height()
        self.bar.create_rectangle(0, 0, int(w * ratio), h, width=0,
                                  fill=METER_COLORS[capacity_level(self.used, self.cap)])


class StegoApp:
    def __init__(self, root):
        self.root = root
        self.root.title("AES Steganography Tool v2 (Texture-Adaptive)")
        self.root.geometry("620x620")
        self.root.configure(bg="#1e1e1e")
        self.file_path = None
        self.capacity = None      # seçili görüntünün kapasitesi (bayt); mod değişince korunur
        self.busy = False
        self.setup_ui()

    def setup_ui(self):
        tk.Label(self.root, text="AES Crypto-Stego Station v2", fg="#00ff00", bg="#1e1e1e",
                 font=("Courier", 18, "bold")).pack(pady=15)
        self.mode = tk.StringVar(value="ENCODE")
        tf = tk.Frame(self.root, bg="#1e1e1e"); tf.pack(pady=5)
        for text, val, col in (("HIDE DATA (ENCODE)", "ENCODE", "#00ff00"),
                               ("REVEAL DATA (DECODE)", "DECODE", "#ff3333")):
            tk.Radiobutton(tf, text=text, variable=self.mode, value=val, fg=col, bg="#1e1e1e",
                           selectcolor="#333", activebackground="#1e1e1e", activeforeground=col,
                           font=("Arial", 10, "bold"), command=self.refresh).pack(side="left", padx=15)
        self.main_frame = tk.Frame(self.root, bg="#252526", padx=20, pady=20)
        self.main_frame.pack(expand=True, fill="both", padx=20, pady=10)
        self.refresh()

    def refresh(self):
        for w in self.main_frame.winfo_children():
            w.destroy()
        enc = self.mode.get() == "ENCODE"
        tk.Button(self.main_frame, text="Select Image (to Hide)" if enc else "Select Image (to Reveal)",
                  command=self.select_file, width=25, bg="#444", fg="white").pack(pady=5)
        self.lbl_path = tk.Label(self.main_frame, text=os.path.basename(self.file_path) if self.file_path
                                 else "No file selected", fg="#aaa", bg="#252526",
                                 font=("Arial", 9, "italic"))
        self.lbl_path.pack()
        tk.Label(self.main_frame, text="Password:", fg="white", bg="#252526",
                 font=("Arial", 10, "bold")).pack(pady=(15, 0))
        self.ent_pwd = tk.Entry(self.main_frame, show="*", width=35, bg="#333", fg="white",
                                insertbackground="white")
        self.ent_pwd.pack(pady=5)

        tk.Label(self.main_frame, text="Secret Message:" if enc else "Decoded Message:",
                 fg="white", bg="#252526", font=("Arial", 10, "bold")).pack(pady=(10, 0))
        self.txt = scrolledtext.ScrolledText(self.main_frame, height=6, width=55, bg="#333",
                                             fg="#00ff00", insertbackground="white",
                                             font=("Consolas", 10))
        self.txt.pack(pady=(5, 2))
        self.meter = None
        if not enc:
            self.txt.config(state="disabled")
        else:
            self.meter = CapacityMeter(self.main_frame)
            self.meter.pack(fill="x", pady=(0, 5))
            # <<Modified>> yazma, yapıştırma, silme... her değişiklikte tetiklenir
            self.txt.bind("<<Modified>>", self.on_text_change)
        self.show_map = tk.BooleanVar(value=True)
        if enc:
            tk.Checkbutton(self.main_frame, text="Also save block-usage map", variable=self.show_map,
                           fg="white", bg="#252526", selectcolor="#333",
                           activebackground="#252526").pack()
        self.btn = tk.Button(self.main_frame, text="🔒 ENCRYPT & HIDE" if enc else "🔓 DECRYPT & REVEAL",
                             bg="#2e7d32" if enc else "#c62828", fg="white",
                             font=("Arial", 11, "bold"), width=20, command=self.run)
        self.btn.pack(pady=10)
        self.lbl_status = tk.Label(self.main_frame, text="", fg="#aaa", bg="#252526", justify="left")
        self.lbl_status.pack()
        self.update_capacity()

    # ---------------- kapasite göstergesi ----------------
    def on_text_change(self, _event=None):
        self.txt.edit_modified(False)   # bayrağı sıfırla, yoksa olay bir daha tetiklenmez
        self.update_capacity()

    def update_capacity(self):
        """Göstergeyi günceller; mesaj sığmıyorsa gizleme butonunu kapatır."""
        enabled = not self.busy
        if self.meter is not None:
            used = message_bytes(self.txt.get("1.0", "end-1c"))
            self.meter.update_meter(used, self.capacity)
            if self.capacity is not None and used > self.capacity:
                enabled = False
        enc = self.mode.get() == "ENCODE"
        color = ("#2e7d32" if enc else "#c62828") if enabled else "#3a3a3a"
        self.btn.config(state="normal" if enabled else "disabled", bg=color)

    def select_file(self):
        p = filedialog.askopenfilename(filetypes=[("Image Files", "*.png *.bmp *.jpg *.jpeg *.tif *.tiff")])
        if p:
            img = read_image_unicode(p)
            if img is None:
                return messagebox.showerror("Error", f"Could not read image:\n{p}")
            self.file_path = p
            self.capacity = capacity_bytes(img)
            self.lbl_path.config(text=f"{os.path.basename(p)}  ·  {img.shape[1]}x{img.shape[0]}")
            self.update_capacity()

    def run(self):
        pwd = self.ent_pwd.get()
        if not self.file_path or not pwd:
            return messagebox.showerror("Error", "Please select an image and enter a password.")
        out = map_path = None
        if self.mode.get() == "ENCODE":
            msg = self.txt.get("1.0", tk.END).strip()
            if not msg:
                return messagebox.showwarning("Warning", "Secret message cannot be empty.")
            base = os.path.splitext(os.path.basename(self.file_path))[0]
            out = filedialog.asksaveasfilename(defaultextension=".png", initialfile=f"{base}_stego.png",
                                               filetypes=[("PNG", "*.png"), ("BMP", "*.bmp")])
            if not out:
                return
            if self.show_map.get():
                map_path = os.path.splitext(out)[0] + "_map.png"
        else:
            msg = None
        self.busy = True
        self.update_capacity()
        self.lbl_status.config(text="Working... (key derivation takes a moment)")
        threading.Thread(target=self.worker, args=(pwd, msg, out, map_path), daemon=True).start()

    def worker(self, pwd, msg, out, map_path):
        try:
            if msg is not None:
                res = embed_data(self.file_path, out, msg, pwd, map_path)
            else:
                res = extract_data(self.file_path, pwd)
        except Exception as e:
            res = f"ERROR: {e}"
        # Tkinter thread-safe değildir → sonucu ana thread'e gönder
        self.root.after(0, self.show_result, res, msg is not None)

    def show_result(self, res, encoding):
        self.busy = False
        self.update_capacity()
        self.lbl_status.config(text="")
        if encoding:
            if res.startswith("Success"):
                messagebox.showinfo("Success", res)
            else:
                messagebox.showerror("Error", res)
        else:
            self.txt.config(state="normal")
            self.txt.delete("1.0", tk.END)
            self.txt.insert("1.0", res)
            self.txt.config(state="disabled")


if __name__ == "__main__":
    root = tk.Tk()
    StegoApp(root)
    root.mainloop()
