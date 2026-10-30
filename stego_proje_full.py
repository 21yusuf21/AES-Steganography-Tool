"""
Doku-Uyarlamalı (Content-Adaptive) DCT-QIM Steganografi  —  v6 (yüksek kapasite)
==================================================================================
* Veri yalnızca MAVİ (B) kanalın 8x8 DCT bloklarına gömülür.
* "Karışık / dokulu" bölge skoru, HİÇ DEĞİŞTİRİLMEYEN R ve G kanallarından TAM SAYI
  aritmetiğiyle hesaplanır → çözücü seçilen blokları birebir aynı bulur.
* Yalnızca en dokulu %50 blok kullanılır (blok başına 4 katsayı = 4 bit); düz bloklara
  hiç dokunulmaz. Hata düzeltme: Reed–Solomon (255, 239).

İnkâr edilebilir kasa yapısı
----------------------------
Görüntünün TÜM kapasitesi tek bir "konteyner" olarak yazılır:

    [ global salt 16 B ][ 4 hücrelik tablo 4 x 24 B ][ veri alanı ......................... ]

* Her görüntüde HER ZAMAN 4 hücre vardır. 1-4 mesaj, her biri kendi şifresiyle gizlenir.
* Bir şifrenin hücresi, AES-GCM ile şifrelenmiş (konum, uzunluk) bilgisidir.
  Mesajın kendisi veri alanında, aynı anahtarla şifreli durur.
* Kullanılmayan hücreler ve veri alanının boş kalan kısmı RASTGELE baytlarla doldurulur.
  Şifreli veri rastgeleden ayırt edilemez → kaç mesaj olduğu anlaşılamaz.
* Çözücü girilen şifreyle 4 hücreyi de dener; yalnızca o şifrenin mesajı açılır.

* Her kasa ya METİN ya DOSYA tutar. Dosyada orijinal ad (uzantı dahil) da şifreli olarak
  saklanır; çözülürken bu adla kaydedilir (ad önce güvenli hâle getirilir).
* Anahtar türetme: Argon2id (bellek-zor). Şifre başına tek çağrı, global salt ile.
* Yük şifrelenmeden önce sıkıştırılır (raw DEFLATE), yalnızca gerçekten küçülürse.
  Şifreli yükün ilk baytı FORMAT BAYTI: sıkıştırma bayrağı + yük türü.

Gereksinimler: pip install opencv-python numpy pycryptodome argon2-cffi
"""

import hashlib
import os
import secrets
import struct
import threading
import zlib
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext

try:                                  # Sürükle-bırak isteğe bağlı: pip install tkinterdnd2
    from tkinterdnd2 import DND_FILES, TkinterDnD
    HAS_DND = True
except ImportError:
    HAS_DND = False

import cv2
import numpy as np
from argon2.low_level import Type, hash_secret_raw
from Crypto.Cipher import AES

# ==========================================
# AYARLAR
# ==========================================
BLOCK = 8
COEFS = [(4, 1), (1, 4), (3, 2), (2, 3)]   # Dokulu blok başına 4 orta frekans katsayısı = 4 bit
TEXTURE_FRACTION = 0.5     # En dokulu %50 blok kullanılır; geri kalanına HİÇ dokunulmaz
Q_STEP = 24.0              # QIM kuantizasyon adımı
MAP_SEED = b"stego-dct-map-v6"   # Yuva sırası şifreden bağımsız (tüm kasalar paylaşır)
RS_N, RS_NSYM = 255, 16    # Reed–Solomon: 255 baytlık kod sözcüğünde 16 eşlik → 8 hatalı bayt düzeltir

# Argon2id parametreleri (RFC 9106'nın düşük bellekli önerisi: t=3, m=64 MiB, p=4)
ARGON2_TIME = 3
ARGON2_MEMORY_KIB = 64 * 1024
ARGON2_LANES = 4

# Konteyner düzeni
N_LOCKERS = 4                         # her görüntüde sabit kasa sayısı (DEĞİŞTİRME: bilgi sızdırır)
SALT_LEN, NONCE_LEN, TAG_LEN, KEY_LEN = 16, 12, 16, 32
CELL_PLAIN = 8                        # hücre içeriği: konum (4 B) + uzunluk (4 B)
CELL_LEN = CELL_PLAIN + TAG_LEN       # 24 B
TABLE_START = SALT_LEN
DATA_START = TABLE_START + N_LOCKERS * CELL_LEN   # 112 B

# Format baytı (şifreli yükün İLK baytı)
#   bit 0     : 1 = gövde DEFLATE ile sıkıştırılmış
#   bit 4..7  : yük türü
#                 0 = UTF-8 metin   → gövde: metin
#                 1 = dosya         → gövde: ad_uzunluğu (1 B) | ad (UTF-8) | içerik
FLAG_COMPRESSED = 0x01
TYPE_TEXT = 0
TYPE_FILE = 1
MAX_NAME_BYTES = 255
MAX_FILE_BYTES = 8 * 1024 * 1024  # bundan büyük dosya hiçbir görüntüye sığmaz; seçerken reddet
MAX_PAYLOAD = 64 * 1024 * 1024   # açılan veri için üst sınır (sıkıştırma bombasına karşı)


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
# 2) KRİPTO  (Argon2id + AES-256-GCM)
# ==========================================
def _kdf(password, salt, n):
    """Argon2id. Her tahmin için 64 MiB bellek ister → GPU/ASIC ile toplu deneme pahalı."""
    return hash_secret_raw(password.encode("utf-8"), salt, time_cost=ARGON2_TIME,
                           memory_cost=ARGON2_MEMORY_KIB, parallelism=ARGON2_LANES,
                           hash_len=n, type=Type.ID)


def derive_keys(password, global_salt):
    """Tek Argon2 çağrısından: anahtar + hücre nonce'u + mesaj nonce'u.
    Global salt her görüntüde rastgele → anahtar görüntüye özgü; aynı anahtarla yapılan
    iki şifreleme farklı nonce kullanır. Nonce'ları saklamaya gerek yok."""
    km = _kdf(password, global_salt, KEY_LEN + 2 * NONCE_LEN)
    return km[:KEY_LEN], km[KEY_LEN:KEY_LEN + NONCE_LEN], km[KEY_LEN + NONCE_LEN:]


def _seal(key, nonce, data):
    ct, tag = AES.new(key, AES.MODE_GCM, nonce=nonce).encrypt_and_digest(data)
    return tag + ct


def _open(key, nonce, sealed):
    try:
        return AES.new(key, AES.MODE_GCM, nonce=nonce).decrypt_and_verify(sealed[TAG_LEN:],
                                                                          sealed[:TAG_LEN])
    except ValueError:
        return None


# ==========================================
# 2b) YÜK (PAYLOAD): format baytı + isteğe bağlı sıkıştırma
# ==========================================
def _deflate(data):
    # Raw DEFLATE (wbits=-15): zlib'in 2 baytlık başlığı ve 4 baytlık checksum'ı yok.
    # Bütünlüğü zaten AES-GCM doğruluyor.
    c = zlib.compressobj(9, zlib.DEFLATED, -15)
    return c.compress(data) + c.flush()


def _pack(kind, body):
    """Format baytı + gövde. Sıkıştırma yalnızca gerçekten küçültürse kullanılır."""
    packed = _deflate(body)
    if len(packed) < len(body):
        return bytes([kind << 4 | FLAG_COMPRESSED]) + packed
    return bytes([kind << 4]) + body


def pack_text(text):
    return _pack(TYPE_TEXT, text.encode("utf-8"))


_WIN_RESERVED = {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)),
                 *(f"LPT{i}" for i in range(1, 10))}


def safe_filename(name):
    """
    Görüntüden çıkan dosya adına GÜVENME: kötü niyetli bir görüntü '..\\..\\Windows\\x.dll'
    gibi bir ad taşıyabilir. Klasör kısımlarını, yasak karakterleri ve Windows'un ayrılmış
    adlarını temizler; sadece düz bir dosya adı bırakır.
    """
    name = name.replace("\\", "/").split("/")[-1]                      # sadece son parça
    name = "".join(c for c in name if c >= " " and c not in '<>:"|?*')  # kontrol + yasak karakterler
    name = name.strip(" .")                                            # Windows sondaki nokta/boşluk
    if not name:
        return "hidden_file.bin"
    if name.split(".")[0].upper() in _WIN_RESERVED:
        name = "_" + name
    return name


def _limit_name(name):
    """UTF-8'de MAX_NAME_BYTES'ı aşan adı, uzantıyı koruyarak kısalt."""
    if len(name.encode("utf-8")) <= MAX_NAME_BYTES:
        return name
    stem, ext = os.path.splitext(name)
    ext = ext[:20]
    while len((stem + ext).encode("utf-8")) > MAX_NAME_BYTES:
        stem = stem[:-1]
    return stem + ext


def pack_file(name, content):
    """Dosya → format baytı + [ad uzunluğu | ad | içerik] (gerekirse sıkıştırılmış)."""
    name_b = _limit_name(safe_filename(name)).encode("utf-8")
    return _pack(TYPE_FILE, bytes([len(name_b)]) + name_b + content)


def unpack_payload(data):
    """
    Format baytı + gövde → ("text", metin)  veya  ("file", güvenli_ad, içerik).
    Tanınmayan / bozuk biçimde None.
    """
    if not data:
        return None
    flags, body = data[0], data[1:]
    kind = flags >> 4
    if kind not in (TYPE_TEXT, TYPE_FILE) or flags & 0x0E:   # bilinmeyen tür / ayrılmış bitler
        return None
    if flags & FLAG_COMPRESSED:
        d = zlib.decompressobj(-15)
        try:
            body = d.decompress(body, MAX_PAYLOAD)
        except zlib.error:
            return None
        if d.unconsumed_tail:                        # sınırı aştı
            return None
    if kind == TYPE_TEXT:
        try:
            return ("text", body.decode("utf-8"))
        except UnicodeDecodeError:
            return None
    if not body or len(body) < 1 + body[0]:
        return None
    n = body[0]
    try:
        name = body[1:1 + n].decode("utf-8")
    except UnicodeDecodeError:
        return None
    return ("file", safe_filename(name), body[1 + n:])


def payload_cost(payload):
    """Paketlenmiş yükün veri alanında kapladığı bayt (doğrulama etiketi dahil)."""
    return TAG_LEN + len(payload)


def message_cost(text):
    """Bir metin mesajının kapladığı bayt. Boş mesaj kasa kullanmaz → 0. strip edilir."""
    text = text.strip()
    return payload_cost(pack_text(text)) if text else 0


# ==========================================
# 3) KONTEYNER (inkâr edilebilir kasalar)
# ==========================================
def build_container(size, items):
    """
    items: [(paketlenmiş_yük, şifre), ...]  (1..N_LOCKERS adet; yük = pack_text / pack_file çıktısı)
    Dönen: tam olarak `size` baytlık konteyner. Kullanılmayan her yer rastgele.
    """
    if not 1 <= len(items) <= N_LOCKERS:
        raise ValueError(f"Between 1 and {N_LOCKERS} lockers can be filled.")
    pwds = [p for _, p in items]
    if any(not p for p in pwds):
        raise ValueError("Every locker needs a password.")
    if len(set(pwds)) != len(pwds):
        raise ValueError("Each locker must have a different password.")
    need = DATA_START + sum(payload_cost(p) for p, _ in items)
    if need > size:
        raise ValueError(f"Content is too large: {need - DATA_START} bytes needed, "
                         f"capacity is {max(0, size - DATA_START)} bytes.")

    box = bytearray(secrets.token_bytes(size))     # her şey önce rastgele
    gsalt = bytes(box[:SALT_LEN])                   # global salt da rastgele baytların parçası
    cells = secrets.SystemRandom().sample(range(N_LOCKERS), len(items))  # hangi hücre: rastgele
    pos = DATA_START
    for (payload, pwd), cell in zip(items, cells):
        key, n_cell, n_msg = derive_keys(pwd, gsalt)
        body = _seal(key, n_msg, payload)
        box[pos:pos + len(body)] = body
        entry = _seal(key, n_cell, struct.pack(">II", pos, len(body)))
        c0 = TABLE_START + cell * CELL_LEN
        box[c0:c0 + CELL_LEN] = entry
        pos += len(body)
    return bytes(box)


def open_container(box, password):
    """Şifrenin kasasını açar: ("text", metin) / ("file", ad, içerik); kasa yoksa None."""
    if len(box) < DATA_START:
        return None
    key, n_cell, n_msg = derive_keys(password, box[:SALT_LEN])
    for cell in range(N_LOCKERS):
        c0 = TABLE_START + cell * CELL_LEN
        entry = _open(key, n_cell, box[c0:c0 + CELL_LEN])
        if entry is None:
            continue
        pos, length = struct.unpack(">II", entry)
        if pos < DATA_START or length < TAG_LEN + 1 or pos + length > len(box):
            return None
        data = _open(key, n_msg, box[pos:pos + length])
        return None if data is None else unpack_payload(data)
    return None


# ==========================================
# 4) DOKU HARİTASI  (tam sayı aritmetiği → her bilgisayarda birebir aynı)
# ==========================================
def block_texture(img):
    """
    Her 8x8 blok için 'karmaşıklık' skoru. SADECE R ve G kanalları kullanılır
    (veri B kanalına gömüldüğü için R,G stego görüntüde aynen kalır).

        skor = var(G) + var(R) + var(R - G)          (64² ile ölçeklenmiş, TAM SAYI)
               └ parlaklık dokusu ┘   └ renk karışıklığı

    Tam sayı kullanılıyor çünkü çözücü hangi blokların seçildiğini BİREBİR aynı bulmalı.
    Kayan noktalı hesap farklı bilgisayarlarda/kütüphane sürümlerinde son basamakta
    farklı çıkabilir ve eşikteki bir bloğun seçimi değişebilir.
    """
    h, w = img.shape[:2]
    bh, bw = h // BLOCK, w // BLOCK
    c = img[:bh * BLOCK, :bw * BLOCK].astype(np.int64)

    def nvar(ch):   # 64 * Σx² − (Σx)²  =  64² · varyans   (kesin)
        b = ch.reshape(bh, BLOCK, bw, BLOCK).swapaxes(1, 2).reshape(-1, BLOCK * BLOCK)
        return BLOCK * BLOCK * (b * b).sum(1) - b.sum(1) ** 2

    G, R = c[:, :, 1], c[:, :, 2]
    return nvar(G) + nvar(R) + nvar(R - G), bw


def textured_blocks(score):
    """En dokulu TEXTURE_FRACTION oranındaki bloklar (eşitlikte küçük indeks önce). Sıralı döner."""
    n = score.size
    m = int(n * TEXTURE_FRACTION)
    order = np.lexsort((np.arange(n), -score))
    return np.sort(order[:m])


def _mix64(x):
    """splitmix64 karıştırıcısı (vektörel, uint64 taşması tanımlı). NumPy sürümünden bağımsız."""
    x = x + np.uint64(0x9E3779B97F4A7C15)
    x = (x ^ (x >> np.uint64(30))) * np.uint64(0xBF58476D1CE4E5B9)
    x = (x ^ (x >> np.uint64(27))) * np.uint64(0x94D049BB133111EB)
    return x ^ (x >> np.uint64(31))


def layout(img):
    """
    Görüntünün gömme düzeni — R ve G kanallarından, şifre olmadan hesaplanır:
      slots : (yuva sayısı, 2) [blok, katsayı_indeksi]; dokulu her bloğun her katsayısı = 1 bit
      bw    : satır başına blok sayısı
      total : toplam blok sayısı
      size  : sığan konteyner boyutu (bayt, RS eşlikleri düşülmüş)
    Yuvalar sabit bir karıştırmayla sıralanır: bitler görüntüye yayılır, olası hatalar
    (ör. parlak bölgede kırpma) tek bir RS kod sözcüğünde toplanmaz. Karıştırma kendi
    karıştırıcımızla yapılır: NumPy'nin rastgele üreteci sürümler arasında değişebilir ve
    o zaman başka bilgisayarda çözülemezdi.
    """
    with np.errstate(over="ignore"):
        score, bw = block_texture(img)
        tex = textured_blocks(score)
        slots = np.stack([np.repeat(tex, len(COEFS)),
                          np.tile(np.arange(len(COEFS)), tex.size)], axis=1)
        seed = np.uint64(int.from_bytes(hashlib.sha256(MAP_SEED).digest()[:8], "big"))
        keys = _mix64(np.arange(len(slots), dtype=np.uint64) ^ seed)
    slots = slots[np.argsort(keys, kind="stable")]
    raw = len(slots) // 8
    k = RS_N - RS_NSYM
    size = raw * k // RS_N
    while size > 0 and rs_coded_len(size) > raw:
        size -= 1
    while rs_coded_len(size + 1) <= raw:
        size += 1
    return {"slots": slots, "bw": bw, "total": score.size, "size": max(0, size)}


# ==========================================
# 4b) HATA DÜZELTME: Reed–Solomon, GF(256)
# ==========================================
# Her RS_N baytlık kod sözcüğü RS_NSYM eşlik baytı taşır ve RS_NSYM/2 hatalı baytı düzeltir.
# Son parça kısaltılmış kod sözcüğüdür (daha az veri, aynı eşlik sayısı).
_GF_EXP = [0] * 512
_GF_LOG = [0] * 256
_x = 1
for _i in range(255):
    _GF_EXP[_i] = _x
    _GF_LOG[_x] = _i
    _x <<= 1
    if _x & 0x100:
        _x ^= 0x11D                       # ilkel polinom x^8 + x^4 + x^3 + x^2 + 1
for _i in range(255, 512):
    _GF_EXP[_i] = _GF_EXP[_i - 255]


def _gf_mul(a, b):
    return 0 if a == 0 or b == 0 else _GF_EXP[_GF_LOG[a] + _GF_LOG[b]]


def _gf_inv(a):
    return _GF_EXP[255 - _GF_LOG[a]]


def _poly_mul(p, q):
    r = [0] * (len(p) + len(q) - 1)
    for j, qj in enumerate(q):
        for i, pi in enumerate(p):
            r[i + j] ^= _gf_mul(pi, qj)
    return r


def _poly_eval(p, x):                     # p[0] en yüksek derece
    y = p[0]
    for c in p[1:]:
        y = _gf_mul(y, x) ^ c
    return y


def _rs_generator(nsym):
    g = [1]
    for i in range(nsym):
        g = _poly_mul(g, [1, _GF_EXP[i]])
    return g


_RS_GEN = {}


def rs_encode(msg, nsym):
    """msg: bayt dizisi (≤ 255 - nsym). Dönen: msg + nsym eşlik baytı."""
    gen = _RS_GEN.setdefault(nsym, _rs_generator(nsym))
    buf = list(msg) + [0] * nsym
    for i in range(len(msg)):
        c = buf[i]
        if c:
            lc = _GF_LOG[c]
            for j in range(1, len(gen)):
                if gen[j]:
                    buf[i + j] ^= _GF_EXP[lc + _GF_LOG[gen[j]]]
    return bytes(msg) + bytes(buf[len(msg):])


def _poly_add(p, q):
    r = [0] * max(len(p), len(q))
    for i, c in enumerate(p):
        r[i + len(r) - len(p)] = c
    for i, c in enumerate(q):
        r[i + len(r) - len(q)] ^= c
    return r


def _poly_scale(p, x):
    return [_gf_mul(c, x) for c in p]


def _poly_divmod_rem(dividend, divisor):
    out = list(dividend)
    for i in range(len(dividend) - (len(divisor) - 1)):
        coef = out[i]
        if coef:
            for j in range(1, len(divisor)):
                if divisor[j]:
                    out[i + j] ^= _gf_mul(divisor[j], coef)
    sep = -(len(divisor) - 1)
    return out[sep:]


def _gf_pow2(e):
    return _GF_EXP[e % 255]


def rs_decode(code, nsym):
    """
    Hataları düzeltip veri kısmını döndürür; düzeltilemezse None.
    En fazla nsym/2 hatalı bayt düzeltilir. (Berlekamp–Massey + Chien + Forney;
    Wikiversity "Reed–Solomon codes for coders" referans uygulamasına sadık.)
    """
    msg = list(code)
    synd = [0] + [_poly_eval(msg, _gf_pow2(i)) for i in range(nsym)]
    if max(synd) == 0:
        return bytes(msg[:-nsym])
    # Berlekamp–Massey
    err_loc, old_loc = [1], [1]
    shift = len(synd) - nsym
    for i in range(nsym):
        K = i + shift
        delta = synd[K]
        for j in range(1, len(err_loc)):
            delta ^= _gf_mul(err_loc[-(j + 1)], synd[K - j])
        old_loc = old_loc + [0]
        if delta:
            if len(old_loc) > len(err_loc):
                new_loc = _poly_scale(old_loc, delta)
                old_loc = _poly_scale(err_loc, _gf_inv(delta))
                err_loc = new_loc
            err_loc = _poly_add(err_loc, _poly_scale(old_loc, delta))
    while err_loc and err_loc[0] == 0:
        err_loc.pop(0)
    n_err = len(err_loc) - 1
    if n_err * 2 > nsym:
        return None
    # Chien araması
    rev = err_loc[::-1]
    nm = len(msg)
    err_pos = [nm - 1 - i for i in range(nm) if _poly_eval(rev, _gf_pow2(i)) == 0]
    if len(err_pos) != n_err:
        return None
    # Forney
    coef_pos = [nm - 1 - p for p in err_pos]
    e_loc = [1]
    for i in coef_pos:
        e_loc = _poly_mul(e_loc, _poly_add([1], [_gf_pow2(i), 0]))
    err_eval = _poly_divmod_rem(_poly_mul(synd[::-1], e_loc), [1] + [0] * len(e_loc))
    err_eval = err_eval[::-1]
    X = [_gf_pow2(c) for c in coef_pos]
    for i, Xi in enumerate(X):
        Xi_inv = _gf_inv(Xi)
        denom = 1
        for j, Xj in enumerate(X):
            if j != i:
                denom = _gf_mul(denom, 1 ^ _gf_mul(Xi_inv, Xj))
        if denom == 0:
            return None
        y = _gf_mul(Xi, _poly_eval(err_eval[::-1], Xi_inv))
        msg[err_pos[i]] ^= _gf_mul(y, _gf_inv(denom))
    if any(_poly_eval(msg, _gf_pow2(i)) for i in range(nsym)):
        return None
    return bytes(msg[:-nsym])


def rs_coded_len(n_bytes):
    k = RS_N - RS_NSYM
    return n_bytes + RS_NSYM * (-(-n_bytes // k))


def rs_encode_all(data):
    k = RS_N - RS_NSYM
    return b"".join(rs_encode(data[i:i + k], RS_NSYM) for i in range(0, len(data), k))


def rs_decode_all(coded, n_bytes):
    """Düzeltilmiş veri ve düzeltilemeyen kod sözcüğü sayısı. Düzeltilemeyen parça olduğu gibi bırakılır."""
    k = RS_N - RS_NSYM
    out, failed, i, left = [], 0, 0, n_bytes
    while left > 0:
        dk = min(k, left)
        chunk = coded[i:i + dk + RS_NSYM]
        fixed = rs_decode(chunk, RS_NSYM)
        if fixed is None:
            failed += 1
            fixed = chunk[:dk]
        out.append(fixed)
        i += dk + RS_NSYM
        left -= dk
    return b"".join(out), failed


# ==========================================
# 5) QIM
# ==========================================
# 8x8 ortonormal DCT-II matrisi (cv2.dct ile aynı): katsayı[u,v] = C[u] @ blok @ C[v]
_C = np.array([[np.sqrt((1 if k == 0 else 2) / BLOCK) * np.cos(np.pi * (2 * n + 1) * k / (2 * BLOCK))
                for n in range(BLOCK)] for k in range(BLOCK)])


def _qim_detect(c, q):
    """Vektörel: c bir dizi olabilir."""
    d0 = np.abs(c - np.round(c / q) * q)
    d1 = np.abs(c - (np.round((c - q / 2) / q) * q + q / 2))
    return (d1 < d0).astype(np.uint8)


def _all_coeffs(chan):
    """Tüm bloklar için kullanılan DCT katsayıları → (blok sayısı, len(COEFS)). Tek seferde, hızlı."""
    h, w = chan.shape
    bh, bw = h // BLOCK, w // BLOCK
    X = chan[:bh * BLOCK, :bw * BLOCK].astype(np.float64)
    X = X.reshape(bh, BLOCK, bw, BLOCK).swapaxes(1, 2).reshape(-1, BLOCK, BLOCK)
    return np.stack([(X @ _C[v]) @ _C[u] for u, v in COEFS], axis=1)


# ==========================================
# 6) GÖMME / ÇIKARMA  (konteyner baytları ↔ görüntü)
# ==========================================
def container_size(img, lay=None):
    """Görüntüye sığan konteyner boyutu (bayt), RS eşlik baytları düşülmüş."""
    return (lay or layout(img))["size"]


def capacity_bytes(img, lay=None):
    """Kasalar için kalan bayt (salt + 4 hücrelik tablo düşülmüş)."""
    return max(0, container_size(img, lay) - DATA_START)


def _blocks_view(chan, blocks, bw):
    """Seçilen blokların piksel indeksleri: (len(blocks), 8, 8) şekilli satır/sütun dizileri."""
    ys = (blocks // bw) * BLOCK
    xs = (blocks % bw) * BLOCK
    r = np.arange(BLOCK)
    return ys[:, None, None] + r[None, :, None], xs[:, None, None] + r[None, None, :]


def _write_blocks(chan, orig, blocks, bw, bits, push):
    """
    Vektörel gömme: blocks (n,), bits (n, len(COEFS)), push (n, len(COEFS)) kafes kaydırması.
    Her blok ORİJİNAL piksellerden yeniden hesaplanır (tekrar yazma birikmesin).
    """
    Y, X = _blocks_view(chan, blocks, bw)
    Xb = orig[Y, X].astype(np.float64)
    D = _C @ Xb @ _C.T                                       # ileri DCT
    for k, (u, v) in enumerate(COEFS):
        c = D[:, u, v]
        q0 = np.round(c / Q_STEP) * Q_STEP
        q1 = np.round((c - Q_STEP / 2) / Q_STEP) * Q_STEP + Q_STEP / 2
        D[:, u, v] = np.where(bits[:, k] == 1, q1, q0) + push[:, k] * Q_STEP
    out = _C.T @ D @ _C                                      # ters DCT (C ortonormal: C⁻¹ = Cᵀ)
    chan[Y, X] = np.clip(np.round(out), 0, 255).astype(np.uint8)


def embed_bytes(img, data, lay=None):
    """Konteyneri görüntüye göm. (stego, kullanılan_bloklar, istatistik) döndürür."""
    lay = lay or layout(img)
    slots, bw = lay["slots"], lay["bw"]
    coded = rs_encode_all(data)
    bits = np.unpackbits(np.frombuffer(coded, np.uint8))
    if bits.size > len(slots):
        raise ValueError("Container does not fit in this image.")
    # Konteyner kapasiteyi tam doldurmayabilir (bayt yuvarlaması); kalan yuvalara da rastgele
    # bit yazılır ki dokulu blokların TAMAMI aynı şekilde değişmiş olsun.
    fill = np.unpackbits(np.frombuffer(secrets.token_bytes(-(-(len(slots) - bits.size) // 8)), np.uint8))
    all_bits = np.concatenate([bits, fill[:len(slots) - bits.size]])

    blocks = np.unique(slots[:, 0])                 # dokulu bloklar (sıralı)
    row = np.searchsorted(blocks, slots[:, 0])      # yuva → blok satırı
    B = np.zeros((blocks.size, len(COEFS)), np.uint8)
    B[row, slots[:, 1]] = all_bits
    push = np.zeros(B.shape, np.int8)

    orig = img[:, :, 0]
    stego = img.copy()
    chan = stego[:, :, 0]                           # B kanalı
    _write_blocks(chan, orig, blocks, bw, B, push)

    # Doğrula ve düzelt: kırpma (0/255'e dayanan pikseller) nadiren bir biti bozar.
    # Hatalı katsayıyı aynı bit için bir sonraki kafes noktasına kaydırıp bloğu yeniden yaz.
    # Hâlâ kalan birkaç hata Reed–Solomon ile düzeltilir.
    tries = np.array([0, 1, -1, 2, -2], np.int8)
    rounds = 0
    for _ in range(len(tries) - 1):
        det = _qim_detect(_all_coeffs(chan)[slots[:, 0], slots[:, 1]], Q_STEP)
        bad = np.nonzero(det != all_bits)[0]
        if bad.size == 0:
            break
        rounds += 1
        r, k = row[bad], slots[bad, 1]
        cur = np.array([np.nonzero(tries == p)[0][0] for p in push[r, k]])
        push[r, k] = tries[(cur + 1) % len(tries)]
        redo = np.unique(r)
        _write_blocks(chan, orig, blocks[redo], bw, B[redo], push[redo])
    det = _qim_detect(_all_coeffs(chan)[slots[:, 0], slots[:, 1]], Q_STEP)
    residual = int((det != all_bits).sum())

    stats = {"used": int(blocks.size), "total": int(lay["total"]),
             "fixed_rounds": rounds, "residual_bit_errors": residual}
    return stego, blocks, stats


def extract_bytes(img, lay=None):
    """Görüntüdeki konteyneri okur (şifre gerekmez; içerik şifreli/rastgele)."""
    lay = lay or layout(img)
    slots, size = lay["slots"], lay["size"]
    n_bits = rs_coded_len(size) * 8
    det = _qim_detect(_all_coeffs(img[:, :, 0])[slots[:n_bits, 0], slots[:n_bits, 1]], Q_STEP)
    data, _failed = rs_decode_all(np.packbits(det).tobytes(), size)
    return data


def embed_data(image_path, output_path, items, map_path=None):
    """items: [(paketlenmiş_yük, şifre), ...] — pack_text() / pack_file() ile hazırlanır."""
    img = read_image_unicode(image_path)
    if img is None:
        return f"ERROR: Could not read image!\nPath: {image_path}"
    if not items:
        return "ERROR: Nothing to hide."
    lay = layout(img)                              # bir kez hesapla, her yerde kullan
    try:
        box = build_container(lay["size"], items)
        stego, used, st = embed_bytes(img, box, lay)
    except ValueError as e:
        return f"ERROR: {e}"

    # Kendi kendini doğrulama: konteyner bayt bayt geri okunabiliyor mu?
    # (Şifre gerektirmez → ek Argon2 maliyeti yok, üstelik tüm kasaları birden kontrol eder.)
    # Stego görüntünün düzeni R,G'den YENİDEN hesaplanır: çözücünün göreceği şeyin aynısı.
    ok = extract_bytes(stego) == box
    if not ok:
        return "ERROR: Self-check failed, the data could not be read back. Try a different image."
    if not save_image_unicode(output_path, stego):
        return f"ERROR: Could not save image!\nPath: {output_path}"
    if map_path:
        save_usage_map(img, used, lay["bw"], map_path)
    used_b = sum(payload_cost(p) for p, _ in items)
    return (f"Success\nLockers filled: {len(items)} (image always has {N_LOCKERS} lockers)\n"
            f"Used: {used_b}/{capacity_bytes(img, lay)} bytes, rest filled with random data\n"
            f"Modified blocks: {st['used']}/{st['total']} "
            f"(%{100 * st['used'] / st['total']:.1f}, textured only; flat blocks untouched)\n"
            f"Raw bit errors left for Reed-Solomon: {st['residual_bit_errors']}\n"
            f"Self-check: OK")


def extract_data(image_path, password):
    """("text", metin) / ("file", güvenli_ad, içerik) / ("error", mesaj) döndürür."""
    img = read_image_unicode(image_path)
    if img is None:
        return ("error", f"Could not read image!\nPath: {image_path}")
    result = open_container(extract_bytes(img), password)
    if result is None:
        # Bilerek ayrım yapılmıyor: "görüntüde veri yok" ile "yanlış şifre" aynı görünmeli.
        return ("error", "No message found for this password.")
    return result


def human_size(n):
    return f"{n} B" if n < 1024 else f"{n / 1024:.1f} KB" if n < 1024 ** 2 else f"{n / 1024 ** 2:.1f} MB"


# ==========================================
# 7) GÖRSELLEŞTİRME
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
# 8) GUI
# ==========================================
METER_COLORS = {"ok": "#2e7d32", "warn": "#f9a825", "over": "#c62828"}
IMAGE_EXTS = (".png", ".bmp", ".jpg", ".jpeg", ".tif", ".tiff", ".webp")
BG, PANEL, FIELD, MUTED = "#1e1e1e", "#252526", "#333", "#aaa"


def capacity_level(used, cap):
    """'ok' (<%80), 'warn' (%80-100), 'over' (sığmıyor)."""
    if used > cap:
        return "over"
    return "warn" if cap and used / cap >= 0.8 else "ok"


def new_locker():
    return {"pwd": "", "kind": "text", "text": "",
            "file_name": None, "file_size": 0, "file_payload": None}


def locker_payload(l):
    """Kasanın paketlenmiş yükü; boş kasa → None."""
    if l["kind"] == "file":
        return l["file_payload"]
    t = l["text"].strip()
    return pack_text(t) if t else None


def locker_cost(l):
    p = locker_payload(l)
    return payload_cost(p) if p is not None else 0


class CapacityMeter(tk.Frame):
    """Canlı güncellenen kapasite çubuğu (tüm kasaların toplamı)."""

    def __init__(self, master):
        super().__init__(master, bg=PANEL)
        self.bar = tk.Canvas(self, height=12, bg=FIELD, highlightthickness=0)
        self.bar.pack(fill="x")
        self.label = tk.Label(self, text="", fg=MUTED, bg=PANEL, font=("Arial", 9))
        self.label.pack(anchor="e")
        self.used = self.cap = None
        self.bar.bind("<Configure>", lambda e: self._draw())

    def update_meter(self, used, cap, note=""):
        """cap None ise henüz görüntü seçilmemiştir."""
        self.used, self.cap = used, cap
        if cap is None:
            self.label.config(text="Select an image to see its capacity", fg=MUTED)
        elif used > cap:
            self.label.config(text=f"All lockers: {used} / {cap} bytes — {used - cap} bytes over the limit",
                              fg=METER_COLORS["over"])
        else:
            level = capacity_level(used, cap)
            self.label.config(text=f"All lockers: {used} / {cap} bytes — {cap - used} left{note}",
                              fg=METER_COLORS["warn"] if level == "warn" else MUTED)
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
        self.root.title("AES Steganography Tool v6 (Deniable Lockers + Files)")
        self.root.geometry("640x700")
        self.root.configure(bg=BG)
        self.file_path = None
        self.capacity = None      # seçili görüntünün kapasitesi (bayt); mod değişince korunur
        self.busy = False
        self.lockers = [new_locker() for _ in range(N_LOCKERS)]
        self.cur = 0              # düzenlenen kasa
        self.locker_btns = []
        self._built_encode = False
        self.setup_ui()

    def setup_ui(self):
        tk.Label(self.root, text="AES Crypto-Stego Station v6", fg="#00ff00", bg=BG,
                 font=("Courier", 18, "bold")).pack(pady=15)
        self.mode = tk.StringVar(value="ENCODE")
        tf = tk.Frame(self.root, bg=BG); tf.pack(pady=5)
        for text, val, col in (("HIDE DATA (ENCODE)", "ENCODE", "#00ff00"),
                               ("REVEAL DATA (DECODE)", "DECODE", "#ff3333")):
            tk.Radiobutton(tf, text=text, variable=self.mode, value=val, fg=col, bg=BG,
                           selectcolor=FIELD, activebackground=BG, activeforeground=col,
                           font=("Arial", 10, "bold"), command=self.refresh).pack(side="left", padx=15)
        self.main_frame = tk.Frame(self.root, bg=PANEL, padx=20, pady=15)
        self.main_frame.pack(expand=True, fill="both", padx=20, pady=10)
        self.refresh()

    @property
    def encoding(self):
        return self.mode.get() == "ENCODE"

    def _label(self, text, **pack):
        tk.Label(self.main_frame, text=text, fg="white", bg=PANEL,
                 font=("Arial", 10, "bold")).pack(**({"pady": (10, 0)} | pack))

    def refresh(self):
        if self._built_encode:
            self.save_locker()                      # mod değişmeden önce düzenlenen kasayı kaydet
        for w in self.main_frame.winfo_children():
            w.destroy()
        enc = self.encoding
        self._built_encode = enc
        tk.Button(self.main_frame, text="Select Image (to Hide)" if enc else "Select Image (to Reveal)",
                  command=self.select_file, width=25, bg="#444", fg="white").pack(pady=5)
        self.lbl_path = tk.Label(self.main_frame, text="", fg=MUTED, bg=PANEL,
                                 font=("Arial", 9, "italic"))
        self.lbl_path.pack()
        self._update_path_label()

        self.locker_btns = []
        if enc:
            lf = tk.Frame(self.main_frame, bg=PANEL); lf.pack(pady=(12, 0))
            tk.Label(lf, text="Locker:", fg="white", bg=PANEL,
                     font=("Arial", 10, "bold")).pack(side="left", padx=(0, 8))
            for i in range(N_LOCKERS):
                b = tk.Button(lf, width=7, command=lambda i=i: self.switch_locker(i),
                              fg="white", relief="flat", font=("Arial", 9, "bold"))
                b.pack(side="left", padx=2)
                self.locker_btns.append(b)
            tk.Label(self.main_frame, text="Each locker = one message or file + its own password. "
                                           "Empty lockers are filled with random data.",
                     fg=MUTED, bg=PANEL, font=("Arial", 8)).pack()

        self._label("Password:")
        self.ent_pwd = tk.Entry(self.main_frame, show="*", width=35, bg=FIELD, fg="white",
                                insertbackground="white")
        self.ent_pwd.pack(pady=5)

        if enc:
            kf = tk.Frame(self.main_frame, bg=PANEL); kf.pack(pady=(8, 0))
            tk.Label(kf, text="Content:", fg="white", bg=PANEL,
                     font=("Arial", 10, "bold")).pack(side="left", padx=(0, 8))
            self.kind_var = tk.StringVar(value="text")
            for text, val in (("Text", "text"), ("File", "file")):
                tk.Radiobutton(kf, text=text, variable=self.kind_var, value=val, fg="white", bg=PANEL,
                               selectcolor=FIELD, activebackground=PANEL, activeforeground="white",
                               command=self.on_kind_change).pack(side="left", padx=6)
        else:
            self._label("Decoded Message / File:")

        # İçerik alanı: metin kutusu ya da dosya paneli (biri gösterilir)
        self.content = tk.Frame(self.main_frame, bg=PANEL)
        self.content.pack(pady=(5, 2), fill="both", expand=True)
        self.txt = scrolledtext.ScrolledText(self.content, height=8, width=58, bg=FIELD,
                                             fg="#00ff00", insertbackground="white",
                                             font=("Consolas", 10), wrap="word")
        self.file_frame = tk.Frame(self.content, bg=FIELD, padx=15, pady=15)
        fb = tk.Frame(self.file_frame, bg=FIELD); fb.pack(anchor="w")
        tk.Button(fb, text="Choose file…", command=self.choose_file, bg="#444", fg="white",
                  width=14).pack(side="left")
        tk.Button(fb, text="Remove", command=self.remove_file, bg="#444", fg="white",
                  width=8).pack(side="left", padx=6)
        self.lbl_file = tk.Label(self.file_frame, text="", fg="#00ff00", bg=FIELD, justify="left",
                                 anchor="w", font=("Consolas", 10), wraplength=520)
        self.lbl_file.pack(anchor="w", pady=(12, 0), fill="x")
        tk.Label(self.file_frame, text="Any file type works. Plain-text files (.txt, .csv, .json, code) "
                                       "compress well;\n.docx/.pdf/.jpg/.zip are already compressed "
                                       "and usually need a large image.",
                 fg=MUTED, bg=FIELD, justify="left", font=("Arial", 8)).pack(anchor="w", pady=(12, 0))

        self.meter = None
        if not enc:
            self.txt.pack(fill="both", expand=True)
            self.txt.config(state="disabled")
        else:
            self.meter = CapacityMeter(self.main_frame)
            self.meter.pack(fill="x", pady=(0, 5))
            self.load_locker(self.cur)
            # <<Modified>> yazma, yapıştırma, silme... her değişiklikte tetiklenir
            self.txt.bind("<<Modified>>", self.on_change)
            self.ent_pwd.bind("<KeyRelease>", self.on_change)
        self.show_map = tk.BooleanVar(value=False)
        if enc:
            tk.Checkbutton(self.main_frame, text="Also save block-usage map", variable=self.show_map,
                           fg="white", bg=PANEL, selectcolor=FIELD,
                           activebackground=PANEL).pack()
        self.btn = tk.Button(self.main_frame, text="🔒 ENCRYPT & HIDE" if enc else "🔓 DECRYPT & REVEAL",
                             fg="white", font=("Arial", 11, "bold"), width=20, command=self.run)
        self.btn.pack(pady=10)
        self.lbl_status = tk.Label(self.main_frame, text="", fg=MUTED, bg=PANEL, justify="left")
        self.lbl_status.pack()
        tip = ("Tip: drag & drop an image here. Drop a file onto the file panel to hide it."
               if HAS_DND else "Drag & drop: pip install tkinterdnd2")
        if not enc and HAS_DND:
            tip = "Tip: drag & drop a stego image here."
        tk.Label(self.main_frame, text=tip, fg="#777", bg=PANEL, font=("Arial", 8)).pack(side="bottom")
        self._register_drop_targets(self.root)
        self.update_capacity()

    # ---------------- kasalar ----------------
    def save_locker(self):
        l = self.lockers[self.cur]
        l["pwd"] = self.ent_pwd.get()
        l["text"] = self.txt.get("1.0", "end-1c")
        l["kind"] = self.kind_var.get()

    def load_locker(self, i):
        self.cur = i
        l = self.lockers[i]
        self.ent_pwd.delete(0, tk.END)
        self.ent_pwd.insert(0, l["pwd"])
        self.txt.delete("1.0", tk.END)
        self.txt.insert("1.0", l["text"])
        self.txt.edit_modified(False)
        self.kind_var.set(l["kind"])
        self._show_content(l["kind"])
        self._update_file_label()

    def switch_locker(self, i):
        self.save_locker()
        self.load_locker(i)
        self.update_capacity()

    def _show_content(self, kind):
        if kind == "file":
            self.txt.pack_forget()
            self.file_frame.pack(fill="both", expand=True)
        else:
            self.file_frame.pack_forget()
            self.txt.pack(fill="both", expand=True)

    def on_kind_change(self):
        self._show_content(self.kind_var.get())
        self.update_capacity()

    def choose_file(self):
        p = filedialog.askopenfilename(title="Choose a file to hide")
        if p:
            self.load_locker_file(p)

    def load_locker_file(self, p):
        """Dosyayı düzenlenen kasaya koyar (diyalogdan ya da sürükle-bıraktan)."""
        if os.path.isdir(p):
            return messagebox.showerror("Error", "Folders can't be hidden. Zip the folder first.")
        try:
            size = os.path.getsize(p)
            if size > MAX_FILE_BYTES:
                return messagebox.showerror("Error", f"File is too large ({human_size(size)}). "
                                                     f"No image can hold it.")
            with open(p, "rb") as f:
                data = f.read()
        except OSError as e:
            return messagebox.showerror("Error", f"Could not read file:\n{e}")
        l = self.lockers[self.cur]
        l["file_name"] = os.path.basename(p)
        l["file_size"] = len(data)
        l["file_payload"] = pack_file(l["file_name"], data)   # bir kez sıkıştır, sonra önbellekten
        self._update_file_label()
        self.update_capacity()

    def remove_file(self):
        l = self.lockers[self.cur]
        l["file_name"], l["file_size"], l["file_payload"] = None, 0, None
        self._update_file_label()
        self.update_capacity()

    def _update_file_label(self):
        l = self.lockers[self.cur]
        if l["file_payload"] is None:
            self.lbl_file.config(text="No file chosen", fg=MUTED)
            return
        comp = " (compressed)" if l["file_payload"][0] & FLAG_COMPRESSED else ""
        self.lbl_file.config(text=f"{l['file_name']}\n{human_size(l['file_size'])}  →  "
                                  f"takes {human_size(payload_cost(l['file_payload']))} in the image{comp}",
                             fg="#00ff00")

    def _style_locker_buttons(self):
        for i, b in enumerate(self.locker_btns):
            l = self.lockers[i]
            filled = locker_payload(l) is not None
            tag = (" file" if l["kind"] == "file" else " txt") if filled else ""
            b.config(text=f"{i + 1}{tag}",
                     bg="#2e7d32" if i == self.cur else ("#3d5a40" if filled else "#444"))

    # ---------------- kapasite göstergesi ----------------
    def on_change(self, _event=None):
        if _event is not None and _event.widget is self.txt:
            self.txt.edit_modified(False)   # bayrağı sıfırla, yoksa olay bir daha tetiklenmez
        self.update_capacity()

    def update_capacity(self):
        """Göstergeyi günceller; içerik sığmıyorsa gizleme butonunu kapatır."""
        enabled = not self.busy
        if self.meter is not None:
            self.save_locker()
            used = sum(locker_cost(l) for l in self.lockers)
            cur = self.lockers[self.cur]
            p = locker_payload(cur)
            note = ""
            if p is not None:
                note = f"  ·  locker {self.cur + 1}: {payload_cost(p)} B"
                if p[0] & FLAG_COMPRESSED:
                    note += " (compressed)"
            self.meter.update_meter(used, self.capacity, note)
            if self.capacity is not None and used > self.capacity:
                enabled = False
            self._style_locker_buttons()
        color = ("#2e7d32" if self.encoding else "#c62828") if enabled else "#3a3a3a"
        self.btn.config(state="normal" if enabled else "disabled", bg=color)

    def _update_path_label(self):
        if not self.file_path:
            self.lbl_path.config(text="No file selected")
            return
        info = f"{os.path.basename(self.file_path)}  ·  {self.image_size[0]}x{self.image_size[1]}"
        if self.encoding:
            info += f"  ·  capacity {self.capacity} bytes"
        self.lbl_path.config(text=info)

    def select_file(self):
        p = filedialog.askopenfilename(filetypes=[("Image Files", "*.png *.bmp *.jpg *.jpeg *.tif *.tiff")])
        if p:
            self.load_image(p)

    def load_image(self, p):
        """Kapak / stego görüntüsünü yükler (diyalogdan ya da sürükle-bıraktan)."""
        img = read_image_unicode(p)
        if img is None:
            return messagebox.showerror("Error", f"Could not read image:\n{p}")
        self.file_path = p
        self.capacity = capacity_bytes(img)
        self.image_size = (img.shape[1], img.shape[0])
        self._update_path_label()
        self.update_capacity()

    # ---------------- sürükle-bırak ----------------
    def _register_drop_targets(self, widget):
        """Pencere ve içindeki her widget bırakma hedefi olur (bırakma alt widget'a gelir)."""
        if not HAS_DND:
            return
        try:
            widget.drop_target_register(DND_FILES)
            widget.dnd_bind("<<Drop>>", self.on_drop)
        except (AttributeError, tk.TclError):
            pass
        for child in widget.winfo_children():
            self._register_drop_targets(child)

    def _in_file_panel(self, widget):
        return widget is not None and str(widget).startswith(str(self.file_frame))

    def on_drop(self, event):
        """
        Bırakılan şey nereye gider?
          • Dosya panelinin üstüne bırakılan her şey → düzenlenen kasaya DOSYA olarak
            (bir resmi gizlemek istiyorsan onu dosya paneline bırak)
          • Gizleme modunda, dosya paneli dışına bırakılan resim → kapak görüntüsü
          • Gizleme modunda resim olmayan dosya → düzenlenen kasaya dosya olarak
          • Çözme modunda → stego görüntüsü
        """
        paths = self.root.tk.splitlist(event.data)    # boşluklu yollar {…} içinde gelir
        if not paths or self.busy:
            return event.action if hasattr(event, "action") else None
        p = paths[0]
        is_image = os.path.splitext(p)[1].lower() in IMAGE_EXTS
        widget = getattr(event, "widget", None)
        if self.encoding and (self._in_file_panel(widget) or not is_image):
            self.kind_var.set("file")
            self._show_content("file")
            self.load_locker_file(p)
        elif is_image:
            self.load_image(p)
        else:
            messagebox.showerror("Error", "Drop an image (PNG/BMP/TIFF/JPG) to reveal.")
        if len(paths) > 1:
            self.lbl_status.config(text=f"Only the first of {len(paths)} dropped items was used.")
        return getattr(event, "action", None)

    # ---------------- çalıştır ----------------
    def run(self):
        if not self.file_path:
            return messagebox.showerror("Error", "Please select an image.")
        out = map_path = None
        if self.encoding:
            self.save_locker()
            filled = [(i, l) for i, l in enumerate(self.lockers) if locker_payload(l) is not None]
            if not filled:
                return messagebox.showwarning("Warning", "Write a message or choose a file first.")
            missing = [i + 1 for i, l in filled if not l["pwd"]]
            if missing:
                return messagebox.showerror("Error", f"Locker {missing[0]} has content but no password.")
            pwds = [l["pwd"] for _, l in filled]
            if len(set(pwds)) != len(pwds):
                return messagebox.showerror("Error", "Each locker must have a different password.")
            items = [(locker_payload(l), l["pwd"]) for _, l in filled]
            need = sum(payload_cost(p) for p, _ in items)
            if self.capacity is not None and need > self.capacity:
                return messagebox.showerror("Error", f"Content is too large: {need} bytes, "
                                                     f"capacity is {self.capacity} bytes.")
            base = os.path.splitext(os.path.basename(self.file_path))[0]
            out = filedialog.asksaveasfilename(defaultextension=".png", initialfile=f"{base}_stego.png",
                                               filetypes=[("PNG", "*.png"), ("BMP", "*.bmp")])
            if not out:
                return
            if self.show_map.get():
                map_path = os.path.splitext(out)[0] + "_map.png"
            args = (items, out, map_path)
            n_kdf = len(items)
        else:
            pwd = self.ent_pwd.get()
            if not pwd:
                return messagebox.showerror("Error", "Please enter a password.")
            args = (pwd,)
            n_kdf = 1
        self.busy = True
        self.update_capacity()
        self.lbl_status.config(text=f"Working... ({n_kdf} key derivation{'s' if n_kdf > 1 else ''}, "
                                    "takes a moment)")
        threading.Thread(target=self.worker, args=(self.encoding, args), daemon=True).start()

    def worker(self, encoding, args):
        try:
            if encoding:
                items, out, map_path = args
                res = embed_data(self.file_path, out, items, map_path)
            else:
                res = extract_data(self.file_path, args[0])
        except Exception as e:
            res = f"ERROR: {e}" if encoding else ("error", str(e))
        # Tkinter thread-safe değildir → sonucu ana thread'e gönder
        self.root.after(0, self.show_result, res, encoding)

    def _show_text(self, text):
        self.txt.config(state="normal")
        self.txt.delete("1.0", tk.END)
        self.txt.insert("1.0", text)
        self.txt.config(state="disabled")

    def show_result(self, res, encoding):
        self.busy = False
        self.update_capacity()
        self.lbl_status.config(text="")
        if encoding:
            if res.startswith("Success"):
                messagebox.showinfo("Success", res)
            else:
                messagebox.showerror("Error", res)
            return
        if self.encoding:                            # kullanıcı bu arada mod değiştirdiyse
            return
        kind = res[0]
        if kind == "error":
            self._show_text("ERROR: " + res[1])
        elif kind == "text":
            self._show_text(res[1])
        else:                                        # dosya: nereye kaydedileceğini sor
            name, data = res[1], res[2]
            info = f"Hidden file: {name}  ({human_size(len(data))})\n"
            path = filedialog.asksaveasfilename(title="Save hidden file", initialfile=name,
                                                filetypes=[("All files", "*.*")])
            if not path:
                self._show_text(info + "\nNot saved. Press REVEAL again to save it.")
                return
            try:
                with open(path, "wb") as f:
                    f.write(data)
            except OSError as e:
                self._show_text(info + f"\nCould not save: {e}")
                return
            self._show_text(info + f"Saved to: {path}\n\nThe file was NOT opened automatically. "
                                   "Be careful with executable files (.exe, .bat, .js, .vbs…) "
                                   "from sources you don't trust.")


if __name__ == "__main__":
    root = TkinterDnD.Tk() if HAS_DND else tk.Tk()
    StegoApp(root)
    root.mainloop()
