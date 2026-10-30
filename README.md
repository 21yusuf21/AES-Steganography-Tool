# AES Crypto-Stego Station

Hide encrypted messages and files inside images. Data is embedded only in the
**textured, colour-busy regions** of the picture, and one image can hold up to
**four independent messages or files, each with its own password**. Without a
password, nobody can tell how many of them are in use.


## Features

- **Texture-adaptive embedding.** Data goes into the blue channel's 8×8 DCT
  blocks, preferring the busiest regions; flat areas such as sky or walls are
  left alone.
- **Deniable lockers.** Every image always contains 4 lockers. Unused lockers
  and free space are filled with random bytes that look the same as encrypted
  data. Each password opens only its own locker.
- **Text or files.** A locker holds a text message or any file. The original
  filename is stored encrypted, and the file is restored with that name.
- **Strong encryption.** Argon2id key derivation and AES-256-GCM authenticated
  encryption. Wrong passwords and corrupted images are detected.
- **Compression.** Payloads are DEFLATE-compressed when that actually makes
  them smaller.
- **Live capacity meter** that shows how much space every locker takes while
  you type or choose files.
- **Optional block-usage map** that marks the blocks where data was embedded.

## Installation

Requires Python 3.9+.

```bash
pip install opencv-python numpy pycryptodome argon2-cffi
python stego_adaptive.py
```

## Usage

**Hide**
1. Select a cover image.
2. Pick a locker (1–4), enter a password, and write a message or choose a file.
3. Optionally fill other lockers with different passwords.
4. Click **ENCRYPT & HIDE** and save the result as **PNG** or **BMP**.

**Reveal**
1. Select the stego image and enter a password.
2. A text message is shown directly. For a file, you choose where to save it.

Each password opens only its own locker. A wrong password and an image with no
hidden data produce the same error message.

## Capacity

The capacity is shared by all lockers. Each image has a fixed overhead of 112
bytes, and each filled locker adds 17 bytes plus, for files, the filename length.

| Image size  | Available for content |
|-------------|-----------------------|
| 512×512     | ~83 B                 |
| 1280×720    | ~573 B                |
| 1920×1080   | ~1.4 KB               |
| 4000×3000   | ~8.8 KB               |

Plain-text content (.txt, .csv, .json, source code) usually compresses by
30–60%. Formats that are already compressed (.zip, .jpg, .png, .docx, .pdf)
do not shrink.

## How it works

```
[ salt 16 B ][ 4 locator cells × 24 B ][ data area (encrypted payloads + random fill) ]
```

1. **Container.** The whole capacity is written on every hide. Each password is
   run through Argon2id with the image's random salt to derive a key and two
   nonces. A locker's cell holds the AES-GCM-encrypted offset and length of its
   payload. Payload layout: `format byte | text`, or
   `format byte | name length | filename | file content`.
2. **Texture map.** A texture score is computed per 8×8 block from the **red and
   green** channels: `std(G) + std(R) + std(R−G)`. Data is written only to the
   blue channel, so R and G stay unchanged and the decoder rebuilds exactly the
   same map.
3. **Embedding.** Bits are Hamming(7,4)-encoded and spread over a fixed
   permutation of (block, coefficient) slots, 3 slots per bit. Two mid-frequency
   DCT coefficients per block are modified with QIM (quantisation step 24).
   The encoder writes only to textured slots unless a bit needs more support.
4. **Decoding.** The decoder uses texture-weighted soft voting, so untouched
   flat blocks have almost no influence on the result.

Typical quality is a PSNR of about 52 dB on a 1080p image, which is not
visible to the eye.

## Limitations

- **Lossless formats only.** Saving as JPEG, resizing, cropping or uploading
  to most social networks destroys the hidden data.
- **Limited noise robustness.** Light noise (σ≈1) is tolerated; stronger noise
  is not.
- **Not undetectable.** The method hides *how many* messages an image holds,
  not *that* steganography was used. Statistical steganalysis can detect the
  QIM traces.
- **Small capacity.** It is meant for messages, keys and small files, not
  documents or media.
- Images created with older versions of this tool cannot be decoded.

## Disclaimer

This is a hobby project and has not been independently audited. Do not rely
on it where your safety depends on it.
