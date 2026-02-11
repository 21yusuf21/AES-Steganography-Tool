import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
import cv2
import numpy as np
import random
import os
import threading
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import SHA256

# ==========================================
# PART 1: CORE HELPER FUNCTIONS
# ==========================================

def read_image_unicode(path):
    """
    Reads images from paths containing special/Unicode characters.
    Standard cv2.imread fails with non-ASCII paths on Windows.
    """
    try:
        with open(path, "rb") as f:
            bytes_data = bytearray(f.read())
            numpy_array = np.asarray(bytes_data, dtype=np.uint8)
            image = cv2.imdecode(numpy_array, cv2.IMREAD_UNCHANGED)
            return image
    except Exception as e:
        print(f"Image Read Error: {e}")
        return None

def save_image_unicode(path, img):
    """Saves images to paths containing special/Unicode characters."""
    try:
        ext = os.path.splitext(path)[1]
        result, n = cv2.imencode(ext, img)
        if result:
            with open(path, mode='wb') as f:
                n.tofile(f)
            return True
        return False
    except:
        return False

def encrypt_aes(plain_text, password):
    """Encrypts text using AES-256 (CBC Mode)."""
    key = SHA256.new(password.encode('utf-8')).digest()
    cipher = AES.new(key, AES.MODE_CBC)
    iv = cipher.iv
    encrypted_bytes = cipher.encrypt(pad(plain_text.encode('utf-8'), AES.block_size))
    return iv + encrypted_bytes

def decrypt_aes(encrypted_data_with_iv, password):
    """Decrypts AES-256 encrypted bytes."""
    try:
        key = SHA256.new(password.encode('utf-8')).digest()
        iv = encrypted_data_with_iv[:16]
        ciphertext = encrypted_data_with_iv[16:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(ciphertext), AES.block_size).decode('utf-8')
    except:
        return None # Return None if decryption fails (Wrong Key/IV)

def bytes_to_binary(byte_data):
    """Converts bytes to a binary string (0s and 1s)."""
    bit_string = ''.join(format(byte, '08b') for byte in byte_data)
    length = len(bit_string)
    length_bin = format(length, '032b') # 32-bit header for length
    return length_bin + bit_string

# ==========================================
# PART 2: ENCODER (HIDING DATA)
# ==========================================

def embed_data(image_path, output_path, secret_text, password):
    # Read image using unicode-safe function
    img = read_image_unicode(image_path)
    if img is None:
        return f"ERROR: Could not read image!\nPath: {image_path}\n(Check file path and permissions.)"

    stego_img = img.copy()
    height, width = img.shape[:2]
    
    # Check for Color Channel
    if len(img.shape) > 2:
        b_channel = img[:, :, 0].astype(np.float32)
    else:
        return "ERROR: Please select a color image (JPG/PNG)."

    # Encrypt the message
    try:
        encrypted_data = encrypt_aes(secret_text, password)
    except Exception as e:
        return f"Encryption Error: {str(e)}"

    full_data_bits = bytes_to_binary(encrypted_data)
    data_length = len(full_data_bits)
    
    # Settings (Robust & Secure)
    Q = 15          # Quantization Step
    U, V = 4, 1     # Middle Frequency Coordinate
    total_blocks = (height // 8) * (width // 8)
    
    # Capacity Check (1 bit needs 3 blocks for redundancy)
    if data_length * 3 > total_blocks:
        return f"ERROR: Message is too long! ({data_length} bits)\nIt does not fit in this image."

    # Generate Random Map based on Password (Seed)
    block_map = list(range(total_blocks))
    random.seed(password)
    random.shuffle(block_map)
    
    # Embedding Loop
    for i in range(data_length):
        bit = int(full_data_bits[i])
        indices = [block_map[i*3], block_map[i*3+1], block_map[i*3+2]]
        
        for idx in indices:
            row, col = idx // (width // 8), idx % (width // 8)
            y, x = row * 8, col * 8
            
            block = b_channel[y:y+8, x:x+8]
            dct_block = cv2.dct(block)
            
            # QIM (Quantization Index Modulation)
            coeff = dct_block[U, V]
            if bit == 0:
                new_coeff = round(coeff / Q) * Q
            else:
                new_coeff = round((coeff - (Q/2)) / Q) * Q + (Q/2)
                
            dct_block[U, V] = new_coeff
            stego_img[y:y+8, x:x+8, 0] = cv2.idct(dct_block)

    # Save Stego Image
    success = save_image_unicode(output_path, stego_img)
    if success:
        return "Success"
    else:
        return f"ERROR: Could not save image!\nPath: {output_path}"

# ==========================================
# PART 3: DECODER (EXTRACTING DATA)
# ==========================================

def extract_data(image_path, password):
    img = read_image_unicode(image_path)
    if img is None:
        return f"ERROR: Could not read image!\nPath: {image_path}"

    height, width = img.shape[:2]
    if len(img.shape) > 2:
        b_channel = img[:, :, 0].astype(np.float32)
    else:
        return "ERROR: Color image required."
    
    Q, U, V = 15, 4, 1
    total_blocks = (height // 8) * (width // 8)
    
    block_map = list(range(total_blocks))
    random.seed(password)
    random.shuffle(block_map)
    
    # Distributed Voting Mechanism
    def get_vote(bit_idx):
        indices = [block_map[bit_idx*3], block_map[bit_idx*3+1], block_map[bit_idx*3+2]]
        votes = []
        for idx in indices:
            row, col = idx // (width // 8), idx % (width // 8)
            y, x = row * 8, col * 8
            dct = cv2.dct(b_channel[y:y+8, x:x+8])
            val = dct[U, V]
            
            # Distance to nearest '0' or '1'
            d0 = abs(val - round(val / Q) * Q)
            d1 = abs(val - (round((val - (Q/2)) / Q) * Q + (Q/2)))
            votes.append(1 if d1 < d0 else 0)
        
        # Majority Vote (2 out of 3)
        return '1' if sum(votes) >= 2 else '0'

    # Read Header (First 32 bits)
    header_bits = ""
    for i in range(32):
        header_bits += get_vote(i)
        
    try:
        length = int(header_bits, 2)
    except:
        return "ERROR: Could not read data header."

    # Sanity Check
    if length > 50000 or length <= 0:
        return "ERROR: Wrong password or no data found in image."

    # Read Payload
    payload_bits = ""
    for i in range(32, 32 + length):
        payload_bits += get_vote(i)
        
    encrypted_bytes = bytearray()
    for i in range(0, len(payload_bits), 8):
        chunk = payload_bits[i:i+8]
        if len(chunk) == 8:
            try:
                encrypted_bytes.append(int(chunk, 2))
            except: pass
            
    # Decrypt AES
    result = decrypt_aes(bytes(encrypted_bytes), password)
    if result is None:
        return "ERROR: Password (Seed) was correct, but AES Key was wrong.\nData might be corrupted or password typo."
    return result

# ==========================================
# PART 4: GUI (USER INTERFACE)
# ==========================================

class StegoApp:
    def __init__(self, root):
        self.root = root
        self.root.title("AES Steganography Tool (Final)")
        self.root.geometry("600x520")
        self.root.configure(bg="#1e1e1e")
        self.setup_ui()

    def setup_ui(self):
        # Header
        tk.Label(self.root, text="AES Crypto-Stego Station", fg="#00ff00", bg="#1e1e1e", font=("Courier", 18, "bold")).pack(pady=15)
        
        # Mode Toggle
        self.mode = tk.StringVar(value="ENCODE")
        toggle_frame = tk.Frame(self.root, bg="#1e1e1e")
        toggle_frame.pack(pady=5)
        
        tk.Radiobutton(toggle_frame, text="HIDE DATA (ENCODE)", variable=self.mode, value="ENCODE", 
                       fg="#00ff00", bg="#1e1e1e", selectcolor="#333", activebackground="#1e1e1e", activeforeground="#00ff00",
                       font=("Arial", 10, "bold"), command=self.refresh).pack(side="left", padx=15)
                       
        tk.Radiobutton(toggle_frame, text="REVEAL DATA (DECODE)", variable=self.mode, value="DECODE", 
                       fg="#ff3333", bg="#1e1e1e", selectcolor="#333", activebackground="#1e1e1e", activeforeground="#ff3333",
                       font=("Arial", 10, "bold"), command=self.refresh).pack(side="left", padx=15)

        # Content Frame
        self.main_frame = tk.Frame(self.root, bg="#252526", padx=20, pady=20, relief="flat", bd=2)
        self.main_frame.pack(expand=True, fill="both", padx=20, pady=10)
        
        self.refresh()

    def refresh(self):
        # Clear frame
        for w in self.main_frame.winfo_children(): w.destroy()
        
        # Dynamic Button Text
        btn_text = "Select Image (to Hide)" if self.mode.get() == "ENCODE" else "Select Image (to Reveal)"
        tk.Button(self.main_frame, text=btn_text, command=self.select_file, 
                  width=25, bg="#444", fg="white", font=("Arial", 10)).pack(pady=5)
                  
        self.lbl_path = tk.Label(self.main_frame, text="No file selected", fg="#aaa", bg="#252526", font=("Arial", 9, "italic"))
        self.lbl_path.pack()

        tk.Label(self.main_frame, text="Password (Seed):", fg="white", bg="#252526", font=("Arial", 10, "bold")).pack(pady=(15,0))
        self.ent_pwd = tk.Entry(self.main_frame, show="*", width=35, bg="#333", fg="white", insertbackground="white")
        self.ent_pwd.pack(pady=5)

        if self.mode.get() == "ENCODE":
            tk.Label(self.main_frame, text="Secret Message:", fg="white", bg="#252526", font=("Arial", 10, "bold")).pack(pady=(10,0))
            # Matrix Style Input
            self.txt_msg = scrolledtext.ScrolledText(self.main_frame, height=6, width=55, 
                                                     bg="#333", fg="#00ff00", insertbackground="white", 
                                                     font=("Consolas", 10))
            self.txt_msg.pack(pady=5)
            tk.Button(self.main_frame, text="🔒 ENCRYPT & HIDE", bg="#2e7d32", fg="white", 
                      font=("Arial", 11, "bold"), width=20, command=self.run).pack(pady=15)
        else:
            tk.Label(self.main_frame, text="Decoded Message:", fg="white", bg="#252526", font=("Arial", 10, "bold")).pack(pady=(10,0))
            # Matrix Style Output
            self.txt_res = scrolledtext.ScrolledText(self.main_frame, height=6, width=55, 
                                                     state="disabled", bg="#333", fg="#00ff00", 
                                                     font=("Consolas", 10))
            self.txt_res.pack(pady=5)
            tk.Button(self.main_frame, text="🔓 DECRYPT & REVEAL", bg="#c62828", fg="white", 
                      font=("Arial", 11, "bold"), width=20, command=self.run).pack(pady=15)

    def select_file(self):
        self.file_path = filedialog.askopenfilename(filetypes=[("Image Files", "*.jpg *.png *.jpeg *.bmp")])
        if self.file_path: self.lbl_path.config(text=os.path.basename(self.file_path))

    def run(self):
        pwd = self.ent_pwd.get()
        if not hasattr(self, 'file_path') or not pwd:
            return messagebox.showerror("Error", "Please select an image and enter a password.")
        
        # Run in separate thread to keep GUI responsive
        threading.Thread(target=self.process_thread, args=(pwd,)).start()

    def process_thread(self, password):
        try:
            if self.mode.get() == "ENCODE":
                msg = self.txt_msg.get("1.0", tk.END).strip()
                if not msg: 
                    messagebox.showwarning("Warning", "Secret message cannot be empty.")
                    return
                
                folder = os.path.dirname(self.file_path)
                output_path = os.path.join(folder, "secret_final.png")
                
                res = embed_data(self.file_path, output_path, msg, password)
                
                if res == "Success":
                    messagebox.showinfo("Success", f"Stego-image created successfully:\n{output_path}")
                else:
                    messagebox.showerror("Error", res)
            else:
                res = extract_data(self.file_path, password)
                
                self.txt_res.config(state="normal")
                self.txt_res.delete("1.0", tk.END)
                self.txt_res.insert("1.0", str(res))
                self.txt_res.config(state="disabled")
        except Exception as e:
            messagebox.showerror("Critical Error", str(e))

if __name__ == "__main__":
    root = tk.Tk()
    StegoApp(root)
    root.mainloop()