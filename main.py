import customtkinter as ctk 
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64

class AESApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("AES Cryptography Tool")
        self.geometry("800x600")
        self.mode_var = ctk.StringVar(value="encrypt")
        self.key = None
        self.iv = None
        self.setup_ui()

    def setup_ui(self):
        top_frame = ctk.CTkFrame(self, height=40)
        top_frame.pack(side="top", fill="x", padx=10, pady=5)
        
        mode_frame = ctk.CTkFrame(top_frame)
        mode_frame.pack(side="left", padx=10)
        ctk.CTkRadioButton(mode_frame, text="Encrypt", variable=self.mode_var, value="encrypt", fg_color="white",hover_color="#4f4f4f",command=self.switch_mode).pack(side="left", padx=10)
        ctk.CTkRadioButton(mode_frame, text="Decrypt", variable=self.mode_var, value="decrypt",fg_color="white", hover_color="#4f4f4f",command=self.switch_mode).pack(side="left", padx=10)
        
        ctk.CTkButton(top_frame, text="⟳", width=10, height=30, fg_color="#2b2b2b", corner_radius=2000,hover_color="#1f1f1f", command=self.clear_all).pack(side="right", padx=10)

        self.encrypt_frame = self.create_encrypt_frame()
        self.decrypt_frame = self.create_decrypt_frame()
        self.switch_mode()

    def create_encrypt_frame(self):
        frame = ctk.CTkFrame(self,fg_color="#2b2b2b")
        ctk.CTkLabel(frame, text="Cipher Tool",font=ctk.CTkFont(size=30)).pack(pady=10)
        ctk.CTkLabel(frame, text="Enter Message to Encrypt:",font=ctk.CTkFont()).pack(pady=10)
        self.input_text = ctk.CTkTextbox(frame, height=150, width=500)
        self.input_text.pack(pady=7)
        ctk.CTkButton(frame, text="Encrypt Message",fg_color="#1f1f1f",hover_color="#262626", command=self.encrypt).pack(pady=10)
        result_frame = ctk.CTkFrame(frame)
        result_frame.pack(pady=40)
        ctk.CTkLabel(result_frame, text="Cipher Text:").grid(row=0, column=0, sticky="w")
        self.cipher_text = ctk.CTkTextbox(result_frame, height=100, width=250)
        self.cipher_text.grid(row=1, column=0, padx=5)
        ctk.CTkButton(result_frame,height=3,width=3, text="Copy",fg_color="#1d1e1e",hover_color="#262626", command=lambda: self.copy_to_clipboard(self.cipher_text)).place(relx=0.41,rely=0.04)
        ctk.CTkLabel(result_frame, text="Secret Key:").grid(row=0, column=1, sticky="w")
        self.key_text = ctk.CTkTextbox(result_frame, height=100, width=250)
        self.key_text.grid(row=1, column=1, padx=5)
        ctk.CTkButton(result_frame, text="Copy",height=3,width=3,fg_color="#1d1e1e",hover_color="#262626", command=lambda: self.copy_to_clipboard(self.key_text)).place(relx=0.91,rely=0.04)
        return frame

    def create_decrypt_frame(self):
        frame = ctk.CTkFrame(self)
        ctk.CTkLabel(frame, text="Cipher Text:").pack(pady=5)
        self.cipher_input = ctk.CTkTextbox(frame, height=100, width=500)
        self.cipher_input.pack(pady=5)
        ctk.CTkLabel(frame, text="Secret Key:").pack(pady=5)
        self.key_input = ctk.CTkTextbox(frame, height=100, width=500)
        self.key_input.pack(pady=5)
        ctk.CTkButton(frame, text="Decrypt Message",fg_color="#1f1f1f",hover_color="#262626", command=self.decrypt).pack(pady=10)
        ctk.CTkLabel(frame, text="Decrypted Message:").pack(pady=5)
        self.decrypted_text = ctk.CTkTextbox(frame, height=150, width=500, state="disabled")
        self.decrypted_text.pack(pady=5)
        return frame

    def switch_mode(self):
        if self.mode_var.get() == "encrypt":
            self.decrypt_frame.pack_forget()
            self.encrypt_frame.pack(fill="both", expand=True)
        else:
            self.encrypt_frame.pack_forget()
            self.decrypt_frame.pack(fill="both", expand=True)

    def clear_all(self):
        self.input_text.delete("1.0", "end")
        self.cipher_text.delete("1.0", "end")
        self.key_text.delete("1.0", "end")
        self.cipher_input.delete("1.0", "end")
        self.key_input.delete("1.0", "end")
        self.decrypted_text.configure(state="normal")
        self.decrypted_text.delete("1.0", "end")
        self.decrypted_text.configure(state="disabled")

    def encrypt(self):
        plaintext = self.input_text.get("1.0", "end").strip()
        if not plaintext:
            return
        self.key = get_random_bytes(16)
        self.iv = get_random_bytes(16)
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        ct_bytes = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
        ct = base64.b64encode(self.iv + ct_bytes).decode()
        self.cipher_text.delete("1.0", "end")
        self.cipher_text.insert("end", ct)
        self.key_text.delete("1.0", "end")
        self.key_text.insert("end", base64.b64encode(self.key).decode())

    def decrypt(self):
        ct = self.cipher_input.get("1.0", "end").strip()
        key = self.key_input.get("1.0", "end").strip()
        if not ct or not key:
            return
        try:
            key = base64.b64decode(key)
            ct = base64.b64decode(ct)
            iv = ct[:16]
            ct = ct[16:]
            cipher = AES.new(key, AES.MODE_CBC, iv)
            pt = unpad(cipher.decrypt(ct), AES.block_size).decode()
            self.decrypted_text.configure(state="normal")
            self.decrypted_text.delete("1.0", "end")
            self.decrypted_text.insert("end", pt)
            self.decrypted_text.configure(state="disabled")
        except:
            pass

    def copy_to_clipboard(self, text_widget):
        self.clipboard_clear()
        self.clipboard_append(text_widget.get("1.0", "end").strip())

if __name__ == "__main__":
    app = AESApp()
    app.mainloop()