import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
from affine_cipher_logic import AffineCipher

class AffineCipherGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Affine Cipher — Encrypt / Decrypt")
        self.root.geometry("820x640")
        self.root.minsize(820, 640)
        self.root.configure(bg='#ffffff')
        self.cipher = AffineCipher()
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        self.create_scrollable_frame()
        self.create_widgets()
        self.setup_styles()
    
    def create_scrollable_frame(self):
        self.canvas = tk.Canvas(self.root, bg='#ffffff', highlightthickness=0)
        self.scrollbar = ttk.Scrollbar(self.root, orient="vertical", command=self.canvas.yview)
        self.scrollable_frame = ttk.Frame(self.canvas)
        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all"))
        )
        self.canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        self.canvas.configure(yscrollcommand=self.scrollbar.set)
        self.canvas.pack(side="left", fill="both", expand=True, padx=12, pady=12)
        self.scrollbar.pack(side="right", fill="y")
        self.canvas.bind_all("<MouseWheel>", self._on_mousewheel)
    
    def _on_mousewheel(self, event):
        self.canvas.yview_scroll(int(-1*(event.delta/120)), "units")
    
    def setup_styles(self):
        style = ttk.Style()
        try:
            style.theme_use('clam')
        except:
            pass
        base_bg = '#ffffff'
        base_fg = '#111111'
        accent = '#111111'
        style.configure('TFrame', background=base_bg)
        style.configure('TLabel', background=base_bg, foreground=base_fg, font=('Segoe UI', 10))
        style.configure('Title.TLabel', font=('Segoe UI', 16, 'bold'), foreground=accent, background=base_bg)
        style.configure('Header.TLabel', font=('Segoe UI', 11, 'bold'), foreground=accent, background=base_bg)
        style.configure('Info.TLabel', font=('Segoe UI', 9), foreground='#444444', background=base_bg)
        style.configure('TButton', font=('Segoe UI', 10), foreground=base_fg)
        style.configure('Action.TButton', font=('Segoe UI', 10, 'bold'))
        style.configure('TEntry', fieldbackground='#ffffff', foreground=base_fg)
        style.configure('TLabelframe', background=base_bg, foreground=base_fg)
        style.configure('TLabelframe.Label', background=base_bg, foreground=base_fg, font=('Segoe UI', 10, 'bold'))
    
    def create_widgets(self):
        main_frame = ttk.Frame(self.scrollable_frame, padding=14)
        main_frame.pack(fill=tk.BOTH, expand=True)
        title_label = ttk.Label(main_frame, text="Affine Cipher — Linear Shift", style='Title.TLabel')
        title_label.pack(pady=(0, 18))
        self.create_keys_section(main_frame)
        self.create_encryption_section(main_frame)
        self.create_decryption_section(main_frame)
        self.create_results_section(main_frame)
        self.create_alphabet_section(main_frame)
    
    def create_keys_section(self, parent):
        keys_frame = ttk.LabelFrame(parent, text="Key Settings", padding=12)
        keys_frame.pack(fill=tk.X, pady=(0, 14))
        info_text = "Key a must be coprime with 36. Key b should be 0–35."
        ttk.Label(keys_frame, text=info_text, style='Info.TLabel').pack(pady=(0, 10), anchor=tk.W)
        keys_input_frame = ttk.Frame(keys_frame)
        keys_input_frame.pack(fill=tk.X)
        ttk.Label(keys_input_frame, text="Key a:", style='Header.TLabel').grid(row=0, column=0, padx=(0, 8), pady=6, sticky=tk.W)
        self.key_a_var = tk.StringVar(value="5")
        self.key_a_entry = ttk.Entry(keys_input_frame, textvariable=self.key_a_var, width=10)
        self.key_a_entry.grid(row=0, column=1, padx=(0, 24), pady=6, sticky=tk.W)
        ttk.Label(keys_input_frame, text="Key b:", style='Header.TLabel').grid(row=0, column=2, padx=(0, 8), pady=6, sticky=tk.W)
        self.key_b_var = tk.StringVar(value="3")
        self.key_b_entry = ttk.Entry(keys_input_frame, textvariable=self.key_b_var, width=10)
        self.key_b_entry.grid(row=0, column=3, pady=6, sticky=tk.W)
        validate_btn = ttk.Button(keys_input_frame, text="Validate keys", command=self.validate_keys, style='Action.TButton')
        validate_btn.grid(row=0, column=4, padx=(18, 0), pady=6, sticky=tk.W)
    
    def create_encryption_section(self, parent):
        encrypt_frame = ttk.LabelFrame(parent, text="Encryption", padding=12)
        encrypt_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 14))
        ttk.Label(encrypt_frame, text="Plaintext:", style='Header.TLabel').pack(anchor=tk.W, pady=(0, 6))
        self.input_text = scrolledtext.ScrolledText(encrypt_frame, height=4, font=('Consolas', 11), wrap=tk.WORD, bg='#ffffff', fg='#000000', relief='flat')
        self.input_text.pack(fill=tk.BOTH, expand=True, pady=(0, 12))
        encrypt_buttons_frame = ttk.Frame(encrypt_frame)
        encrypt_buttons_frame.pack()
        encrypt_btn = ttk.Button(encrypt_buttons_frame, text="Encrypt", command=self.encrypt_text, style='Action.TButton')
        encrypt_btn.pack(side=tk.LEFT, padx=(0, 10))
        clear_input_btn = ttk.Button(encrypt_buttons_frame, text="Clear input", command=lambda: self.input_text.delete(1.0, tk.END))
        clear_input_btn.pack(side=tk.LEFT)
    
    def create_decryption_section(self, parent):
        decrypt_frame = ttk.LabelFrame(parent, text="Decryption", padding=12)
        decrypt_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 14))
        ttk.Label(decrypt_frame, text="Ciphertext:", style='Header.TLabel').pack(anchor=tk.W, pady=(0, 6))
        self.cipher_input_text = scrolledtext.ScrolledText(decrypt_frame, height=4, font=('Consolas', 11), wrap=tk.WORD, bg='#ffffff', fg='#000000', relief='flat')
        self.cipher_input_text.pack(fill=tk.BOTH, expand=True, pady=(0, 12))
        decrypt_buttons_frame = ttk.Frame(decrypt_frame)
        decrypt_buttons_frame.pack()
        decrypt_btn = ttk.Button(decrypt_buttons_frame, text="Decrypt", command=self.decrypt_text, style='Action.TButton')
        decrypt_btn.pack(side=tk.LEFT, padx=(0, 10))
        clear_cipher_btn = ttk.Button(decrypt_buttons_frame, text="Clear input", command=lambda: self.cipher_input_text.delete(1.0, tk.END))
        clear_cipher_btn.pack(side=tk.LEFT)
    
    def create_results_section(self, parent):
        results_frame = ttk.LabelFrame(parent, text="Results", padding=12)
        results_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 14))
        self.results_text = scrolledtext.ScrolledText(results_frame, height=8, font=('Consolas', 10), wrap=tk.WORD, state=tk.DISABLED, bg='#fafafa', fg='#000000', relief='flat')
        self.results_text.pack(fill=tk.BOTH, expand=True, pady=(0, 12))
        clear_results_btn = ttk.Button(results_frame, text="Clear results", command=self.clear_results)
        clear_results_btn.pack()
    
    def create_alphabet_section(self, parent):
        alphabet_frame = ttk.LabelFrame(parent, text="Alphabets", padding=12)
        alphabet_frame.pack(fill=tk.X, pady=(0, 14))
        ttk.Label(alphabet_frame, text="Original alphabet:", style='Header.TLabel').pack(anchor=tk.W)
        self.original_alphabet_label = ttk.Label(alphabet_frame, text=self.cipher.alphabet, font=('Consolas', 10), foreground='#111111', background='#ffffff')
        self.original_alphabet_label.pack(anchor=tk.W, pady=(4, 10))
        ttk.Label(alphabet_frame, text="Cipher alphabet:", style='Header.TLabel').pack(anchor=tk.W)
        self.cipher_alphabet_label = ttk.Label(alphabet_frame, text="(Enter keys and run)", font=('Consolas', 10), foreground='#666666', background='#ffffff')
        self.cipher_alphabet_label.pack(anchor=tk.W)
    
    def validate_keys(self):
        a = self.key_a_var.get()
        b = self.key_b_var.get()
        valid_a, msg_a = self.cipher.validate_key_a(a)
        valid_b, msg_b = self.cipher.validate_key_b(b)
        if valid_a and valid_b:
            messagebox.showinfo("Keys validated", "Both keys are valid.")
            cipher_alphabet = self.cipher.generate_cipher_alphabet(int(a), int(b))
            self.cipher_alphabet_label.config(text=cipher_alphabet, foreground='#111111')
        else:
            error_msg = []
            if not valid_a:
                error_msg.append(f"a: {msg_a}")
            if not valid_b:
                error_msg.append(f"b: {msg_b}")
            messagebox.showerror("Validation error", "\n".join(error_msg))
    
    def encrypt_text(self):
        plaintext = self.input_text.get(1.0, tk.END).strip()
        if not plaintext:
            messagebox.showwarning("Warning", "Please enter plaintext to encrypt.")
            return
        a = self.key_a_var.get()
        b = self.key_b_var.get()
        result, error = self.cipher.encrypt(plaintext, a, b)
        if error:
            messagebox.showerror("Encryption error", error)
            return
        self.display_encryption_results(result)
        self.cipher_alphabet_label.config(text=result['cipher_alphabet'], foreground='#111111')
    
    def decrypt_text(self):
        ciphertext = self.cipher_input_text.get(1.0, tk.END).strip()
        if not ciphertext:
            messagebox.showwarning("Warning", "Please enter ciphertext to decrypt.")
            return
        a = self.key_a_var.get()
        b = self.key_b_var.get()
        result, error = self.cipher.decrypt(ciphertext, a, b)
        if error:
            messagebox.showerror("Decryption error", error)
            return
        self.display_decryption_results(result)
        self.cipher_alphabet_label.config(text=result['cipher_alphabet'], foreground='#111111')
    
    def display_encryption_results(self, result):
        self.results_text.config(state=tk.NORMAL)
        self.results_text.delete(1.0, tk.END)
        output = (
            "ENCRYPTION RESULTS\n"
            + "="*60 + "\n\n"
            f"Original text:\n{result['original_text']}\n\n"
            f"Filtered text:\n{result['filtered_text']}\n\n"
            f"Ciphertext:\n{result['formatted_ciphertext']}\n\n"
            "Info:\n"
            f"- keys: a={self.key_a_var.get()}, b={self.key_b_var.get()}\n"
            f"- original length: {len(result['original_text'])}\n"
            f"- filtered length: {len(result['filtered_text'])}\n"
            f"- ciphertext length: {len(result['ciphertext'])}\n\n"
            + "-"*60 + "\n"
        )
        self.results_text.insert(tk.END, output)
        self.results_text.config(state=tk.DISABLED)
    
    def display_decryption_results(self, result):
        self.results_text.config(state=tk.NORMAL)
        self.results_text.delete(1.0, tk.END)
        output = (
            "DECRYPTION RESULTS\n"
            + "="*60 + "\n\n"
            f"Input ciphertext:\n{result['ciphertext']}\n\n"
            f"Clean ciphertext:\n{result['clean_ciphertext']}\n\n"
            f"Decrypted (no spaces):\n{result['decrypted_text']}\n\n"
            f"Restored text:\n{result['restored_text']}\n\n"
            "Info:\n"
            f"- keys: a={self.key_a_var.get()}, b={self.key_b_var.get()}\n"
            f"- input length: {len(result['ciphertext'])}\n"
            f"- clean length: {len(result['clean_ciphertext'])}\n"
            f"- restored length: {len(result['restored_text'])}\n\n"
            + "-"*60 + "\n"
        )
        self.results_text.insert(tk.END, output)
        self.results_text.config(state=tk.DISABLED)
    
    def clear_results(self):
        self.results_text.config(state=tk.NORMAL)
        self.results_text.delete(1.0, tk.END)
        self.results_text.config(state=tk.DISABLED)
    
    def clear_all(self):
        self.input_text.delete(1.0, tk.END)
        self.cipher_input_text.delete(1.0, tk.END)
        self.clear_results()
        self.cipher_alphabet_label.config(text="(Enter keys and run)", foreground='#666666')

def main():
    root = tk.Tk()
    app = AffineCipherGUI(root)
    try:
        root.iconname("Affine Cipher")
    except:
        pass
    root.mainloop()

if __name__ == "__main__":
    main()