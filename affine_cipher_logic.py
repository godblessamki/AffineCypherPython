# affine_cipher_logic.py
import math
import re

class AffineCipher:
    def __init__(self):
        # Rozšířená abeceda - písmena A-Z + číslice 0-9
        self.alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        self.m = len(self.alphabet)  # 36 znaků
        
        # Mapování pro konverzi
        self.char_to_index = {char: i for i, char in enumerate(self.alphabet)}
        self.index_to_char = {i: char for i, char in enumerate(self.alphabet)}
    
    def filter_input_text(self, text):
        """Filtruje vstupní text: odstraní diakritiku, převede na velká písmena,
        nahradí mezery speciálním tokenem a odstraní speciální znaky."""
        if not text:
            return ""
        
        # Mapa pro odstranění diakritiky
        diakritic_map = {
            'á': 'A', 'à': 'A', 'â': 'A', 'ä': 'A', 'ã': 'A', 'å': 'A',
            'é': 'E', 'è': 'E', 'ê': 'E', 'ë': 'E',
            'í': 'I', 'ì': 'I', 'î': 'I', 'ï': 'I',
            'ó': 'O', 'ò': 'O', 'ô': 'O', 'ö': 'O', 'õ': 'O', 'ø': 'O',
            'ú': 'U', 'ù': 'U', 'û': 'U', 'ü': 'U',
            'ý': 'Y', 'ÿ': 'Y',
            'ň': 'N', 'ñ': 'N',
            'č': 'C', 'ć': 'C', 'ç': 'C',
            'ř': 'R',
            'š': 'S', 'ś': 'S',
            'ť': 'T',
            'ž': 'Z', 'ź': 'Z',
            'ď': 'D',
            'ľ': 'L', 'ł': 'L',
            'ĺ': 'L',
            'ô': 'O'
        }
        
        # Add uppercase versions of diacritics to the map
        upper_diakritic_map = {k.upper(): v for k, v in diakritic_map.items()}
        diakritic_map.update(upper_diakritic_map)
        
        # Převod na velká písmena a odstranění diakritiky
        filtered = ""
        for char in text.upper():
            if char in diakritic_map:
                filtered += diakritic_map[char]
            elif char == ' ':
                filtered += 'XMEZERAX'
            elif char.isalnum():  # Písmena a číslice
                filtered += char
            # Speciální znaky ignorujeme
        
        return filtered
    
    def restore_spaces(self, text):
        return text.replace('XMEZERAX', ' ')
    
    def validate_key_a(self, a):
        try:
            a = int(a)
            if a < 1 or a >= self.m:
                return False, f"Klíč 'a' musí být mezi 1 a {self.m-1}"
            if math.gcd(a, self.m) != 1:
                return False, f"Klíč 'a' musí být nesoudělný s {self.m} (GCD musí být 1)"
            return True, ""
        except ValueError:
            return False, "Klíč 'a' musí být celé číslo"
    
    def validate_key_b(self, b):
        """Ověří, zda je klíč 'b' platný"""
        try:
            b = int(b)
            if b < 0 or b >= self.m:
                return False, f"Klíč 'b' musí být mezi 0 a {self.m-1}"
            return True, ""
        except ValueError:
            return False, "Klíč 'b' musí být celé číslo"
    
    def find_multiplicative_inverse(self, a):
        for i in range(1, self.m):
            if (a * i) % self.m == 1:
                return i
        return None
    
    def encrypt(self, plaintext, a, b):
        valid_a, msg_a = self.validate_key_a(a)
        if not valid_a:
            return None, msg_a
        
        valid_b, msg_b = self.validate_key_b(b)
        if not valid_b:
            return None, msg_b
        
        a, b = int(a), int(b)
        
        filtered_text = self.filter_input_text(plaintext)
        if not filtered_text:
            return None, "Vstupní text je prázdný nebo neobsahuje platné znaky"
        
        ciphertext = ""
        for char in filtered_text:
            if char in self.char_to_index:
                x = self.char_to_index[char]
                encrypted_index = (a * x + b) % self.m
                ciphertext += self.index_to_char[encrypted_index]
        
        # Formátování výstupu po pěticích
        formatted_cipher = self.format_in_groups(ciphertext, 5)
        
        return {
            'original_text': plaintext,
            'filtered_text': filtered_text,
            'ciphertext': ciphertext,
            'formatted_ciphertext': formatted_cipher,
            'original_alphabet': self.alphabet,
            'cipher_alphabet': self.generate_cipher_alphabet(a, b)
        }, ""
    
    def decrypt(self, ciphertext, a, b):
        """
        Dešifruje text pomocí afinní šifry
        Vzorec: OT = a_inv * (ŠT - b) mod m
        """
        # Validace klíčů
        valid_a, msg_a = self.validate_key_a(a)
        if not valid_a:
            return None, msg_a
        
        valid_b, msg_b = self.validate_key_b(b)
        if not valid_b:
            return None, msg_b
        
        a, b = int(a), int(b)
        
        # Najdeme multiplikativní inverzi
        a_inv = self.find_multiplicative_inverse(a)
        if a_inv is None:
            return None, f"Nepodařilo se najít multiplikativní inverzi pro klíč 'a' = {a}"
        
        # Odstranění mezer a převod na velká písmena
        clean_cipher = ciphertext.replace(' ', '').upper()
        
        if not clean_cipher:
            return None, "Zašifrovaný text je prázdný"
        
        # Dešifrování
        plaintext = ""
        for char in clean_cipher:
            if char in self.char_to_index:
                y = self.char_to_index[char]
                decrypted_index = (a_inv * (y - b)) % self.m
                plaintext += self.index_to_char[decrypted_index]
        
        # Obnovení mezer
        restored_text = self.restore_spaces(plaintext)
        
        return {
            'ciphertext': ciphertext,
            'clean_ciphertext': clean_cipher,
            'decrypted_text': plaintext,
            'restored_text': restored_text,
            'original_alphabet': self.alphabet,
            'cipher_alphabet': self.generate_cipher_alphabet(a, b)
        }, ""
    
    def format_in_groups(self, text, group_size=5):
        """Formátuje text po skupinách znaků oddělených mezerami"""
        return ' '.join([text[i:i+group_size] for i in range(0, len(text), group_size)])
    
    def generate_cipher_alphabet(self, a, b):
        """Generuje šifrovou abecedu pro dané klíče"""
        cipher_alphabet = ""
        for i in range(self.m):
            encrypted_index = (a * i + b) % self.m
            cipher_alphabet += self.index_to_char[encrypted_index]
        return cipher_alphabet

# Testovací funkce
def test_affine_cipher():
    """Testovací funkce pro ověření správnosti algoritmu"""
    cipher = AffineCipher()
    
    # Test 1: Základní šifrování
    test_text = "Ahoj Pepo, sejdeme se v 5 u mostu."
    a, b = 5, 3
    
    print("=== Test Afinní šifry ===")
    print(f"Původní text: {test_text}")
    print(f"Klíče: a={a}, b={b}")
    
    # Šifrování
    encrypt_result, encrypt_error = cipher.encrypt(test_text, a, b)
    if encrypt_error:
        print(f"Chyba při šifrování: {encrypt_error}")
        return
    
    print(f"Filtrovaný text: {encrypt_result['filtered_text']}")
    print(f"Zašifrovaný text: {encrypt_result['formatted_ciphertext']}")
    print(f"Původní abeceda: {encrypt_result['original_alphabet']}")
    print(f"Šifrová abeceda:  {encrypt_result['cipher_alphabet']}")
    
    # Dešifrování
    decrypt_result, decrypt_error = cipher.decrypt(encrypt_result['formatted_ciphertext'], a, b)
    if decrypt_error:
        print(f"Chyba při dešifrování: {decrypt_error}")
        return
    
    print(f"Dešifrovaný text: {decrypt_result['restored_text']}")
    
    # Ověření
    original_upper = test_text.upper().replace(',', '').replace('.', '')
    if decrypt_result['restored_text'] == cipher.filter_input_text(test_text).replace('XMEZERAX', ' '):
        print("✓ Test prošel úspěšně!")
    else:
        print("✗ Test selhal!")

if __name__ == "__main__":
    test_affine_cipher()