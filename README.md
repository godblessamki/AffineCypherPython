# Affine Cipher Python

A graphical user interface (GUI) application for encrypting and decrypting text using the Affine cipher algorithm with an extended character set.

## Overview

The Affine Cipher is a type of monoalphabetic substitution cipher where each letter in the alphabet is mapped to its numeric equivalent, encrypted using a mathematical function, and converted back to a letter. This implementation uses the formula:

- **Encryption**: `E(x) = (a*x + b) mod m`
- **Decryption**: `D(y) = a^(-1) * (y - b) mod m`

Where:
- `x` is the position of the plaintext character
- `y` is the position of the ciphertext character
- `a` and `b` are the encryption keys
- `m` is the size of the alphabet (63 characters in this implementation)

## Features

- **Extended Character Set**: Supports A-Z letters, digits 0-9, and special characters `.,!?;:+-*/<>=()[]`
- **Diacritics Support**: Automatically converts accented characters to their base form
- **Space Handling**: Preserves spaces in encrypted/decrypted text
- **User-Friendly GUI**: Clean, modern interface built with Tkinter
- **Real-time Validation**: Validates encryption keys to ensure mathematical correctness
- **Scrollable Interface**: Handles long text inputs and outputs efficiently

## Requirements

- Python 3.x
- tkinter (usually included with Python)

## Installation

1. Clone this repository:
```bash
git clone https://github.com/godblessamki/AffineCypherPython.git
cd AffineCypherPython
