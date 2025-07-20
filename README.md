# 🔐 Steganography Tool (Python GUI)

A cinematic-style steganography application built with Python and `CustomTkinter`, allowing users to securely **hide messages within images**, **encrypt/decrypt messages**, and **store image-password-key data** in a local SQLite database.

---

## 🧰 Features

- 📤 Upload and preview images
- 🧬 Encode secret messages into images (with or without password)
- 🔒 Encrypt sensitive text before encoding
- 🔓 Decrypt and reveal hidden messages from images
- 💾 Store image names, passwords, and encryption keys using SQLite
- 🎨 Modern UI with custom button hover effects and color theme
- 🧠 Basic steganography using the `Stegano` LSB library
- 🛡️ AES-based encryption using `cryptography.fernet`

---

## 🖼️ Interface Preview

> *(Include a screenshot if possible here)*

---

## 🛠️ Tech Stack

- Python 3.x
- `customtkinter` for GUI
- `Stegano` for LSB steganography
- `cryptography.fernet` for symmetric encryption
- `PIL` (Pillow) for image handling
- `sqlite3` for password/key storage

---

## 🚀 Installation

```bash
git clone https://github.com/yourusername/steganography-tool.git
cd steganography-tool
pip install -r requirements.txt
python Stegnography\ Tool\ Final\ Project.py
