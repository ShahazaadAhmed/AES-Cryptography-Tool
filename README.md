# AES Cryptography Tool

## Description
The **AES Cryptography Tool** is an advanced encryption and decryption application built using CustomTkinter and PyCryptodome. It allows users to securely encrypt messages using the AES-128-CBC algorithm and decrypt them using the correct secret key. The tool features an intuitive graphical interface designed for ease of use.

## Features
- **User-friendly GUI**: Built with CustomTkinter for a modern and responsive interface.
- **AES-128-CBC Encryption**: Secure encryption with automatic key and IV generation.
- **Message Encryption**: Converts plaintext into ciphertext securely.
- **Message Decryption**: Restores the original message when the correct key is provided.
- **Clipboard Support**: Easily copy ciphertext and keys for secure storage.
- **Reset Functionality**: Clears all input fields with a single button.

## Requirements
To run this application, ensure you have the following installed:
- **Python 3.8+**
- **CustomTkinter** (for the GUI)
- **PyCryptodome** (for AES encryption)

## Installation

1. **Clone the Repository**:
    ```bash
    git clone https://github.com/your-username/aes-cryptography-tool.git
    cd aes-cryptography-tool
    ```

2. **Install Dependencies**:
    ```bash
    pip install -r requirements.txt
    ```
    Or manually install required libraries:
    ```bash
    pip install customtkinter pycryptodome
    ```

## Usage

### Running the Application
To launch the GUI application, run:
```bash
python ciphertool.py
```
or use the excutable file
```bash
ciphertool.exe
```

### Encrypting a Message
1. Select **Encrypt** mode (default view).
2. Enter the text to be encrypted.
3. Click **Encrypt Message**.
4. The application generates:
   - **Ciphertext** (encrypted message)
   - **Secret Key** (required for decryption)
5. Copy the ciphertext and secret key for future use.

### Decrypting a Message
1. Select **Decrypt** mode.
2. Paste the encrypted **Ciphertext**.
3. Enter the corresponding **Secret Key**.
4. Click **Decrypt Message**.
5. If the correct key is provided, the original message is displayed.

### Reset Fields
To clear all input fields, click the **⟳ (refresh button)** in the top right corner.

### Troubleshooting

If you encounter any issues or errors while running the application, you can use the provided **ZIP file**:

1. **Extract the ZIP file**.
2. Locate and run the **ciphertool.exe** file.
3. Follow the encryption or decryption steps as needed.
## Project Structure
```
.
├── main.py  # Main application file
├── README.md  # Documentation file
├── requirements.txt  # Dependencies
```

## How AES-128-CBC Works
1. A **random 16-byte key** and **IV (Initialization Vector)** are generated.
2. The plaintext message is **padded** to match AES block size.
3. Encryption is performed using **AES-128 in CBC mode**.
4. The **ciphertext is Base64-encoded** for easy storage and transfer.
5. Decryption requires the **original key** and **IV** to restore the plaintext message.

## License
This project is licensed under the **MIT License**.

## Contribution
Contributions are welcome! Feel free to fork this repository, submit pull requests, or report issues.
