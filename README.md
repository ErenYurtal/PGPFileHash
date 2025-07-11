# PGPFileHash

A simple command-line utility for PGP file encryption and decryption using BouncyCastle and Java 17.

## Features

- Encrypt any file using a recipient’s public key (ASCII-armored or binary).
- Decrypt PGP-encrypted files with your private key and passphrase.
- Specify custom output directory and filename for both encryption and decryption.
- Optional ASCII-armoring (`.asc`) and integrity protection (MDC).
- Cross-platform: runs wherever Java 17 and Maven are available.

## Prerequisites

- Java 17 SDK
- Apache Maven 3.6+

## GPG Key Generation

If you haven’t generated your own key pair yet:

```bash
# 1. Generate a new key with full options
gpg --full-generate-key

# 2. Export public and private keys in ASCII-armored format
gpg --export --armor you@example.com > pub.asc
gpg --export-secret-keys --armor you@example.com > priv.asc
```

## Getting Started

1. **Clone the repository**
   ```bash
   git clone https://github.com/your-username/PGPFileHash.git
   cd PGPFileHash
   ```

2. **Build the project**
   ```bash
   mvn clean package
   ```

3. **Run the application**
   ```bash
   java -jar target/PGPFileHash-1.0.jar
   ```

## Usage

When you run the JAR, you’ll see a menu:

1. **Encrypt a file**
   - Select `1`.
   - Enter the path to the file to encrypt (e.g. `/path/to/plain.txt`).
   - Enter the path to the public key file (e.g. `/path/to/public.asc`).
   - **Enter the directory where the encrypted file should be saved** (e.g. `/output/dir`).
   - **Enter the name for the encrypted file** (e.g. `secret.pgp`).
   - The tool will write the encrypted output to `<directory>/<filename>`.

2. **Decrypt a file**
   - Select `2`.
   - Enter the path to the encrypted file (e.g. `secret.pgp`).
   - Enter the path to your private key file (e.g. `/path/to/private.asc`).
   - Enter your passphrase (input is hidden in a real terminal; !! visible in IDEs).
   - **Enter the directory where the decrypted file should be saved** (e.g. `/output/dir`).
   - The tool will write the decrypted output to `<directory>/<original_filename>`.

3. **Quit**
   - Press `q` at the menu to exit.

## Project Structure

```
PGPFileHash/
├── pom.xml
└── src/
    ├── main/
    │   └── java/io/github/erenyurtal/
    │       ├── Main.java
    │       └── EncryptDecrypt.java
    └── test/        ← (Optional) add JUnit tests here
```

## .gitignore

Exclude:

- Maven build output (`/target/`)
- IDE settings (`.idea/`, `.vscode/`, etc.)
- OS junk (`.DS_Store`, `Thumbs.db`)
- Sensitive key files (`*.asc`, `*.gpg`, `*.key`, `*.pgp`)
- Generated artifacts (`*.class`, `*.jar`, etc.)

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/your-feature`)
3. Commit your changes (`git commit -m "Add your feature"`)
4. Push to your branch (`git push origin feature/your-feature`)
5. Open a Pull Request

## License

MIT License

```
MIT License

Copyright (c) 2025 Eren Yurtal

Permission is hereby granted, free of charge, to any person obtaining a copy  
of this software and associated documentation files (the “Software”), to deal  
in the Software without restriction, including without limitation the rights  
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell  
copies of the Software, and to permit persons to whom the Software is  
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all  
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR  
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,  
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE  
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER  
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,  
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE  
SOFTWARE.
```