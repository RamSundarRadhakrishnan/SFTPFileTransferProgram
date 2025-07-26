# SFTPFileTransferProgram
A small tool to easy transfer files between systems using SFTP - great for setting up a backup system!


`sshconnect` is a simple C command‑line utility that uses **libssh** to securely transfer a local file to a remote host over SFTP. It handles:

- SSH host‑key verification (known_hosts)
- Password authentication
- Automatic creation of an `upload/` directory on the server
- Full-file SFTP transfer with progress feedback

---

## 📋 Table of Contents

- [Prerequisites]
- [Building]
- [Usage]
- [License]
- [Contact]  

---

## 🔧 Prerequisites

- **C compiler** (e.g. `gcc` or `clang`)  
- **libssh** development headers & library
- **OpenSSL development headers & library** (usually pulled in by libssh)

## 🏗️ Building

Compile directly with:
gcc sshconnect.c -o sshconnect -lssh -lcrypto

## ▶️ Usage

./sshconnect

Enter remote host IP/hostname

Trust the host key (if first time connecting)

Enter your SSH password

Enter the local filename to upload

The file will be placed under upload/<filename> on the remote server.

## 📄 License

This project is released under the Apache 2.0 License. 

## 📫 Contact

Ram Sundar Radhakrishnan

✉️ ramsundar289@gmail.com
