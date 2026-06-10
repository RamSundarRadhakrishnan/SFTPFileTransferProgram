# SFTPFileTransferProgram
A small tool to easy transfer files between systems using SFTP - great for setting up a backup system!


`sshconnect` is a simple C utility that uses **libssh** to securely transfer a local file to a remote host over SFTP, using a **GTK** based window UI for ease of use. It handles:

- SSH host‑key verification (known_hosts)
- Password authentication
- Automatic creation of an `upload/` directory on the server
- Full-file SFTP transfer with progress feedback

---

## Table of Contents

- [Prerequisites]
- [Building]
- [Usage]
- [License]
- [Contact]  

---

## Prerequisites

- **C compiler** (e.g. `gcc` or `clang`)  
- **libssh** development headers & library
- **GTK** development headers & library
- **OpenSSL development headers & library** (usually pulled in by libssh)

## Building

Compile directly with:
gcc -o sshconnect sshconnect.c $(pkg-config --cflags --libs gtk+-3.0 libssh)

## Usage

./sshconnect

Enter remote host IP/hostname

Trust the host key (if first time connecting)

Enter your SSH password

Enter the local filename to upload

The file will be placed under upload/<filename> on the remote server.

## License

This project is released under the Apache 2.0 License. 

## Contact

Ram Sundar Radhakrishnan

## Known Issues

The GTK process gets blocked once the SFTP file transfer is underway and an error message is displayed that claims the program is inactive. This is a false alert, and the file transfer runs successfully without problems.

The probable solution is to move the GTK process to a different thread - please contact me if you have any ideas on how to best do this!
