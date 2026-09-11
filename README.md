# Chrome App-Bound Encryption v20 Master Key Extractor

An educational proof-of-concept (PoC) demonstrating local cryptographic boundaries and memory analysis techniques on Windows x64. This project explores the mechanics of Google Chrome's updated Application-Bound Encryption (ABE) v20 mitigation.

## ⚠️ Disclaimer
This repository is created strictly for educational purposes, security auditing, and malware analysis research. It is intended to demonstrate the technical boundaries of local processes and native Windows debugging APIs. The author does not condone, support, or facilitate unauthorized access or malicious activities.

## 🔬 Technical Overview
Unlike traditional methods that rely on high-privilege system escalation or noisy code injection, this implementation operates as a non-destructive local analysis utility utilizing a stealthier debugger-based methodology:

* **Targeted AOB Scanning:** Utilizes a signature-based Array of Bytes (AOB) scanner to locate the specific cryptographically scrambled internal function signatures within the Chrome binary—specifically targeting the memory patterns associated with `OSCRYPT.AppBoundProvider.Decrypt.ResultCode`.
* **Hardware Breakpoints:** Registers native x64 hardware breakpoints via the Win32 Debugging API (`SetThreadContext`) to intercept the control flow at the precise instruction containing the decrypted master key, capturing the plaintext `v20_master_key` directly from the CPU registers.
* **Thread Context Isolation:** Cleanly handles thread suspension and context synchronization to ensure absolute execution stability on Windows x64 without crashing the target browser process.

For more details on the underlying discovery and methodology, look up the **Gen Digital void stealer debugger technique**.
