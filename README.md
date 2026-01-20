# Scryfx: Python-Based Windows Internals Research POC 🐍🛡️

> **Disclaimer**
> This project is intended **strictly for educational purposes and defensive security research**.
> It was created to study how certain offensive techniques work internally in order to better understand, analyze, and detect them from a defensive (Blue Team) perspective.
> **Do not run this project outside of isolated lab environments (VMs, sandboxes).**
> The author takes no responsibility for misuse.

---

## 🔎 Overview

**Scryfx** is a Proof of Concept (POC) **Windows shellcode loader** written entirely in Python.

The project explores the following question:

> *Can a high-level interpreted language like Python interact with low-level Windows Internals to reproduce techniques usually implemented in C/C++?*

Using Python’s `ctypes` library, Scryfx demonstrates how Native Windows APIs exposed by `ntdll.dll` can be invoked directly, how memory can be manipulated safely, and how execution can occur via less common mechanisms such as **Asynchronous Procedure Calls (APC)**.

The objective is **research and learning**, not operational use.

---

## 🧠 Technical Highlights

###  Indirect Native API Calls ("Ninja Mode")

Instead of relying on common Win32 APIs that are frequently monitored or hooked by EDR solutions, Scryfx interfaces directly with the Native API:

- `NtAllocateVirtualMemory`
- `NtProtectVirtualMemory`
- `NtFreeVirtualMemory`
- `RtlCopyMemory`

This helps illustrate how userland hooks can be bypassed and why behavioral detection matters more than API-level signatures.

---

### 📉 Lightweight Obfuscation (Why XOR?)

- No heavy cryptographic libraries
- Minimal dependencies
- Lower static footprint

Key characteristics:
- **Streaming XOR decryption**
- **Key fragmentation** across multiple memory chunks
- Runtime key reconstruction
- Secure key zeroization after use

This approach was chosen to study detection trade-offs rather than to provide strong cryptography.

---

### 💉 APC-Based Execution

Instead of noisy execution methods such as `CreateThread` or `CreateRemoteThread`, Scryfx uses:

- `QueueUserAPC`
- `SleepEx` (alertable state)

This demonstrates how APCs can be abused for stealthy execution inside the current process context.

---

### 🎭 Heuristic Noise & Sandbox Evasion

To simulate legitimate application behavior and stress heuristic engines, the loader performs:

- Random benign API calls (system info, disk info, timing APIs)
- Non-deterministic delays
- Dummy computations
- Variable execution paths

These techniques help understand how sandboxes and heuristic engines make decisions.

---

## 📂 Project Structure

| File | Description |
|-----|-------------|
| `Scryfx.py` | Main research loader containing memory handling, evasion logic, and execution flow |
| `Encryptor_XOR.py` | Utility script for encrypting raw shellcode using a lightweight XOR stream |
| `XOR_Hello_Message_ShellCode.bin` | Encrypted POC payload (MessageBox demonstration) |

---

##  Usage (Lab Environments Only)

### 1️⃣ Encrypt a Payload

```bash
python Encryptor_XOR.py raw_shellcode.bin encrypted_payload.bin
```

Optional custom key:

```bash
python Encryptor_XOR.py raw_shellcode.bin encrypted_payload.bin -k "1a2b3c4d..."
```

> ⚠️ After encryption, update the `KEY_CHUNKS` variable inside `Scryfx.py` accordingly.

---

### 2️⃣ Run the Loader

```bash
python Scryfx.py
```

In real-world research scenarios, Python loaders are often compiled into executables using tools like **PyInstaller** or **Nuitka** to remove the interpreter dependency.

---

## ⚙️ Execution Flow (High-Level)

1. Initialization with flattened control flow
2. Anti-debugging checks
3. Heuristic noise generation
4. Payload decryption in memory
5. Native memory allocation (RW → RX)
6. APC queueing & alertable execution
7. Memory cleanup & artifact wiping

---

## 🛠️ POC Payload Generation

The included payload is intentionally **harmless** and used for demonstration purposes only.

It displays a simple Windows message box, generated from a minimal C program and converted to position-independent shellcode using **Donut**.

```c
#include <windows.h>

int main() {
    MessageBoxA(0, "Your pipeline worked successfully!", 0);
    return 0;
}
```

---

## 🎓 Research Goals

This project helped reinforce understanding of:

- Windows Internals
- Native API behavior
- EDR detection strategies
- Heuristic vs signature-based detection
- Memory forensics fundamentals

It is best viewed as a **learning artifact**.

---

## 📜 License

This project is licensed under the **MIT License**.

---
