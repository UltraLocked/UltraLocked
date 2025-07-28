# UltraLocked: An Overview of Our Approach to Mobile Data Sovereignty

**Version:** 1.0  
**Last Updated:** July 28, 2025

---

## 🔒 What Is UltraLocked?

UltraLocked is a secure vault for iOS that protects your most sensitive files — documents, photos, recordings — using the same kind of hardware-level protection trusted by governments and top-tier privacy apps.

It’s not cloud-based. It doesn’t require an account. It never talks to our servers — because there are none.

Your data lives only on your device, under your exclusive control.

---

## 🧠 Why It Matters

Most "secure" apps still rely on passwords, cloud servers, or software-based encryption. But:

- **Passwords can be guessed or stolen**
- **Cloud servers can be hacked or subpoenaed**
- **Forensic tools can recover deleted data**

UltraLocked is different. It uses the **Secure Enclave** — a tamper-resistant chip built into your iPhone — to generate and store encryption keys that even UltraLocked itself cannot access.

This means:
- Your files are protected even if your phone is stolen
- No one — not even us — can decrypt your data
- You have tools to defend against coercion, loss, or surveillance

---

## 🛡️ Key Features

### 1. **Hardware-Backed Encryption**
Every file is encrypted using a secret key **stored only in your device’s hardware** — not the cloud, not in software, and not in RAM.

### 2. **Per-File Perfect Forward Secrecy**
Each file has its **own encryption key**, used once and then destroyed. If someone breaks into one file, it **tells them nothing about the rest**.

### 3. **Offline-First, Zero-Trust Design**
UltraLocked has **no online components**. No telemetry. No accounts. No hidden APIs. If you see the app trying to talk to a server, it’s not UltraLocked.

### 4. **Duress Code & Decoy Vault**
In extreme situations, you can enter a **secret panic PIN** that:
- Opens a fake but believable decoy vault
- **Silently erases the real one**

No alerts. No trace.

### 5. **Emergency Self-Destruct**
You can configure:
- A **Dead Man’s Switch** (e.g. auto-wipe if you don’t unlock for 7 days)
- **File self-destruct timers** for sensitive data
- Motion/gesture triggers to instantly wipe the vault

---

## 🧬 What Makes UltraLocked Different

| Feature | UltraLocked | Typical "Secure" Apps |
|--------|-------------|------------------------|
| Encryption Root | Hardware-only (Secure Enclave) | Software password or cloud key |
| Cloud / Server | None — fully offline | Yes (often invisible to user) |
| Forensic Resilience | Yes — RAM-wipe, anti-debug, secure deletion | Often leaves traces on disk |
| Per-File Keys | ✅ | ❌ |
| Emergency Protocols | Duress PIN, Dead Man’s Switch, triggers | Usually absent |
| Data Collection | Zero | Often extensive (analytics, crash logs) |
| Transparency | Public white paper, threat model, audit-ready | Opaque |

---

## 🔐 Who Should Use UltraLocked?

- Investigative journalists
- High-risk travelers or dissidents
- Privacy-focused professionals (lawyers, doctors)
- Anyone who stores sensitive media or documents on their phone

If you need **credibility, deniability, or true local control**, UltraLocked is built for you.

---

## 🧾 Privacy, By Design

- No accounts, emails, or identifiers
- No network requests — ever
- No cloud sync, backups, or telemetry
- No logs, crash reports, or metadata retention
- No way for us to access your vault — even if compelled

Your phone is your only point of trust. We’ve designed UltraLocked so **you don’t have to trust anyone else — including us.**

---

## 📣 Want to Learn More?

- 📘 [Read the Full White Paper →](./whitepaper.md)
- 📫 [Report a Vulnerability](./SECURITY.md)

---

© 2025 UltraLocked. All rights reserved.