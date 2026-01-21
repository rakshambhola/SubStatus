<div align="center">

# SubStatus

### *A Kali Linux Tool*

<p align="center">
  <a href="#options">Options</a> •
  <a href="#📥installation">Installation</a> •
  <a href="#🧠usage">Usage</a> •
  <a href="#scope">Scope</a>
</p>

</div>

# 🔥 SubStatus - A Kali Linux Tool
  
### Fast & Smart Subdomain Status Scanner for Recon, Bug Bounty & Pentesting
Discover subdomains → detect live hosts → analyze HTTP responses → export results.

SubStatus is a tool that takes a website domain and automatically finds its subdomains, checks which ones are online, and shows their HTTP response codes. It can also collect extra information like DNS & CNAME records and export the results to a report file. The main purpose of SubStatus is to save time during recon by quickly identifying active subdomains that may be useful for bug bounty and penetration testing.

---

## Options:
| Options       | Description                    |
| ------------- | ------------------------------ |
| `-u`          | Target domain *(required)*     |
| `-c`          | Filter by specific status code |
| `-cname`      | CNAME lookup *(True/False)*    |
| `-dns_lookup` | DNS lookup *(True/False)*      |
| `-exp`        | Export type *(txt/csv)*        |
| `-version`    | Show tool version              |

---

## 📥 Installation

### 1️⃣ Requirements

```
sudo apt install subfinder
```
```
sudo apt install python
```
```
pip install requests tqdm dnspython
```
or
```
pip install requests tqdm dnspython --break-system-packages 
```

### 2️⃣ Clone the repo

```
git clone https://github.com/rakshambhola/SubStatus.git
cd SubStatus
```

### 3️⃣ Make executable

```
chmod +x substatus.py
```

### (optional) Run globally

```
sudo mv substatus.py /usr/local/bin/substatus
```

---

## 🧠 Usage

### 🔹 Basic scan

```
substatus -u example.com
```

### 🔹 Filter by specific status

```
substatus -u example.com -c 200
```

### 🔹 Include DNS & CNAME lookup

```
substatus -u example.com -dns_lookup True -cname True
```

### 🔹 Export report

```
substatus -u example.com -exp csv
```

### 🔹 Full scan mode

```
substatus -u example.com -dns_lookup True -cname True -exp csv
```

### 🔹 Show version

```
substatus -version
```

---

## Scope:

* Subdomain discovery using subfinder
* HTTP/HTTPS probing to check online/offline hosts
* Status code inspection (200 / 301 / 403 / 500 etc.)
* DNS & CNAME enumeration (optional)
* Exporting to CSV/TXT for reporting

It’s designed to save time during recon, highlight interesting targets, and provide a clean workflow for bug bounty hunters & penetration testers.

---

## 🛡️ Legal Notice

SubStatus is intended **only for educational purposes and authorized security testing**.
Do **not** scan domains without prior permission.
You are responsible for your actions.

---

## 💬 Notes

* For Ethical use ONLY!!

---

## 🧑‍💻 Author

**👤 Raksham Bhola**
🔗 GitHub: [rakshambhola](https://github.com/rakshambhola)

---

## 📜 License

This project is open-source and available under the **MIT License**.

---

<div align="center">

**Star ⭐ this repo if you find it useful!**

[⬆ Back to Top](#SubStatus)

</div>
