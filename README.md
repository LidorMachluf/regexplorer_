# 📘 Regex Scanner

A lightweight Python 3 tool to recursively scan files in a Linux system (local machine, EC2, Kubernetes pod, container, etc.) for **regex-defined secrets or patterns**.

It reads all readable files (plain text, source code, configs, `.docx`, and PDFs if `PyPDF2` is installed), applies the regexes you define, and outputs findings to **JSON** (detailed) and **CSV** (triage-friendly).

---

## 🚀 Features

- 🔍 **Regex-only matching**: catches exactly what your regexes define.  
- 📂 Recursively scans directories.  
- 📝 Supports `.txt`, source code, configs, `.docx`, and optionally PDFs.  
- 🧾 Outputs both **JSON** and **CSV**.  
- 🗂️ Includes optional **context window** around each match for review.  
- 🚫 Skips noisy system dirs (`/proc`, `/sys`, `/dev`, `/run`) by default.  
- 🔄 Multi-threaded scanning for performance.  
- ✅ Exit codes:  
  - `0` → no matches found  
  - `3` → matches found  

---

## 📦 Requirements

- **Python 3.7+** (tested on 3.8–3.12)  
- Standard Python libraries (no extra install needed for `.txt`, code, `.docx`).  
- Optional: `PyPDF2` if you want to scan PDFs.  

### Install required Python libraries

```bash
# For basic scanning (no PDFs needed)
# nothing to install

# If you want PDF scanning support:
pip install PyPDF2
```

Or keep dependencies explicit with a `requirements.txt` file:

```
PyPDF2>=3.0.0
```

---

## 🛠️ Installation

1. Clone the repo:
   ```bash
   git clone https://github.com/LidorMachluf/regexplorer_
   cd regexplorer_
   ```

2. Make the script executable:
   ```bash
   chmod +x find_secrets.py
   ```

3. (Optional) Install PDF support:
   ```bash
   pip install PyPDF2
   ```

---

## 📄 Regex Configuration

You must provide a **`regexes.json`** file. Two formats are supported:

- **JSON list of objects** (recommended):
  ```json
  [
    {"name": "aws-access-key", "pattern": "\\bAKIA[0-9A-Z]{16}\\b"},
    {"name": "slack-token", "pattern": "xox[baprs]-[0-9A-Za-z-]{10,48}"}
  ]
  ```

- **Plaintext list of regexes** (names auto-generated):
  ```
  \\bAKIA[0-9A-Z]{16}\\b
  xox[baprs]-[0-9A-Za-z-]{10,48}
  ```

---

## ▶️ Usage

Basic scan of `/home` with regexes from `regexes.json`:

```bash
python3 find_secrets.py -r /home -R regexes.json
```

Scan `/var/www`, output JSON & CSV with extra context:

```bash
python3 find_secrets.py \
  --root /var/www \
  --regex-file regexes.json \
  --out-json findings.json \
  --out-csv findings.csv \
  --threads 8 \
  --context 60
```

Scan entire filesystem (⚠️ heavy and noisy):

```bash
sudo python3 find_secrets.py -r / -R regexes.json --no-skip
```

---

## 📊 Output Examples

### JSON (`findings.json`)
```json
[
  {
    "file": "/etc/config/keys.txt",
    "regex_name": "aws-access-key",
    "regex": "\\bAKIA[0-9A-Z]{16}\\b",
    "match": "AKIA1234567890ABCD",
    "line": 12,
    "start": 150,
    "end": 170,
    "context": "AWS_KEY=AKIA1234567890ABCD REGION=us-east-1"
  }
]
```

### CSV (`findings.csv`)
```
file,line,regex_name,regex,match,start,end,context
/etc/config/keys.txt,12,aws-access-key,\\bAKIA[0-9A-Z]{16}\\b,AKIA1234567890ABCD,150,170,"AWS_KEY=AKIA1234567890ABCD REGION=us-east-1"
```

---

## ⚠️ Notes & Caveats

- This tool **only matches by your regexes**. No guessing, no heuristics.  
- Precision of results depends entirely on your regex patterns.  
- Handle output files (`results.json`, `results.csv`) carefully — they may contain real secrets.  
- Scanning `/` or large filesystems can be slow and produce massive output. Start with targeted paths.  
- Default skips: `/proc`, `/sys`, `/dev`, `/run` to avoid noisy/unreadable files. Use `--no-skip` if you need them.  

---

## ✅ Example Workflow

1. Clone into a Kubernetes pod or EC2:
   ```bash
   git clone https://github.com/LidorMachluf/regexplorer_ /tmp/regexplorer_
   cd /tmp/regexplorer_
   ```

2. Copy or edit your regex file:
   ```bash
   cp regexes.json my_regexes.json
   ```

3. Run the scan:
   ```bash
   python3 find_secrets.py -r /app -R my_regexes.json -o findings.json -c findings.csv
   ```

4. Review results:
   ```bash
   cat findings.csv
   ```

---

## 📜 License

MIT License — free to use and adapt.
