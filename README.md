# Access Log Analyzer (hamravesh task)

A command-line tool for analyzing web server access logs in **Combined Log Format**.

---

## **About the Project**

This project was developed as the **selection task for the HamAmooz course**.

We have a web service that receives millions of requests daily and logs them all in a single access log file. When the service becomes slow or returns errors, the infrastructure engineer needs to analyze these logs to identify the root cause.

**Task:** Build a CLI tool that reads an access log file and extracts useful reports from it.

---

## **Features**

- Parse logs in Combined Log Format
- Handle malformed/incomplete lines (no crashes)
- Total request count
- Unique IP count
- Top 10 endpoints (configurable with `--top`)
- Error rate (percentage of 4xx and 5xx responses)
- Hourly distribution with histogram
- Streaming (line-by-line) processing - no loading entire file into memory
- CLI interface with `argparse`
- Readable output with tables and histograms

### Extra Features

- Support for gzip compressed files (`.log.gz`)
- JSON output with `--json`
- Time range filtering with `--since` and `--until`
- Suspicious activity detection (401 on `/login`) with `--suspicious-threshold`
- 5xx error spike detection with `--error-spike-threshold`

---

## **Log Format (Combined Log Format)**

Each line contains these fields:

```
IP  -  -  [time]  "method path protocol"  status  size  "referrer"  "user-agent"
```

**Example:**
```
203.0.113.42 - - [01/Jun/2026:09:14:22 +0000] "GET /products/1877 HTTP/1.1" 200 5324 "-" "Mozilla/5.0 ..."
```

---

## **Installation & Setup**

### 1. Clone the Repository

```bash
 git clone https://github.com/adriana1214/log-analizer-hamravesh-starter

cd log-analyzer
```

### 2. Run (No external packages required)

```bash
python3 -m log_analyzer.cli access_log/access.log
```

---

## **Usage Guide**

### Basic Usage

```bash
python3 -m log_analyzer.cli access_log/access.log
```

### Compressed File (`.log.gz`)

```bash
python3 -m log_analyzer.cli access_log/access.log.gz
```

### Custom Number of Top Endpoints

```bash
python3 -m log_analyzer.cli access_log/access.log --top 5
```

### JSON Output

```bash
python3 -m log_analyzer.cli access_log/access.log --json
```

### Time Range Filtering

```bash
python3 -m log_analyzer.cli access_log/access.log --since 2026-06-01T00:00 --until 2026-06-30T23:59
```

### Brute Force Detection with Custom Threshold

```bash
python3 -m log_analyzer.cli access_log/access.log --suspicious-threshold 3
```

### Error Spike Detection with Custom Threshold

```bash
python3 -m log_analyzer.cli access_log/access.log --error-spike-threshold 0.3
```

### View All Options

```bash
python3 -m log_analyzer.cli --help
```

---

## **Command Line Arguments**

| Argument | Description | Default |
|----------|-------------|---------|
| `logfile` | Path to log file (`.log` or `.log.gz`) | **Required** |
| `--top N` | Number of top endpoints to display | 10 |
| `--json` | Output in JSON format | - |
| `--suspicious-threshold N` | 401 threshold for brute force detection | 10 |
| `--error-spike-threshold RATE` | 5xx threshold for spike detection (0-1) | 0.5 |
| `--since YYYY-MM-DDTHH:MM` | Start time filter (UTC) | - |
| `--until YYYY-MM-DDTHH:MM` | End time filter (UTC) | - |

---

## **Sample Output**

```
========================================================
log analysis report:
========================================================
total lines:                500000
legal parsed lines:    495044
malformed lines:             4956
unique ips:             4001
error rate percent(4xx + 5xx):          10.32%

-- tops(top 10) --
    146302   /
     87685   /products
     48842   /api/search
     34181   /cart
     31658   /login
     29249   /static/app.js
     24299   /static/style.css
     14549   /health
      9807   /api/checkout
        20   /products/9820

--hourly distribution: --
  2026-06-01 00:00     51026   ########################################
  2026-06-01 01:00     50971   #######################################
  2026-06-01 02:00     50975   #######################################
  2026-06-01 03:00     50705   #######################################
  2026-06-01 04:00     50847   #######################################
  2026-06-01 05:00     51002   #######################################
  2026-06-01 06:00     50809   #######################################
  2026-06-01 07:00     50844   #######################################
  2026-06-01 08:00     50912   #######################################
  2026-06-01 09:00     36953   ############################

--suspicious ips on/login --
  21.67.75.144         7464 unsuccesfull try

```

---

## **Architecture & Key Decisions**

### Project Structure

```
log-analyzer/
├── log_analyzer/
│   ├── __init__.py          # Package initializer
│   ├── parser.py            # Log line parsing
│   ├── analyzer.py          # Statistics collection
│   └── cli.py               # Command-line interface
├── access_logs 
     └── access.logs         # log file
├── README.md                # This file
└── .gitignore               # Ignored files
```

### Modules

#### `log_analyzer/parser.py`
- Only responsible for parsing a **single** log line.
- Contains a compiled Regex for Combined Log Format.
- Returns `None` on mismatch or invalid values.
- Never throws exceptions — as required by the "dirty file, no crashes" requirement.

#### `log_analyzer/analyzer.py`
- `LogAnalyzer` class maintains state with `collections.Counter` and `set`.
- `process_line` method is called for each line.
- No lists of lines or entries are ever created.
- Memory usage is independent of file size, not dependent on line count.

#### `log_analyzer/cli.py`
- Uses `argparse` for argument parsing.
- Opens files with `open()` or `gzip.open()` (depending on `.gz` extension).
- Processes line-by-line with `for line in f:`.
- Python reads this as a stream, never loading the entire file.

### Why Three Files?

- `parser` is independently testable (pure function: string input → entry or None)
- `analyzer` keeps statistics logic separate from I/O
- `cli` is just the user interface/argument layer
- This separation makes the code more readable and debugging easier

---

## **Issue Encountered & Solution**

### Issue

I started with a simpler regex that always parsed the `size` field as a number.

When testing on "dirty" data (as required by the task), I found some lines had `"-"` for `size` (meaning no response body). This caused the entire line to be incorrectly marked as "malformed," even though it was structurally valid.

### Solution

In `parse_line`, before calling `int()`, I check for `"-"` and treat it as `0` bytes:

```python
size = int(data["size"]) if data["size"] != "-" else 0
```

---

## **Requirements**

- **Python 3.8** or higher
- **No external packages** required

| Library | Purpose |
|---------|---------|
| `re` | Regular expressions for parsing |
| `argparse` | Command-line argument parsing |
| `collections.Counter` | Counting and ranking |
| `datetime` | Date and time handling |
| `gzip` | Compressed file support |
| `json` | JSON output |
| `typing` | Type hints |
| `sys` | Input/output and errors |

---

## **AI Usage Policy**

As per the task policy: This code was written using the assistance of an AI (deepseek) and documentation/Stack Overflow.


---


---

## **Acknowledgments**

This project was written as the selection task for the **HamAmooz** course.
