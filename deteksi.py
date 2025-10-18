import re
import csv
from urllib.parse import unquote

# Pola deteksi gabungan: (regex, reason, attack_type)
combined_patterns = [
    # SQLi
    (re.compile(r"('|%27|%22)\s*(or|and)\s*('|%27|%22)?.+('|%27|%22)?\s*=\s*('|%27|%22)?.+?('|%27|%22)?", re.IGNORECASE), "Boolean logic injection", "SQLi"),
    (re.compile(r"union(?:\s|\+)+select", re.IGNORECASE), "UNION SELECT injection", "SQLi"),
    (re.compile(r"\b(select|insert|update|delete|drop|sleep|benchmark)\b.*\b(from|where)\b", re.IGNORECASE), "SQL keyword abuse", "SQLi"),
    (re.compile(r"(?:\s|['\"=]|%20)(--|%2[dD]%2[dD])(?:\s|&|$|.)", re.IGNORECASE), "SQL comment injection", "SQLi"),
    (re.compile(r";|%3B", re.IGNORECASE), "SQL chaining using semicolon", "SQLi"),
    (re.compile(r"\bor\s+\d+=\d+\b", re.IGNORECASE), "Simple OR condition", "SQLi"),
    (re.compile(r"\band\s+\d+=\d+\b", re.IGNORECASE), "Simple AND condition", "SQLi"),
    (re.compile(r"(sleep|benchmark)\s*\(", re.IGNORECASE), "Time-based SQLi", "SQLi"),

    # Traversal
    (re.compile(r"(\.\./|\.\.\\|%2e%2e%2f|%2e%2e%5c|%252e%252e%252f|%252e%252e%255c)", re.IGNORECASE), "Path traversal sequence", "Traversal"),

    # XSS
    (re.compile(r"(?i)<script.*?>.*?</script>"), "Script tag injection", "XSS"),
    (re.compile(r"(?i)on\w+\s*=\s*['\"].*?['\"]"), "Event handler attribute", "XSS"),
    (re.compile(r"(?i)javascript\s*:"), "JavaScript URI", "XSS"),
    (re.compile(r"(?i)(alert|prompt|confirm|fetch|eval|location|document\.cookie)\s*\("), "Dangerous JS function call", "XSS"),
    (re.compile(r"(?i)%3C(script|img|svg|iframe|on)"), "URL-encoded XSS", "XSS"),
    (re.compile(r"(?i)<(img|svg|iframe|video|object|embed)[^>]+(onerror|onload|onclick)\s*="), "Event on media tag", "XSS"),
    (re.compile(r"(?i)<iframe\s+srcdoc="), "Iframe srcdoc XSS", "XSS"),
    (re.compile(r"(?i)<meta\s+http-equiv\s*=\s*['\"]refresh['\"]\s+content\s*="), "Meta tag redirection", "XSS"),

    # SSRF
    (re.compile(r"(?i)(127\.0\.0\.1|localhost|internal|169\.254\.169\.254)"), "Potential SSRF endpoint", "SSRF"),

    # RFI
    (re.compile(r"(?i)(http|https|ftp):\/\/[^\s]+(\.php|\.txt|\.sh)"), "Remote File Inclusion (RFI) attempt", "RFI"),

    # Command Injection
    (re.compile(r"(?i)(;|\||&)\s*(ls|cat|echo|wget|curl|whoami|id|nc|bash|sh|chmod)\b"), "Command injection via shell operators", "Command Injection"),

    # Recon
    (re.compile(r"(?i)/((admin|wp-login|setup|config|\.env|web-console|phpmyadmin)(\.php)?)"), "Recon/config page access", "Reconnaissance Access"),

    # Sensitive Page Access — hanya valid jika status code cocok
    (re.compile(r"/(admin|login|wp-login|phpmyadmin|dashboard)", re.IGNORECASE), "Sensitive page probing", "Sensitive Page Access"),
]

# Fungsi pengecualian untuk /jsonList
def is_whitelisted_jsonlist(url_decoded):
    return (
        "/rapidGrails/jsonList" in url_decoded and
        "filter=[" in url_decoded and
        "columns=[" in url_decoded and
        "g.message(" in url_decoded
    )

# Regex ambil URL dan referer
request_pattern = re.compile(r'"(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+([^\s]+)\s+HTTP/[\d\.]+"')
referer_pattern = re.compile(r'"[^"]+"\s+"[^"]+"\s+"([^"]+)"$')

def detect_attacks_from_log(log_file_path, output_csv_path):
    with open(log_file_path, 'r', encoding='utf-8') as infile, \
         open(output_csv_path, 'w', newline='', encoding='utf-8') as outfile:

        writer = csv.DictWriter(outfile, fieldnames=[
            'log_index', 'original_log', 'status_code', 'url_detected', 'referer_detected', 'attack_type', 'reason'
        ])
        writer.writeheader()

        for index, line in enumerate(infile, 1):
            original_log = line.strip()
            url_detected = "-"
            referer_detected = "-"
            attack_type = ""
            reason = ""
            status_code = ""

            try:
                url_match = request_pattern.search(line)
                referer_match = referer_pattern.search(line)

                if not url_match:
                    continue

                url_raw = url_match.group(2)
                url_decoded = unquote(url_raw)
                referer_raw = referer_match.group(1) if referer_match else ""
                referer_decoded = unquote(referer_raw)

                # Ekstrak status code
                try:
                    status_code = line.split('"')[2].strip().split()[0]
                except:
                    status_code = ""

                # Lewati JSONList yang dibangun framework
                if is_whitelisted_jsonlist(url_decoded):
                    continue

                # Cek URL
                for pattern, r, a in combined_patterns:
                    # Sensitive Access hanya dicatat jika status menarik
                    if pattern.search(url_decoded):
                        if a in ["Sensitive Page Access", "Reconnaissance Access"] and status_code == "200":
                            break
                        url_detected = url_raw
                        attack_type = a
                        reason = r
                        break

                # Cek Referer
                for pattern, r, a in combined_patterns:
                    if referer_decoded and pattern.search(referer_decoded):
                        referer_detected = referer_raw
                        attack_type = a
                        reason = r
                        break
                
                

                if url_detected != "-" or referer_detected != "-":
                    writer.writerow({
                        'log_index': index,
                        'original_log': original_log,
                        'status_code': status_code,
                        'url_detected': url_detected,
                        'referer_detected': referer_detected,
                        'attack_type': attack_type,
                        'reason': reason
                    })

            except Exception:
                continue

    print(f"✅ Deteksi selesai. Output disimpan di: {output_csv_path}")

# Contoh pemanggilan:
detect_attacks_from_log('access.log', 'akapahFinal.csv')
