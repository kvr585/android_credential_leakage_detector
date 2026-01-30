import os
import subprocess
import sys

APK_PATH = sys.argv[1] if len(sys.argv) > 1 else None
OUTPUT_DIR = "/tmp/apk_dec"
REPORT_FILE = "reports/strings.txt"

if not APK_PATH or not os.path.exists(APK_PATH):
    print("Usage: python3 extract_strings.py <apk_path>")
    sys.exit(1)

# Decompile APK
print("[+] Decompiling APK...")
subprocess.run(["apktool", "d", "-f", APK_PATH, "-o", OUTPUT_DIR],
               stdout=subprocess.DEVNULL,
               stderr=subprocess.DEVNULL)

os.makedirs("reports", exist_ok=True)

with open(REPORT_FILE, "w", encoding="utf-8") as out:
    # Extract strings.xml
    strings_xml = os.path.join(OUTPUT_DIR, "res", "values", "strings.xml")
    if os.path.exists(strings_xml):
        out.write("==== strings.xml ====\n")
        with open(strings_xml, errors="ignore") as f:
            out.write(f.read())
            out.write("\n\n")

    # Extract smali files
    out.write("==== smali files ====\n")
    for root, _, files in os.walk(OUTPUT_DIR):
        for file in files:
            if file.endswith(".smali"):
                path = os.path.join(root, file)
                try:
                    with open(path, errors="ignore") as f:
                        out.write(f"\n--- {path} ---\n")
                        out.write(f.read())
                except:
                    pass

print(f"[+] Strings extracted to {REPORT_FILE}")

