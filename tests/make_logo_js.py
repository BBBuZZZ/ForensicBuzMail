import os

base_dir = r"E:\App\parseador"
img_b64_path = os.path.join(base_dir, "public", "img", "logo_base64.txt")
logo_js_path = os.path.join(base_dir, "public", "js", "logo.js")

if os.path.exists(img_b64_path):
    with open(img_b64_path, "r", encoding="utf-8") as f:
        b64_str = f.read().strip()
    with open(logo_js_path, "w", encoding="utf-8") as f:
        f.write('const FORENSIC_BADGE_B64 = "data:image/jpeg;base64,' + b64_str + '";\n')
    print("Created logo.js:", os.path.getsize(logo_js_path), "bytes")
else:
    print("Error: logo_base64.txt not found")

