import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from server import run_full_analysis

samples = ['legitimate_email.eml', 'phishing_spoof.eml', 'invoice_sample.msg']
for s in samples:
    p = os.path.join(os.path.dirname(__file__), '..', 'samples', s)
    with open(p, 'rb') as f:
        data = f.read()
    res = run_full_analysis(data, s)
    subject = res['email']['subject']
    spf_st = res['spf']['status']
    score = res['risk']['score']
    level = res['risk']['level']
    print(f"[PYTHON PASS] {s}: {subject} | SPF: {spf_st} | Score: {score} ({level})")
print("\nTODOS LOS ARCHIVOS FUERON PARSEADOS Y ANALIZADOS CON EXITO POR PYTHON!")
