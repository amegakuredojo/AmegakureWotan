import subprocess
import os
import sys
import json
import glob
from pathlib import Path

# Paths inside Docker container
BASE_DIR = Path("/app")
DATA_DIR = Path(os.environ.get("AMEWOTAN_DATA_DIR", "/data"))
SESSIONS_DIR = DATA_DIR / "sessions"
REPORTS_DIR = DATA_DIR / "reports"

def run_cmd(args):
    cmd = ["python3", "-m", "amegakurewotan.cli"] + args
    print(f"\n[RUNNING] {' '.join(cmd)}")
    res = subprocess.run(cmd, capture_output=True, text=True, cwd=str(BASE_DIR))
    if res.returncode != 0:
        print(f"[FAILED] Exit code: {res.returncode}")
        print(f"[STDOUT]\n{res.stdout}")
        print(f"[STDERR]\n{res.stderr}")
        return False, res.stdout, res.stderr
    print(f"[SUCCESS]")
    return True, res.stdout, res.stderr

def main():
    print("=== AMEWOTANGAKURE OSINT FORENSIC SMOKE TEST SUITE ===")
    
    # 1. Initialize environments
    success, stdout, _ = run_cmd(["init"])
    if not success:
        print("[-] Init phase failed.")
        sys.exit(1)
        
    # 2. Run deterministic LangGraph orchestration pipeline
    test_target = "testtarget.com"
    success, stdout, _ = run_cmd(["orchestrate", test_target])
    if not success:
        print("[-] Orchestration phase failed.")
        sys.exit(1)
        
    # Find the session ID generated
    session_files = glob.glob(str(SESSIONS_DIR / "session_*.json"))
    if not session_files:
        print("[-] No checkpoint session files found after orchestration!")
        sys.exit(1)
    
    latest_file = max(session_files, key=os.path.getmtime)
    session_id = os.path.basename(latest_file).replace("session_", "").replace(".json", "")
    print(f"[INFO] Discovered active session ID: {session_id}")
    
    # Verify checkpoint exists and has contents
    with open(latest_file, "r") as f:
        session_data = json.load(f)
    print(f"[INFO] Session Checkpoint contents: Phase={session_data.get('phase')}, Target={session_data.get('target')}")
    
    # 3. Test Resume capability using the checkpoint session file
    success, stdout, _ = run_cmd(["resume", session_id])
    if not success:
        print("[-] Resume phase failed.")
        sys.exit(1)
        
    # 4. Test Cryptographic Audit trail verification
    success, stdout, _ = run_cmd(["audit", "verify"])
    if not success:
        print("[-] Audit verify phase failed.")
        sys.exit(1)
    if "Forensic Audit Ledger Integrity: OK" not in stdout:
        print("[-] Audit ledger verification reported mismatch!")
        sys.exit(1)
        
    # 5. Ingest node manually
    success, stdout, _ = run_cmd(["graph", "ingest", "-t", "Domain", "-v", "manualingest.com", "-s", "operator", "-r", "A", "-c", "1"])
    if not success:
        print("[-] Manual ingest failed.")
        sys.exit(1)
        
    # 6. Query manually
    success, stdout, _ = run_cmd(["graph", "query", "manualingest.com"])
    if not success:
        print("[-] Query failed.")
        sys.exit(1)
        
    # 7. Run correlation via Fenrir
    success, stdout, _ = run_cmd(["correlate"])
    if not success:
        print("[-] Correlate phase failed.")
        sys.exit(1)
        
    # 8. Run Tyr scoring engine
    success, stdout, _ = run_cmd(["validate", "-r", "B", "-c", "2"])
    if not success:
        print("[-] Tyr scoring failed.")
        sys.exit(1)
        
    # 9. Test evidence freeze & clearsign via Skadi
    test_evidence_file = DATA_DIR / "evidence" / "test_evidence.txt"
    test_evidence_file.parent.mkdir(parents=True, exist_ok=True)
    with open(test_evidence_file, "w") as f:
        f.write("CONFIDENTIAL OSINT CAPTURE EVIDENCE")
        
    success, stdout, _ = run_cmd(["freeze", str(test_evidence_file)])
    if not success:
        print("[-] Evidence freeze failed.")
        sys.exit(1)
        
    # 10. Generate investigation dossier report
    success, stdout, _ = run_cmd(["report"])
    if not success:
        print("[-] Dossier report failed.")
        sys.exit(1)
        
    # 11. Export entire Graph database structure
    success, stdout, _ = run_cmd(["export"])
    if not success:
        print("[-] Export failed.")
        sys.exit(1)
        
    # 12. Run GBD JSON export/import cycle
    export_json_file = DATA_DIR / "evidence" / "graph_export.json"
    success, stdout, _ = run_cmd(["graph", "export", str(export_json_file)])
    if not success:
        print("[-] Graph export failed.")
        sys.exit(1)
        
    success, stdout, _ = run_cmd(["graph", "import", str(export_json_file)])
    if not success:
        print("[-] Graph import failed.")
        sys.exit(1)
        
    # 13. Test Kaisen integration
    report_files = glob.glob(str(REPORTS_DIR / "dossier_*.md"))
    if report_files:
        latest_report = max(report_files, key=os.path.getmtime)
        success, stdout, _ = run_cmd(["kaisen", "ingest", latest_report])
        if not success:
            print("[-] Kaisen ingest failed.")
            sys.exit(1)
            
        success, stdout, _ = run_cmd(["kaisen", "list"])
        if not success:
            print("[-] Kaisen list failed.")
            sys.exit(1)

        success, stdout, _ = run_cmd(["kaisen", "playbooks"])
        if not success:
            print("[-] Kaisen playbooks failed.")
            sys.exit(1)

        success, stdout, _ = run_cmd(["kaisen", "promote"])
        if not success:
            print("[-] Kaisen promote failed.")
            sys.exit(1)
        
    print("\n[+] ALL SMOKE TESTS COMPLETED SUCCESSFULLY!")
    print("[+] AmegakureWotan is fully operational and forensics compliant.")

if __name__ == "__main__":
    main()
