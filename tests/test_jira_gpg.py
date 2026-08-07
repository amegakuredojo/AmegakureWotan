import subprocess
import os
import json
import base64
import requests

JIRA_URL = "https://amegakuredojo.atlassian.net"
PROJECT_KEY = "AMDC2"

def load_credentials():
    creds_path = "/home/lugh/.amegakurewotan/opsec/credentials.json.gpg"
    if not os.path.exists(creds_path):
        raise FileNotFoundError(f"Encrypted credentials file not found at {creds_path}")
        
    proc = subprocess.Popen(
        ["gpg", "--decrypt", creds_path],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    stdout, stderr = proc.communicate()
    if proc.returncode != 0:
        raise RuntimeError(f"GPG Decryption failed: {stderr.decode('utf-8')}")
    return json.loads(stdout.decode("utf-8"))

def upload_to_jira():
    try:
        creds = load_credentials()
    except Exception as e:
        print(f"[-] Could not load credentials from GPG vault: {e}")
        return
        
    email = creds["email"]
    token = creds["token"]
    
    # Auth
    auth_str = f"{email}:{token}"
    auth_b64 = base64.b64encode(auth_str.encode("utf-8")).decode("utf-8")
    headers = {
        "Authorization": f"Basic {auth_b64}",
        "Accept": "application/json"
    }
    
    # Check if there is an issue we can attach to in AMDC2
    print(f"[INFO] Querying Jira for issues in project {PROJECT_KEY}...")
    search_url = f"{JIRA_URL}/rest/api/3/search?jql=project={PROJECT_KEY} ORDER BY created DESC"
    res = requests.get(search_url, headers=headers)
    
    issue_key = None
    if res.status_code == 200:
        data = res.json()
        issues = data.get("issues", [])
        if issues:
            issue_key = issues[0]["key"]
            print(f"[INFO] Found existing issue to attach to: {issue_key}")
            
    if not issue_key:
        # Create a new issue
        print(f"[INFO] Creating a new issue in project {PROJECT_KEY}...")
        create_url = f"{JIRA_URL}/rest/api/3/issue"
        create_payload = {
            "fields": {
                "project": {
                    "key": PROJECT_KEY
                },
                "summary": "AmegakureWotan Forensic OSINT Deployment Documentation",
                "description": {
                    "type": "doc",
                    "version": 1,
                    "content": [
                        {
                            "type": "paragraph",
                            "content": [
                                {
                                    "type": "text",
                                    "text": "Attachment of approved AmegakureWotan OSINT Deployment and Operational runbooks."
                                }
                            ]
                        }
                    ]
                },
                "issuetype": {
                    "name": "Task"
                }
            }
        }
        c_res = requests.post(create_url, headers=headers, json=create_payload)
        if c_res.status_code == 201:
            issue_key = c_res.json()["key"]
            print(f"[SUCCESS] Created new Jira issue: {issue_key}")
        else:
            print(f"[-] Failed to create issue: {c_res.status_code} - {c_res.text}")
            raise RuntimeError(f"Could not create issue: {c_res.text}")
            
    # Now upload attachments
    upload_url = f"{JIRA_URL}/rest/api/3/issue/{issue_key}/attachments"
    upload_headers = {
        "Authorization": f"Basic {auth_b64}",
        "X-Atlassian-Token": "no-check"
    }
    
    files_to_upload = [
        "/home/lugh/.gemini/antigravity-cli/brain/6bd1e299-0c0b-430a-bce8-abd2c353b815/deployment_runbook.md",
        "/home/lugh/.gemini/antigravity-cli/brain/6bd1e299-0c0b-430a-bce8-abd2c353b815/deployment_and_diagnosis.md"
    ]
    
    for fpath in files_to_upload:
        filename = os.path.basename(fpath)
        print(f"[INFO] Uploading {filename} to {issue_key}...")
        with open(fpath, "rb") as f:
            files = {"file": (filename, f, "text/markdown")}
            up_res = requests.post(upload_url, headers=upload_headers, files=files)
            if up_res.status_code == 200:
                print(f"[SUCCESS] Attached {filename} to issue {issue_key}")
            else:
                print(f"[-] Attachment failed: {up_res.status_code} - {up_res.text}")

if __name__ == "__main__":
    upload_to_jira()
