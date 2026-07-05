import os
import re

ROOT = "/home/lugh/AmegakureDojo/Karasugakure"

def refactor_file(path):
    with open(path, "r", encoding="utf-8") as f:
        content = f.read()

    # Replace lowercase sha256 with sha512
    content = content.replace("sha256", "sha512")
    # Replace uppercase SHA-256 with SHA-512
    content = content.replace("SHA-256", "SHA-512")
    content = content.replace("SHA256", "SHA512")

    with open(path, "w", encoding="utf-8") as f:
        f.write(content)

for root, _, files in os.walk(ROOT):
    for f in files:
        if f.endswith(".py") or f == "Makefile" or f.endswith(".md") or f == "Dockerfile":
            path = os.path.join(root, f)
            if "scratch" in path or "refactor" in path:
                continue
            with open(path, "r", encoding="utf-8") as file:
                if "sha256" in file.read().lower():
                    print(f"Refactoring {path}")
                    refactor_file(path)

print("Refactoring complete.")
