import os
import subprocess
import platform
def run(cmd):
    subprocess.run(cmd, shell=True, check=True)
os_name = platform.system()
print("Building HashChat for", os_name)
run("cargo build --release")
run("cabal build")
print("HashChat built securely")