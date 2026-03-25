import os
import subprocess
import platform
def run(cmd):
    subprocess.run(cmd, shell=True, check=True)
print("Building HashChat for", platform.system())
run("cargo build --release")
run("cabal build")
print("HashChat built successfully")