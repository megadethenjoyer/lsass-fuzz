import os
import sys
import time

if len(sys.argv) != 3:
    print("Bad usage")
    print("exec-n.py <n> <harness>")
    sys.exit(1)

n = int(sys.argv[1])

for i in range(0, n):
    time.sleep(1)
    os.system(f"start python exec-one.py {sys.argv[2]}")
