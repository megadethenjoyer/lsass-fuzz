import os
import random
import string
import time
import sys

if len(sys.argv) < 2:
    print('bad usage')
    sys.exit(1)

harness = sys.argv[1]

print('Harness', harness)

temp = os.getenv('TEMP')
rand_name = ''.join(random.choices(string.ascii_lowercase, k=8))
bufsize_name = f"{temp}\\{rand_name}"
harness_pipe_name = f"\\\\.\\pipe\\pipe_{rand_name}"
lsass_pipe_name = f"\\\\.\\pipe\\lsass_{rand_name}"
gateway_pipe_name = f"\\\\.\\pipe\\gateway_{rand_name}"

def get_bufsize():
    try:
        with open(bufsize_name, "r") as f:
            return f.read()
    except FileNotFoundError:
        return None

os.system(f"start ..\\out\\harness.exe {harness_pipe_name} {harness} {bufsize_name}")

bufsize = None
while bufsize == None:
    time.sleep(0.5)
    bufsize = get_bufsize()

os.system(f"start ..\\out\\lsass-iat-hook.exe {lsass_pipe_name} {gateway_pipe_name} {harness_pipe_name} {bufsize}")

time.sleep(0.5)

os.system(f"cargo run -r {bufsize} {gateway_pipe_name}")


# start ..\out\harness.exe \\.\pipe\target_pipe_a lsa_logon_user_kerb_interactive_logon_harness C:\
# start ..\out\lsass-iat-hook.exe \\.\pipe\lsass_pipe_a \\.\pipe\c_pipe_a \\.\pipe\target_pipe_a 48
# cargo run -r 48 \\.\pipe\c_pipe_a