# lsass-fuzz

Fuzzing lsass with libAFL using a remote IAT hook as coverage information

![picture of the fuzzer fuzzing](https://i.imgur.com/Un8Smdg.png)

In the above screenshot you can see multiple processes fuzzing. Currently they are fuzzing the exact same endpoint but later this will be extended to fuzz multiple things in parallel.

## TODO
~~[ ] Forward this coverage information to afl-fuzz (probably via manually writing to the __afl_area_ptr)~~
- using libAFL

[X] Write the actual harness
- just implement Lsa function calling

[ ] Write more harnesses (see notes below)

[ ] Perhaps also stackwalk to get better coverage information (get information about specific branches)

[ ] Write a blogpost ?? :)

[ ] Get a more stable way of getting SspirLogonUser (and others) base address and instruction sizes (see notes below)

[ ] Document this a little more

#### Other theoretical methods

[ ] Maybe try a different method of getting coverage, like emulation

[ ] Maybe use static binary rewriting & somehow just map lsasrv.dll

[X] Maybe try libAFL ~~with FRIDA?~~ with a custom "instrumentation" engine

[ ] Maybe try an entirely different fuzzer

[ ] Maybe make my own fuzzer

## Project structure
```
helper-driver/
    src/main.c - Contains the entire driver
                 TODO: Maybe refactor to multiple files?

    The helper driver is required since lsass.exe is PPL protected.
    The helper driver implements a few ioctls:   
    - HELPER_READ  
    - HELPER_WRITE 
    - HELPER_GET_PEB 
    - HELPER_ALLOCATE 
    - HELPER_DUPLICATE 
    - HELPER_PROTECT

lsass-iat-hook/
    src/main.cpp - Main initialization
    src/ipc.cpp  - client_thread has the code which receives the function calls
    src/hook.cpp - does the IAT hooking (should be pretty much done by now)
    src/gateway.cpp - does the gateway between harness.exe and libafl-fuzz.exe

    This executable hooks every function from the IAT of lsasrv.dll which is loaded in lsass.exe and logs them. This will later be used as coverage information for afl-fuzz.

libafl-fuzz/
    The actual fuzzing engine (in Rust) using libAFL.

```

## Some notes
To get this up and running (in a VM, I don't recommend running on your host):

- Build the entire solution (with VS)
- Start the helper driver (with sc) - TODO: do it automatically
- Get yourself a copy of libAFL (from their repo) and put it in `libafl` (where `crates` must be inside `./libafl`)
- Build libafl-fuzz (cargo build)
- run exec.cmd from libafl-fuzz

Currently it works like this: libafl-fuzz does the fuzzing of a harness in Rust (see main and do_harness). This harness basically just logs syscall hooks (which it gathers via IPC to lsass-iat-hook.exe).

Also in its current state it probably won't work for you (unless you're on a specific windows version), because SspirLogonUser offset and prolog instruction sizes are hardcoded in lsass-iat-hook main.cpp.
See todo above, need to get a more stable way of getting this stuff. Probably automatically download pdb from microsoft servers to get offset & use bddisasm to get prolog size.
I guess if somebody (reader) is trying to get this up and running you might aswell contribute by doing this in a PR (might aswell just make a python script or something, doesn't matter)

harness.exe is running with IPC to lsass-iat-hook.exe. libafl-fuzz sends a buffer to lsass-iat-hook.exe, lsass-iat-hook.exe forwards it to harness.exe, lsass-iat-hook.exe logs syscalls and sends them to libafl-fuzz.exe for coverage.

When harness.exe is finished with its operation, it sends back a done message to lsass-iat-hook.exe. If it "crashed" (valid input, in this case "abcde") it sends a crashed message to lsass-iat-hook.exe.

This is done to simulate lsass client calls.

~~This will be extended to use LsaLogonUser instead of the "abcde" buffer thing.~~

~~... I need to get information about successful attempts, there are probably 2 things to check: lsass crashes (~~maybe? we'll see~~ most likely) and logging in as a user without proper authorization (pretty unlikely)~~

Currently I am using LsaLogonUser with MSV1.0 Interactive logon, implemented in harness. See its code for reference.
I need to make a lot more harnesses for this to be useful.
I also should figure out lsass crashes. (They would be the most interesting since I could probably do remote DOS of a machine with them, or maybe even full blown RCE or local ACE)
