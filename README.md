# lsass-fuzz

Fuzzing lsass with afl++ using a remote IAT hook as coverage information

### ❗ Currently only the remote IAT hook functionality is implemented, meaning I'm not fuzzing anything (yet!)
## TODO
[ ] Forward this coverage information to afl-fuzz (probably via manually writing to the __afl_area_ptr)

[ ] Write the actual harness

[ ] Perhaps also stackwalk to get better coverage information (get information about specific branches)

[ ] Write a blogpost ?? :)

#### Other theoretical methods

[ ] Maybe try a different method of getting coverage, like emulation

[ ] Maybe use static binary rewriting & somehow just map lsasrv.dll

[ ] Maybe try libAFL with FRIDA?

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

    This executable hooks every function from the IAT of lsasrv.dll which is loaded in lsass.exe and logs them. This will later be used as coverage information for afl-fuzz.
        
```

## Some notes
I will have to somehow compile with `afl-cc` so that `afl-fuzz` runs it (and `__afl_area_ptr` needs to be valid in the executable) but also so that it doesn't instrument this IAT hooking thing. Perhaps compile `middleware.c` with `gcc`, link that regular non-instrumented object with afl-cc, and access `__afl_area_ptr` manually from `middleware.c`

Probably the easiest solution to achieve this would be:

(Assume we're in a VM)

lsass-iat-hook.exe running in the VM

afl-fuzz running in WSL inside the VM, running a "middleware" executable, which would probably communicate via named pipe, or a slower but probably easier to implement option (with WSL) would be sockets

Assume this middleware communicates to lsass-iat-hook.exe, lsass-iat-hook.exe informs it about the logged functions/syscalls, and the middleware simply passes this down to `afl-fuzz` (via `__afl_area_ptr`). Also set up persistent mode in this `middleware.c` which would actually just execute LsaLogonUser (or any other function)

Some problems with this multi step middleware stuff might be speed, but we'll see

I also need to get information about successful attempts, there are probably 2 things to check: lsass crashes (maybe? we'll see) and logging in as a user without proper authorization (pretty unlikely)