start ..\out\harness.exe \\.\pipe\target_pipe_b
start ..\out\lsass-iat-hook.exe \\.\pipe\lsass_pipe_b \\.\pipe\c_pipe_b \\.\pipe\target_pipe_b 48
cargo run 48 \\.\pipe\c_pipe_b