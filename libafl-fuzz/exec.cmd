start ..\out\harness.exe \\.\pipe\target_pipe_a
start ..\out\lsass-iat-hook.exe \\.\pipe\lsass_pipe_a \\.\pipe\c_pipe_a \\.\pipe\target_pipe_a 48
cargo run 48 \\.\pipe\c_pipe_a