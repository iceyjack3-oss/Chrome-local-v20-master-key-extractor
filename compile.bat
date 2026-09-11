@echo off
rem low level CRT-Less compiler flags
gcc chromastereng1.c -o chromenginev20.exe -nostdlib -e entry -mno-stack-arg-probe -O -s -lkernel32 -luser32
pause