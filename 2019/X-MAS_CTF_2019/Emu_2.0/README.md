# Emu 2.0

## Emulation, 50 points

### Description

```
Hey! We have found this old cartridge under a desk in the library of Lapland. It appears to be for a system called "Emu 2.0", made back in 1978. These systems don't get produced anymore, and we can't seem to find anyone that owns one.

Thankfully we have the documentation for it, so maybe we can use it to write an emulator and see what this ROM does?

Author: Milkdrop
```

Files : [rom](rom), [documentation.pdf](documentation.pdf)

### Solution

This challenge was pretty straightforward; we were given a ROM file along with a short 3-page specification, and we had to code an emulator to run the ROM which would print out the flag.

There's nothing much to detail further, so here's my implementation of the emulator in Python.

```python
import sys

def emulate(filename):
    rom = open(filename, 'rb').read()
    assert len(rom) == 0xf00

    A = 0
    PC = 0x100
    mem = [0] * 0x100 + [x for x in rom]
    blocked = [False] * 0x1000
    
    while 0 <= PC < 0xfff:
        op = mem[PC:PC + 2]

        # Arithmetic
        if op[0] == 0x00:
            A = (A + op[1]) & 0xff
        elif op[0] == 0x01:
            A = op[1]
        elif op[0] == 0x02:
            A ^= op[1]
        elif op[0] == 0x03:
            A |= op[1]
        elif op[0] == 0x04:
            A &= op[1]
        elif op[0] >> 4 == 0x08:
            A = mem[((op[0] & 0x0f) << 8) | op[1]]
        elif op[0] >> 4 == 0x0d:
            if not blocked[((op[0] & 0x0f) << 8) | op[1]]:
                mem[((op[0] & 0x0f) << 8) | op[1]] ^= A
        elif op[0] >> 4 == 0x0f:
            if not blocked[((op[0] & 0x0f) << 8) | op[1]]:
                mem[((op[0] & 0x0f) << 8) | op[1]] = A

        # I/O        
        elif op[0] == 0x13 and op[1] == 0x37:
            sys.stdout.write(chr(A))
            sys.stdout.flush()
        
        # Control Flow
        elif op[0] >> 4 == 0x02:
            PC = ((op[0] & 0x0f) << 8) | op[1]
            continue
        elif op[0] >> 4 == 0x03:
            if A == 0x00:
                PC = ((op[0] & 0x0f) << 8) | op[1]
                continue
        elif op[0] >> 4 == 0x04:
            if A == 0x01:
                PC = ((op[0] & 0x0f) << 8) | op[1]
                continue
        elif op[0] >> 4 == 0x05:
            if A == 0xff:
                PC = ((op[0] & 0x0f) << 8) | op[1]
                continue
        elif op[0] == 0x60:
            if A == op[1]:
                A = 0x00
            elif A > op[1]:
                A = 0xff
            else:
                A = 0x01
        elif op[0] >> 4 == 0x07:
            c = mem[((op[0] & 0x0f) << 8) | op[1]]
            if A == c:
                A = 0x00
            elif A > c:
                A = 0xff
            else:
                A = 0x01
        elif op[0] == 0xbe and op[1] == 0xef:
            PC = 0x100
            A = 0x42
            continue
        
        # Security
        elif op[0] >> 4 == 0x09:
            blocked[((op[0] & 0x0f) << 8) | op[1]] = True
        elif op[0] >> 4 == 0x0a:
            blocked[((op[0] & 0x0f) << 8) | op[1]] = False
        elif op[0] >> 4 == 0x0c:
            if not blocked[((op[0] & 0x0f) << 8) | op[1]]:
                mem[((op[0] & 0x0f) << 8) | op[1]] ^= 0x42
        
        # Misc
        elif op[0] == 0xee and op[1] == 0xee:
            pass
    
        else:
            A = (A - 1) & 0xff
        
        PC += 2

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print('[-] Usage: %s <romfile>' % sys.argv[0])
        sys.exit(1)
    sys.exit(emulate(sys.argv[1]))

```

Let's run it on the file.

```shell
╭─face0xff@aniesu-chan /den/ctf/xmas  
╰─$ python rom.py rom                                                                                                                                                                                      1 ↵
X-MAS{S4nt4_U5e5_An_Emu_2.0_M4ch1n3}
```

We can notice the program actually never ends because it is stuck in an infinite loop. Indeed, at PC=0x408, the instruction is `24 08` which means "jump to 0x408".

Enjoy
