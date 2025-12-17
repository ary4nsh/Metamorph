# Metamorph

This code is a simple metamorphic engine that takes a 32-bit ELF executable binary as input, and generates a 32-bit metamorphicated ELF executable binary file. It currently supports injecting these instructions as NOP:
- NOP
- CMP [register],[register]
- PUSH [register] / POP [register]
- PUSHAD / POPAD

And altering these instructions:
- mov [register 1], [register 2] -> push [register 2]; pop [register 1] or xor [register 1], [register 1]; add [register 1], [register 2]
- xor [register], [register] -> mov [register], 0 or sub [register], [register]

Note: This code will be updated to support amd64 architecture and injecting/changing instructions...

## Usage

To make a .raw file of a shellcode, simply convert your assembly code into a machine code using these commands:
```
nasm -f elf32 shellcode.asm -o shellcode.o
ld -m elf_i386 -s -o shellcode shellcode.o
```

After that, you can use this tool to generate a metamorphicated 32-bit ELF file:
```
./Metamorph shellcode executable
```

## Example:
```
┌──(kali㉿kali)-[~/Codes/Go/Metamorph]
└─$ ./Metamorph shellcode shellcode2
Original file: 4492 bytes
Found 5 sections
.text section: offset=0x1000, size=25 bytes
.symtab section: offset=0x101c, size=96 bytes
.strtab section: offset=0x107c, size=39 bytes
.shstrtab section: offset=0x10a3, size=33 bytes
Disassembled 11 instructions
Replaced 3 patterns:
  0x0: XOR EAX, EAX -> SUB EAX, EAX
  0xd: MOV EBX, ESP -> XOR EBX, EBX; ADD EBX, ESP
  0x11: MOV ECX, ESP -> PUSH ESP; POP ECX
Injecting NOP at offset 0x13

.text size change: 25 -> 28 bytes (+3)

Output file: 4495 bytes

Success: shellcode2

┌──(kali㉿kali)-[~/Codes/Go/Metamorph]
└─$ ./shellcode2
$ whoami
kali
```

## Disassembly Difference
For original ELF:
```
┌──(kali㉿kali)-[~/Codes/Go/Metamorph]
└─$ objdump -d -M intel shellcode

shellcode:     file format elf32-i386


Disassembly of section .text:

08049000 <_start>:
 8049000:       31 c0                   xor    eax,eax
 8049002:       50                      push   eax
 8049003:       68 2f 2f 73 68          push   0x68732f2f
 8049008:       68 2f 62 69 6e          push   0x6e69622f
 804900d:       89 e3                   mov    ebx,esp
 804900f:       50                      push   eax
 8049010:       53                      push   ebx
 8049011:       89 e1                   mov    ecx,esp
 8049013:       31 d2                   xor    edx,edx
 8049015:       b0 0b                   mov    al,0xb
 8049017:       cd 80                   int    0x80
```


For metamorphicated ELF:
```
┌──(kali㉿kali)-[~/Codes/Go/Metamorph]
└─$ objdump -d -M intel shellcode2

shellcode2:     file format elf32-i386


Disassembly of section .text:

08049000 <_start>:
 8049000:       29 c0                   sub    eax,eax
 8049002:       50                      push   eax
 8049003:       68 2f 2f 73 68          push   0x68732f2f
 8049008:       68 2f 62 69 6e          push   0x6e69622f
 804900d:       31 db                   xor    ebx,ebx
 804900f:       01 e3                   add    ebx,esp
 8049011:       50                      push   eax
 8049012:       53                      push   ebx
 8049013:       90                      nop
 8049014:       54                      push   esp
 8049015:       59                      pop    ecx
 8049016:       31 d2                   xor    edx,edx
 8049018:       b0 0b                   mov    al,0xb
 804901a:       cd 80                   int    0x80
```
