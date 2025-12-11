# Metamorph

This code is a simple metamorphic engine that takes .raw file of a 32-bit ELF executable binary as input, and generates a 32-bit metamorphicated ELF executable binary file. It currently supports injecting these instructions:
- NOP
- CMP [register],[register]
- PUSH [register] / POP [register]
- PUSHAD / POPAD

* Note: This code will be updated to support amd64 architecture and injecting/changing instructions...

## Usage

To make a .raw file of a shellcode, simply convert your assembly code into a machine code using these commands:
```
nasm -f elf32 shellcode.asm -o shellcode.o
ld -m elf_i386 -s -o shellcode shellcode.o
```

Then, you need to generate a .raw file from your executable:
```
objcopy -O binary shellcode shellcode.raw
```

After that, you can use this tool to generate a metamorphicated 32-bit ELF file:
```
./metamorph shellcode.raw executable
```

## Example:
```
┌──(env)─(kali㉿kali)-[~/Codes/Go/test/metamorph]
└─$ ./metamorph shellcode.raw shellcode2
Original code size: 4108 bytes
Detected mode: 64-bit (output will be 32-bit ELF)
Disassembled 2046 instructions

Selected instruction #1195:
  Offset: 0x967
  Instruction: ADD [RAX], AL
  Size: 2 bytes
  Bytes: 00 00 

Injecting PUSH EBX; POP EBX (53 5b ) at offset: 0x969

  No relative jumps/calls needed adjustment
Modified code size: 4110 bytes
Final ELF size: 8384 bytes

Successfully created ELF executable: shellcode2
                                                                     
┌──(env)─(kali㉿kali)-[~/Codes/Go/test/metamorph]
└─$ ./shellcode2                        
Hello ther$ whoami
kali
```

## Disassembly Difference
For original ELF:
```
┌──(env)─(kali㉿kali)-[~/Codes/Go/test/metamorph]
└─$ objdump -d -M intel shellcode 

shellcode:     file format elf32-i386


Disassembly of section .text:

08049000 <.text>:
 8049000:       b8 04 00 00 00          mov    eax,0x4
 8049005:       bb 01 00 00 00          mov    ebx,0x1
 804900a:       b9 00 a0 04 08          mov    ecx,0x804a000
 804900f:       ba 0c 00 00 00          mov    edx,0xc
 8049014:       cd 80                   int    0x80
 8049016:       31 c0                   xor    eax,eax
 8049018:       50                      push   eax
 8049019:       68 2f 2f 73 68          push   0x68732f2f
 804901e:       68 2f 62 69 6e          push   0x6e69622f
 8049023:       89 e3                   mov    ebx,esp
 8049025:       31 c9                   xor    ecx,ecx
 8049027:       31 d2                   xor    edx,edx
 8049029:       b0 0b                   mov    al,0xb
 804902b:       cd 80                   int    0x80
```


For metamorphicated ELF:
```
┌──(env)─(kali㉿kali)-[~/Codes/Go/test/metamorph]
└─$ objdump -d -M intel shellcode2     

shellcode2:     file format elf32-i386


Disassembly of section .text:

08049000 <.text>:
 8049000:       b8 04 00 00 00          mov    eax,0x4
 8049005:       bb 01 00 00 00          mov    ebx,0x1
 804900a:       b9 00 a0 04 08          mov    ecx,0x804a000
 804900f:       ba 0c 00 00 00          mov    edx,0xc
 8049014:       cd 80                   int    0x80
 8049016:       31 c0                   xor    eax,eax
 8049018:       50                      push   eax
 8049019:       68 2f 2f 73 68          push   0x68732f2f
 804901e:       68 2f 62 69 6e          push   0x6e69622f
 8049023:       89 e3                   mov    ebx,esp
 8049025:       31 c9                   xor    ecx,ecx
 8049027:       31 d2                   xor    edx,edx
 8049029:       b0 0b                   mov    al,0xb
 804902b:       cd 80                   int    0x80
        ...
 8049969:       53                      push   ebx
 804996a:       5b                      pop    ebx
        ...
 8049fff:       00 00                   add    BYTE PTR [eax],al
 804a001:       00 48 65                add    BYTE PTR [eax+0x65],cl
 804a004:       6c                      ins    BYTE PTR es:[edi],dx
 804a005:       6c                      ins    BYTE PTR es:[edi],dx
 804a006:       6f                      outs   dx,DWORD PTR ds:[esi]
 804a007:       20 74 68 65             and    BYTE PTR [eax+ebp*2+0x65],dh
 804a00b:       72 65                   jb     0x804a072
        ...
```
