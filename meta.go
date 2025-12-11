package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"math/rand"
	"os"
	"time"

	"golang.org/x/arch/x86/x86asm"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintf(os.Stderr, "Usage: %s <input.raw> <output_binary>\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "\nReads raw x86 binary, injects NOP after random instruction, outputs ELF executable.\n")
		os.Exit(1)
	}

	inputFile := os.Args[1]
	outputFile := os.Args[2]

	if err := processRawToELF(inputFile, outputFile); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("\nSuccessfully created ELF executable: %s\n", outputFile)
}

type Instruction struct {
	Offset uint64
	Size   int
	Inst   x86asm.Inst
}

func processRawToELF(inputPath, outputPath string) error {
	// Read the raw binary file
	inFile, err := os.Open(inputPath)
	if err != nil {
		return fmt.Errorf("failed to open input file: %w", err)
	}
	defer inFile.Close()

	code, err := io.ReadAll(inFile)
	if err != nil {
		return fmt.Errorf("failed to read input file: %w", err)
	}

	if len(code) == 0 {
		return fmt.Errorf("input file is empty")
	}

	fmt.Printf("Original code size: %d bytes\n", len(code))

	// Detect if it's 32-bit or 64-bit by trying to disassemble
	mode := detectMode(code)
	fmt.Printf("Detected mode: %d-bit (output will be 32-bit ELF)\n", mode)

	// Disassemble the code
	instructions, err := disassemble(code, mode)
	if err != nil || len(instructions) == 0 {
		return fmt.Errorf("failed to disassemble code: %w", err)
	}

	fmt.Printf("Disassembled %d instructions\n\n", len(instructions))

	// Choose a random instruction (not the last one)
	rand.Seed(time.Now().UnixNano())
	randomIdx := rand.Intn(len(instructions) - 1)
	selectedInsn := instructions[randomIdx]

	// Calculate offset after the selected instruction
	insertOffset := selectedInsn.Offset + uint64(selectedInsn.Size)

	// Randomly choose instruction to inject
	var injectBytes []byte
	var injectName string
	
	// Register opcodes for 32-bit
	registers := []struct {
		name string
		code byte
	}{
		{"EAX", 0xC0}, // 000
		{"ECX", 0xC9}, // 001
		{"EDX", 0xD2}, // 010
		{"EBX", 0xDB}, // 011
		{"ESP", 0xE4}, // 100 (skip for push/pop)
		{"EBP", 0xED}, // 101 (skip for push/pop)
		{"ESI", 0xF6}, // 110
		{"EDI", 0xFF}, // 111
	}
	
	// Filter out ESP and EBP for push/pop operations
	safeRegisters := []struct {
		name     string
		code     byte
		pushPop  byte
	}{
		{"EAX", 0xC0, 0x50},
		{"ECX", 0xC9, 0x51},
		{"EDX", 0xD2, 0x52},
		{"EBX", 0xDB, 0x53},
		{"ESI", 0xF6, 0x56},
		{"EDI", 0xFF, 0x57},
	}
	
	choice := rand.Intn(4)
	
	switch choice {
	case 0:
		// NOP
		injectBytes = []byte{0x90}
		injectName = "NOP"
		
	case 1:
		// CMP reg, reg
		reg := registers[rand.Intn(len(registers))]
		injectBytes = []byte{0x39, reg.code}
		injectName = fmt.Sprintf("CMP %s, %s", reg.name, reg.name)
		
	case 2:
		// PUSH reg; POP reg
		reg := safeRegisters[rand.Intn(len(safeRegisters))]
		injectBytes = []byte{reg.pushPop, reg.pushPop + 0x08} // PUSH=0x50+r, POP=0x58+r
		injectName = fmt.Sprintf("PUSH %s; POP %s", reg.name, reg.name)
		
	case 3:
		// PUSHAD; POPAD
		injectBytes = []byte{0x60, 0x61}
		injectName = "PUSHAD; POPAD"
	}

	fmt.Printf("Selected instruction #%d:\n", randomIdx)
	fmt.Printf("  Offset: 0x%x\n", selectedInsn.Offset)
	fmt.Printf("  Instruction: %s %s\n", selectedInsn.Inst.Op, formatArgs(selectedInsn.Inst))
	fmt.Printf("  Size: %d bytes\n", selectedInsn.Size)
	fmt.Printf("  Bytes: %s\n", formatBytes(code[selectedInsn.Offset:selectedInsn.Offset+uint64(selectedInsn.Size)]))
	fmt.Printf("\nInjecting %s (%s) at offset: 0x%x\n\n", injectName, formatBytes(injectBytes), insertOffset)

	// Create new code with inserted instruction
	newCode := make([]byte, len(code)+len(injectBytes))
	copy(newCode[:insertOffset], code[:insertOffset])
	copy(newCode[insertOffset:insertOffset+uint64(len(injectBytes))], injectBytes)
	copy(newCode[insertOffset+uint64(len(injectBytes)):], code[insertOffset:])

	// Fix relative jumps and calls
	fixRelativeOffsets(newCode, insertOffset, instructions, len(injectBytes))

	// Create ELF32 executable (always 32-bit)
	elfData := createELF32(newCode)

	// Write the ELF file
	outFile, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer outFile.Close()

	if _, err := outFile.Write(elfData); err != nil {
		return fmt.Errorf("failed to write output file: %w", err)
	}

	// Make executable
	if err := os.Chmod(outputPath, 0755); err != nil {
		return fmt.Errorf("failed to set executable permission: %w", err)
	}

	fmt.Printf("Modified code size: %d bytes\n", len(newCode))
	fmt.Printf("Final ELF size: %d bytes\n", len(elfData))

	return nil
}

func detectMode(code []byte) int {
	// Try to disassemble as 32-bit first
	instructions32, err32 := disassemble(code, 32)
	instructions64, err64 := disassemble(code, 64)

	// If 32-bit works better, use it
	if err32 == nil && len(instructions32) > 0 {
		if err64 != nil || len(instructions32) > len(instructions64) {
			return 32
		}
	}

	return 64
}

func createELF32(code []byte) []byte {
	// ELF32 structure
	baseAddr := uint32(0x08048000)
	codeAddr := baseAddr + 0x1000 // Code starts at second page
	
	ehSize := uint16(52)      // ELF header size
	phentSize := uint16(32)   // Program header entry size
	phnum := uint16(1)        // Number of program headers
	shentSize := uint16(40)   // Section header entry size
	shnum := uint16(4)        // Number of sections: null, .text, .shstrtab
	
	// Section names
	shstrtab := "\x00.text\x00.shstrtab\x00"
	
	// Calculate offsets
	phoff := uint32(ehSize)
	codeOffset := uint32(0x1000)
	codeSize := uint32(len(code))
	shstrtabOffset := codeOffset + codeSize
	shoff := shstrtabOffset + uint32(len(shstrtab))
	
	// Align section header table
	if shoff%4 != 0 {
		shoff = ((shoff / 4) + 1) * 4
	}
	
	totalSize := int(shoff) + int(shentSize)*int(shnum)
	buf := make([]byte, totalSize)
	
	// ELF Header
	copy(buf[0:4], []byte{0x7f, 'E', 'L', 'F'}) // Magic
	buf[4] = 1                                    // 32-bit
	buf[5] = 1                                    // Little endian
	buf[6] = 1                                    // ELF version
	buf[7] = 0                                    // SYSV ABI
	// buf[8:16] = padding
	binary.LittleEndian.PutUint16(buf[16:18], 2)        // e_type: ET_EXEC
	binary.LittleEndian.PutUint16(buf[18:20], 3)        // e_machine: EM_386
	binary.LittleEndian.PutUint32(buf[20:24], 1)        // e_version
	binary.LittleEndian.PutUint32(buf[24:28], codeAddr) // e_entry
	binary.LittleEndian.PutUint32(buf[28:32], phoff)    // e_phoff
	binary.LittleEndian.PutUint32(buf[32:36], shoff)    // e_shoff
	binary.LittleEndian.PutUint32(buf[36:40], 0)        // e_flags
	binary.LittleEndian.PutUint16(buf[40:42], ehSize)   // e_ehsize
	binary.LittleEndian.PutUint16(buf[42:44], phentSize) // e_phentsize
	binary.LittleEndian.PutUint16(buf[44:46], phnum)    // e_phnum
	binary.LittleEndian.PutUint16(buf[46:48], shentSize) // e_shentsize
	binary.LittleEndian.PutUint16(buf[48:50], shnum)    // e_shnum
	binary.LittleEndian.PutUint16(buf[50:52], 2)        // e_shstrndx (.shstrtab is section 2)
	
	// Program Header (LOAD segment)
	phoffInt := int(phoff)
	binary.LittleEndian.PutUint32(buf[phoffInt+0:phoffInt+4], 1)          // p_type: PT_LOAD
	binary.LittleEndian.PutUint32(buf[phoffInt+4:phoffInt+8], 0)          // p_offset
	binary.LittleEndian.PutUint32(buf[phoffInt+8:phoffInt+12], baseAddr)  // p_vaddr
	binary.LittleEndian.PutUint32(buf[phoffInt+12:phoffInt+16], baseAddr) // p_paddr
	binary.LittleEndian.PutUint32(buf[phoffInt+16:phoffInt+20], uint32(totalSize)) // p_filesz
	binary.LittleEndian.PutUint32(buf[phoffInt+20:phoffInt+24], uint32(totalSize)) // p_memsz
	binary.LittleEndian.PutUint32(buf[phoffInt+24:phoffInt+28], 7)        // p_flags: RWX
	binary.LittleEndian.PutUint32(buf[phoffInt+28:phoffInt+32], 0x1000)   // p_align
	
	// Copy code
	copy(buf[codeOffset:], code)
	
	// Copy .shstrtab
	copy(buf[shstrtabOffset:], []byte(shstrtab))
	
	// Section Headers
	shoffInt := int(shoff)
	
	// Section 0: NULL section
	// All zeros, skip
	
	// Section 1: .text
	sh := shoffInt + int(shentSize)
	binary.LittleEndian.PutUint32(buf[sh+0:sh+4], 1)           // sh_name (offset in .shstrtab)
	binary.LittleEndian.PutUint32(buf[sh+4:sh+8], 1)           // sh_type: SHT_PROGBITS
	binary.LittleEndian.PutUint32(buf[sh+8:sh+12], 6)          // sh_flags: SHF_ALLOC | SHF_EXECINSTR
	binary.LittleEndian.PutUint32(buf[sh+12:sh+16], codeAddr)  // sh_addr
	binary.LittleEndian.PutUint32(buf[sh+16:sh+20], codeOffset) // sh_offset
	binary.LittleEndian.PutUint32(buf[sh+20:sh+24], codeSize)  // sh_size
	binary.LittleEndian.PutUint32(buf[sh+24:sh+28], 0)         // sh_link
	binary.LittleEndian.PutUint32(buf[sh+28:sh+32], 0)         // sh_info
	binary.LittleEndian.PutUint32(buf[sh+32:sh+36], 16)        // sh_addralign
	binary.LittleEndian.PutUint32(buf[sh+36:sh+40], 0)         // sh_entsize
	
	// Section 2: .shstrtab
	sh = shoffInt + int(shentSize)*2
	binary.LittleEndian.PutUint32(buf[sh+0:sh+4], 7)           // sh_name (offset in .shstrtab)
	binary.LittleEndian.PutUint32(buf[sh+4:sh+8], 3)           // sh_type: SHT_STRTAB
	binary.LittleEndian.PutUint32(buf[sh+8:sh+12], 0)          // sh_flags
	binary.LittleEndian.PutUint32(buf[sh+12:sh+16], 0)         // sh_addr
	binary.LittleEndian.PutUint32(buf[sh+16:sh+20], shstrtabOffset) // sh_offset
	binary.LittleEndian.PutUint32(buf[sh+20:sh+24], uint32(len(shstrtab))) // sh_size
	binary.LittleEndian.PutUint32(buf[sh+24:sh+28], 0)         // sh_link
	binary.LittleEndian.PutUint32(buf[sh+28:sh+32], 0)         // sh_info
	binary.LittleEndian.PutUint32(buf[sh+32:sh+36], 1)         // sh_addralign
	binary.LittleEndian.PutUint32(buf[sh+36:sh+40], 0)         // sh_entsize
	
	return buf
}

func disassemble(code []byte, mode int) ([]Instruction, error) {
	var instructions []Instruction
	offset := uint64(0)

	for offset < uint64(len(code)) {
		inst, err := x86asm.Decode(code[offset:], mode)
		if err != nil {
			offset++
			continue
		}

		instructions = append(instructions, Instruction{
			Offset: offset,
			Size:   inst.Len,
			Inst:   inst,
		})

		offset += uint64(inst.Len)
	}

	return instructions, nil
}

func fixRelativeOffsets(data []byte, insertOffset uint64, instructions []Instruction, injectSize int) {
	adjustedCount := 0

	for _, insn := range instructions {
		if isRelativeJumpOrCall(insn.Inst.Op) {
			target := getRelativeTarget(insn.Inst, insn.Offset)
			if target == 0 {
				continue
			}

			insnEnd := insn.Offset + uint64(insn.Size)

			if insnEnd <= insertOffset && target > insertOffset {
				adjustRelativeJump(data, insn.Offset, insn.Size, insn.Inst, int32(injectSize))
				fmt.Printf("  Adjusted relative jump at offset 0x%x -> target 0x%x (added %d bytes)\n", insn.Offset, target, injectSize)
				adjustedCount++
			}
		}
	}

	if adjustedCount == 0 {
		fmt.Println("  No relative jumps/calls needed adjustment")
	} else {
		fmt.Printf("  Total adjustments: %d\n", adjustedCount)
	}
}

func isRelativeJumpOrCall(op x86asm.Op) bool {
	switch op {
	case x86asm.JMP, x86asm.JA, x86asm.JAE, x86asm.JB, x86asm.JBE,
		x86asm.JE, x86asm.JG, x86asm.JGE, x86asm.JL, x86asm.JLE,
		x86asm.JNE, x86asm.JNO, x86asm.JNP, x86asm.JNS, x86asm.JO,
		x86asm.JP, x86asm.JS, x86asm.CALL, x86asm.LOOP, x86asm.LOOPE,
		x86asm.LOOPNE, x86asm.JCXZ, x86asm.JECXZ:
		return true
	}
	return false
}

func getRelativeTarget(inst x86asm.Inst, currentOffset uint64) uint64 {
	for _, arg := range inst.Args {
		if arg == nil {
			continue
		}
		if rel, ok := arg.(x86asm.Rel); ok {
			target := int64(currentOffset) + int64(inst.Len) + int64(rel)
			if target >= 0 {
				return uint64(target)
			}
		}
	}
	return 0
}

func adjustRelativeJump(data []byte, insnOffset uint64, insnSize int, inst x86asm.Inst, adjustment int32) {
	var offsetSize int
	var offsetPos uint64

	if insnSize == 2 {
		offsetSize = 1
		offsetPos = insnOffset + 1
	} else if insnSize >= 5 {
		offsetSize = 4
		offsetPos = insnOffset + uint64(insnSize) - 4
	} else if insnSize == 3 || insnSize == 4 {
		offsetSize = insnSize - 1
		offsetPos = insnOffset + 1
	} else {
		offsetSize = 4
		offsetPos = insnOffset + uint64(insnSize) - 4
	}

	if offsetPos+uint64(offsetSize) <= uint64(len(data)) {
		switch offsetSize {
		case 1:
			currentOffset := int8(data[offsetPos])
			newOffset := currentOffset + int8(adjustment)
			data[offsetPos] = byte(newOffset)
		case 2:
			currentOffset := int16(binary.LittleEndian.Uint16(data[offsetPos : offsetPos+2]))
			newOffset := currentOffset + int16(adjustment)
			binary.LittleEndian.PutUint16(data[offsetPos:offsetPos+2], uint16(newOffset))
		case 4:
			currentOffset := int32(binary.LittleEndian.Uint32(data[offsetPos : offsetPos+4]))
			newOffset := currentOffset + adjustment
			binary.LittleEndian.PutUint32(data[offsetPos:offsetPos+4], uint32(newOffset))
		}
	}
}

func formatBytes(bytes []byte) string {
	result := ""
	for _, b := range bytes {
		result += fmt.Sprintf("%02x ", b)
	}
	return result
}

func formatArgs(inst x86asm.Inst) string {
	args := ""
	for i, arg := range inst.Args {
		if arg == nil {
			break
		}
		if i > 0 {
			args += ", "
		}
		args += arg.String()
	}
	return args
}
