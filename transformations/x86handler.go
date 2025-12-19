package transformation

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"time"

	"golang.org/x/arch/x86/x86asm"
)

type Instruction struct {
	Offset uint64
	Size   int
	Inst   x86asm.Inst
}

// ProcessX86Code applies metamorphic transformations to x86 code
func ProcessX86Code(code []byte, textBaseAddr uint32) ([]byte, error) {
	rand.Seed(time.Now().UnixNano())

	// Disassemble
	instructions, err := disassemble(code, 32)
	if err != nil || len(instructions) == 0 {
		return nil, fmt.Errorf("disassembly failed: %w", err)
	}

	fmt.Printf("Disassembled %d instructions\n", len(instructions))

	// Replace XOR and MOV reg, reg patterns (only one)
	code, replacements := ReplaceXorPatterns(code, instructions)
	if len(replacements) > 0 {
		fmt.Printf("Replaced 1 XOR/MOV pattern:\n")
		for _, repl := range replacements {
			fmt.Printf("  0x%x: %s -> %s\n", repl.Offset, repl.Original, repl.Replaced)
		}

		// Re-disassemble
		instructions, _ = disassemble(code, 32)
	}

	// Inject random instruction
	randomIdx := rand.Intn(len(instructions) - 1)
	selectedInsn := instructions[randomIdx]
	insertOffset := selectedInsn.Offset + uint64(selectedInsn.Size)

	injectBytes, injectName := generateRandomInstruction()
	fmt.Printf("Injecting %s at offset 0x%x\n", injectName, insertOffset)

	// Insert instruction
	newCode := make([]byte, len(code)+len(injectBytes))
	copy(newCode[:insertOffset], code[:insertOffset])
	copy(newCode[insertOffset:], injectBytes)
	copy(newCode[insertOffset+uint64(len(injectBytes)):], code[insertOffset:])

	// Fix relative jumps after injection
	fixRelativeOffsets(newCode, insertOffset, instructions, len(injectBytes))

	return newCode, nil
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

func generateRandomInstruction() ([]byte, string) {
	registers := []struct {
		name string
		code byte
	}{
		{"EAX", 0xC0}, {"ECX", 0xC9}, {"EDX", 0xD2}, {"EBX", 0xDB},
		{"ESI", 0xF6}, {"EDI", 0xFF},
	}

	safeRegisters := []struct {
		name    string
		pushPop byte
	}{
		{"EAX", 0x50}, {"ECX", 0x51}, {"EDX", 0x52},
		{"EBX", 0x53}, {"ESI", 0x56}, {"EDI", 0x57},
	}

	choice := rand.Intn(4)
	switch choice {
	case 0:
		return []byte{0x90}, "NOP"
	case 1:
		reg := registers[rand.Intn(len(registers))]
		return []byte{0x39, reg.code}, fmt.Sprintf("CMP %s, %s", reg.name, reg.name)
	case 2:
		reg := safeRegisters[rand.Intn(len(safeRegisters))]
		return []byte{reg.pushPop, reg.pushPop + 0x08}, fmt.Sprintf("PUSH %s; POP %s", reg.name, reg.name)
	case 3:
		return []byte{0x60, 0x61}, "PUSHAD; POPAD"
	}
	return []byte{0x90}, "NOP"
}

func fixRelativeOffsets(data []byte, insertOffset uint64, instructions []Instruction, injectSize int) {
	for _, insn := range instructions {
		if isRelativeJumpOrCallX86(insn.Inst.Op) {
			target := getRelativeTargetX86(insn.Inst, insn.Offset)
			if target == 0 {
				continue
			}

			insnEnd := insn.Offset + uint64(insn.Size)

			if insnEnd <= insertOffset && target > insertOffset {
				adjustRelativeJumpX86(data, insn.Offset, insn.Size, int32(injectSize))
			}
		}
	}
}

func isRelativeJumpOrCallX86(op x86asm.Op) bool {
	switch op {
	case x86asm.JMP, x86asm.JA, x86asm.JAE, x86asm.JB, x86asm.JBE,
		x86asm.JE, x86asm.JG, x86asm.JGE, x86asm.JL, x86asm.JLE,
		x86asm.JNE, x86asm.JNO, x86asm.JNP, x86asm.JNS, x86asm.JO,
		x86asm.JP, x86asm.JS, x86asm.CALL:
		return true
	}
	return false
}

func getRelativeTargetX86(inst x86asm.Inst, currentOffset uint64) uint64 {
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

func adjustRelativeJumpX86(data []byte, insnOffset uint64, insnSize int, adjustment int32) {
	var offsetSize int
	var offsetPos uint64

	if insnSize == 2 {
		offsetSize = 1
		offsetPos = insnOffset + 1
	} else if insnSize >= 5 {
		offsetSize = 4
		offsetPos = insnOffset + uint64(insnSize) - 4
	} else {
		offsetSize = 4
		offsetPos = insnOffset + uint64(insnSize) - 4
	}

	if offsetPos+uint64(offsetSize) <= uint64(len(data)) {
		switch offsetSize {
		case 1:
			currentOffset := int8(data[offsetPos])
			data[offsetPos] = byte(currentOffset + int8(adjustment))
		case 4:
			currentOffset := int32(binary.LittleEndian.Uint32(data[offsetPos : offsetPos+4]))
			binary.LittleEndian.PutUint32(data[offsetPos:], uint32(currentOffset+adjustment))
		}
	}
}