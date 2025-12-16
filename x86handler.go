package main

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

type XorReplacement struct {
	Offset   uint64
	Original string
	Replaced string
}

// ProcessX86Code applies metamorphic transformations to x86 code
func ProcessX86Code(code []byte) ([]byte, error) {
	rand.Seed(time.Now().UnixNano())

	// Disassemble
	instructions, err := disassemble(code, 32)
	if err != nil || len(instructions) == 0 {
		return nil, fmt.Errorf("disassembly failed: %w", err)
	}

	fmt.Printf("Disassembled %d instructions\n", len(instructions))

	// Replace XOR and MOV patterns
	code, replacements := replaceXorPatterns(code, instructions)
	if len(replacements) > 0 {
		fmt.Printf("Replaced %d patterns:\n", len(replacements))
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

	// Fix relative jumps
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

func replaceXorPatterns(code []byte, instructions []Instruction) ([]byte, []XorReplacement) {
	var replacements []XorReplacement

	// XOR r,r -> zero
	xorZero := map[uint16]struct {
		mov []byte
		sub []byte
		reg string
	}{
		0xC031: {[]byte{0xB8, 0x00, 0x00, 0x00, 0x00}, []byte{0x29, 0xC0}, "EAX"},
		0xC933: {[]byte{0xB9, 0x00, 0x00, 0x00, 0x00}, []byte{0x29, 0xC9}, "ECX"},
		0xD233: {[]byte{0xBA, 0x00, 0x00, 0x00, 0x00}, []byte{0x29, 0xD2}, "EDX"},
		0xDB33: {[]byte{0xBB, 0x00, 0x00, 0x00, 0x00}, []byte{0x29, 0xDB}, "EBX"},
		0xF633: {[]byte{0xBE, 0x00, 0x00, 0x00, 0x00}, []byte{0x29, 0xF6}, "ESI"},
		0xFF33: {[]byte{0xBF, 0x00, 0x00, 0x00, 0x00}, []byte{0x29, 0xFF}, "EDI"},
	}

	// Walk backwards so offsets stay valid while we patch
	for i := len(instructions) - 1; i >= 0; i-- {
		insn := instructions[i]

		// XOR r,r -> zero
		if insn.Inst.Op == x86asm.XOR && insn.Size == 2 {
			if len(insn.Inst.Args) >= 2 {
				arg0, ok0 := insn.Inst.Args[0].(x86asm.Reg)
				arg1, ok1 := insn.Inst.Args[1].(x86asm.Reg)
				if ok0 && ok1 && arg0 == arg1 {
					offset := insn.Offset
					if offset+1 < uint64(len(code)) {
						pattern := uint16(code[offset]) | (uint16(code[offset+1]) << 8)
						if repl, ok := xorZero[pattern]; ok {
							var newBytes []byte
							var newText string
							if rand.Intn(2) == 0 {
								newBytes = repl.mov
								newText = fmt.Sprintf("MOV %s, 0", repl.reg)
							} else {
								newBytes = repl.sub
								newText = fmt.Sprintf("SUB %s, %s", repl.reg, repl.reg)
							}
							code = patchBytes(code, offset, code[offset:offset+2], newBytes)
							replacements = prepend(replacements, XorReplacement{
								Offset:   offset,
								Original: fmt.Sprintf("XOR %s, %s", repl.reg, repl.reg),
								Replaced: newText,
							})
							continue
						}
					}
				}
			}
		}

		// MOV r32, r32 (ONLY different registers) -> PUSH/POP or XOR-ADD
		if insn.Inst.Op == x86asm.MOV && insn.Size == 2 {
			if len(insn.Inst.Args) >= 2 {
				dst, okD := insn.Inst.Args[0].(x86asm.Reg)
				src, okS := insn.Inst.Args[1].(x86asm.Reg)
				
				// CRITICAL: Only transform when dst != src (different registers)
				if okD && okS && dst != src && is32BitGPR(dst) && is32BitGPR(src) {
					offset := insn.Offset
					if offset+1 < uint64(len(code)) {
						modRM := code[offset+1]
						
						// Check if this is register-to-register MOV (mod=11b)
						if (modRM >> 6) == 3 {
							var newBytes []byte
							var newText string
							
							if rand.Intn(2) == 0 {
								// Strategy 1: PUSH src; POP dst
								pushOp := getPushOpcode(src)
								popOp := getPopOpcode(dst)
								newBytes = []byte{pushOp, popOp}
								newText = fmt.Sprintf("PUSH %s; POP %s", src, dst)
							} else {
								// Strategy 2: XOR dst, dst; ADD dst, src
								xorOp := []byte{0x31, getModRM(dst, dst)}
								addOp := []byte{0x01, getModRM(dst, src)}
								newBytes = append(xorOp, addOp...)
								newText = fmt.Sprintf("XOR %s, %s; ADD %s, %s", dst, dst, dst, src)
							}
							
							// Replace the 2-byte MOV with new instruction sequence
							oldBytes := code[offset : offset+2]
							code = patchBytes(code, offset, oldBytes, newBytes)
							
							replacements = prepend(replacements, XorReplacement{
								Offset:   offset,
								Original: fmt.Sprintf("MOV %s, %s", dst, src),
								Replaced: newText,
							})
						}
					}
				}
			}
		}
	}
	return code, replacements
}

// patchBytes replaces oldBytes at offset, grows/shrinks slice if needed
func patchBytes(code []byte, offset uint64, oldBytes, newBytes []byte) []byte {
	delta := len(newBytes) - len(oldBytes)
	if delta == 0 {
		copy(code[offset:], newBytes)
		return code
	}
	newCode := make([]byte, len(code)+delta)
	copy(newCode[:offset], code[:offset])
	copy(newCode[offset:], newBytes)
	copy(newCode[offset+uint64(len(newBytes)):], code[offset+uint64(len(oldBytes)):])
	return newCode
}

func prepend(lst []XorReplacement, item XorReplacement) []XorReplacement {
	return append([]XorReplacement{item}, lst...)
}

func is32BitGPR(reg x86asm.Reg) bool {
	return reg == x86asm.EAX || reg == x86asm.ECX || reg == x86asm.EDX || 
	       reg == x86asm.EBX || reg == x86asm.ESI || reg == x86asm.EDI || 
	       reg == x86asm.ESP || reg == x86asm.EBP
}

func getPushOpcode(reg x86asm.Reg) byte {
	switch reg {
	case x86asm.EAX: return 0x50
	case x86asm.ECX: return 0x51
	case x86asm.EDX: return 0x52
	case x86asm.EBX: return 0x53
	case x86asm.ESP: return 0x54
	case x86asm.EBP: return 0x55
	case x86asm.ESI: return 0x56
	case x86asm.EDI: return 0x57
	default: return 0x50
	}
}

func getPopOpcode(reg x86asm.Reg) byte {
	switch reg {
	case x86asm.EAX: return 0x58
	case x86asm.ECX: return 0x59
	case x86asm.EDX: return 0x5A
	case x86asm.EBX: return 0x5B
	case x86asm.ESP: return 0x5C
	case x86asm.EBP: return 0x5D
	case x86asm.ESI: return 0x5E
	case x86asm.EDI: return 0x5F
	default: return 0x58
	}
}

func getModRM(dst, src x86asm.Reg) byte {
	dstBits := getRegBits(dst)
	srcBits := getRegBits(src)
	return 0xC0 | (srcBits << 3) | dstBits
}

func getRegBits(reg x86asm.Reg) byte {
	switch reg {
	case x86asm.EAX: return 0
	case x86asm.ECX: return 1
	case x86asm.EDX: return 2
	case x86asm.EBX: return 3
	case x86asm.ESP: return 4
	case x86asm.EBP: return 5
	case x86asm.ESI: return 6
	case x86asm.EDI: return 7
	default: return 0
	}
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
		if isRelativeJumpOrCall(insn.Inst.Op) {
			target := getRelativeTarget(insn.Inst, insn.Offset)
			if target == 0 {
				continue
			}

			insnEnd := insn.Offset + uint64(insn.Size)

			if insnEnd <= insertOffset && target > insertOffset {
				adjustRelativeJump(data, insn.Offset, insn.Size, int32(injectSize))
			}
		}
	}
}

func isRelativeJumpOrCall(op x86asm.Op) bool {
	switch op {
	case x86asm.JMP, x86asm.JA, x86asm.JAE, x86asm.JB, x86asm.JBE,
		x86asm.JE, x86asm.JG, x86asm.JGE, x86asm.JL, x86asm.JLE,
		x86asm.JNE, x86asm.JNO, x86asm.JNP, x86asm.JNS, x86asm.JO,
		x86asm.JP, x86asm.JS, x86asm.CALL:
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

func adjustRelativeJump(data []byte, insnOffset uint64, insnSize int, adjustment int32) {
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