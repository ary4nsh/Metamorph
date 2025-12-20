package transformation

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"time"

	"golang.org/x/arch/x86/x86asm"
)

type InstructionX64 struct {
	Offset uint64
	Size   int
	Inst   x86asm.Inst
}

type XorReplacementX64 struct {
	Offset   uint64
	Original string
	Replaced string
}

// ProcessX64Code applies metamorphic transformations to x64 code
func ProcessX64Code(code []byte) ([]byte, error) {
	rand.Seed(time.Now().UnixNano())

	// Disassemble
	instructions, err := disassemble(code, 64)
	if err != nil || len(instructions) == 0 {
		return nil, fmt.Errorf("disassembly failed: %w", err)
	}

	fmt.Printf("Disassembled %d instructions\n", len(instructions))

	// Replace XOR and MOV patterns
	code, replacements := replaceX64Patterns(code, instructions)
	if len(replacements) > 0 {
		fmt.Printf("Replaced %d patterns:\n", len(replacements))
		for _, repl := range replacements {
			fmt.Printf("  0x%x: %s -> %s\n", repl.Offset, repl.Original, repl.Replaced)
		}

		// Re-disassemble
		instructions, _ = disassemble(code, 64)
	}

	// Inject random instruction
	if len(instructions) > 1 {
		randomIdx := rand.Intn(len(instructions) - 1)
		selectedInsn := instructions[randomIdx]
		insertOffset := selectedInsn.Offset + uint64(selectedInsn.Size)

		injectBytes, injectName := generateRandomX64Instruction()
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

	return code, nil
}

func disassembleX64(code []byte, mode int) ([]Instruction, error) {
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

func replaceX64Patterns(code []byte, instructions []Instruction) ([]byte, []XorReplacement) {
	var replacements []XorReplacement

	// XOR r,r -> zero (64-bit registers)
	xorZero64 := map[uint32]struct {
		mov []byte // MOV r64, 0 (using 32-bit zero extension)
		sub []byte // SUB r64, r64
		reg string
	}{
		// XOR rax, rax (48 31 C0)
		0xC03148: {[]byte{0x48, 0xC7, 0xC0, 0x00, 0x00, 0x00, 0x00}, []byte{0x48, 0x29, 0xC0}, "RAX"},
		// XOR rcx, rcx (48 31 C9)
		0xC93148: {[]byte{0x48, 0xC7, 0xC1, 0x00, 0x00, 0x00, 0x00}, []byte{0x48, 0x29, 0xC9}, "RCX"},
		// XOR rdx, rdx (48 31 D2)
		0xD23148: {[]byte{0x48, 0xC7, 0xC2, 0x00, 0x00, 0x00, 0x00}, []byte{0x48, 0x29, 0xD2}, "RDX"},
		// XOR rbx, rbx (48 31 DB)
		0xDB3148: {[]byte{0x48, 0xC7, 0xC3, 0x00, 0x00, 0x00, 0x00}, []byte{0x48, 0x29, 0xDB}, "RBX"},
		// XOR rsi, rsi (48 31 F6)
		0xF63148: {[]byte{0x48, 0xC7, 0xC6, 0x00, 0x00, 0x00, 0x00}, []byte{0x48, 0x29, 0xF6}, "RSI"},
		// XOR rdi, rdi (48 31 FF)
		0xFF3148: {[]byte{0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00}, []byte{0x48, 0x29, 0xFF}, "RDI"},
		// XOR r8, r8 (4D 31 C0)
		0xC0314D: {[]byte{0x49, 0xC7, 0xC0, 0x00, 0x00, 0x00, 0x00}, []byte{0x4D, 0x29, 0xC0}, "R8"},
		// XOR r9, r9 (4D 31 C9)
		0xC9314D: {[]byte{0x49, 0xC7, 0xC1, 0x00, 0x00, 0x00, 0x00}, []byte{0x4D, 0x29, 0xC9}, "R9"},
		// XOR r10, r10 (4D 31 D2)
		0xD2314D: {[]byte{0x49, 0xC7, 0xC2, 0x00, 0x00, 0x00, 0x00}, []byte{0x4D, 0x29, 0xD2}, "R10"},
		// XOR r11, r11 (4D 31 DB)
		0xDB314D: {[]byte{0x49, 0xC7, 0xC3, 0x00, 0x00, 0x00, 0x00}, []byte{0x4D, 0x29, 0xDB}, "R11"},
		// XOR r12, r12 (4D 31 E4)
		0xE4314D: {[]byte{0x49, 0xC7, 0xC4, 0x00, 0x00, 0x00, 0x00}, []byte{0x4D, 0x29, 0xE4}, "R12"},
		// XOR r13, r13 (4D 31 ED)
		0xED314D: {[]byte{0x49, 0xC7, 0xC5, 0x00, 0x00, 0x00, 0x00}, []byte{0x4D, 0x29, 0xED}, "R13"},
		// XOR r14, r14 (4D 31 F6)
		0xF6314D: {[]byte{0x49, 0xC7, 0xC6, 0x00, 0x00, 0x00, 0x00}, []byte{0x4D, 0x29, 0xF6}, "R14"},
		// XOR r15, r15 (4D 31 FF)
		0xFF314D: {[]byte{0x49, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00}, []byte{0x4D, 0x29, 0xFF}, "R15"},
	}

	// Also handle 32-bit XOR (which zero-extends to 64-bit)
	xorZero32 := map[uint16]struct {
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

		// XOR r64,r64 -> zero (3 bytes)
		if insn.Inst.Op == x86asm.XOR && insn.Size == 3 {
			if len(insn.Inst.Args) >= 2 {
				arg0, ok0 := insn.Inst.Args[0].(x86asm.Reg)
				arg1, ok1 := insn.Inst.Args[1].(x86asm.Reg)
				if ok0 && ok1 && arg0 == arg1 {
					offset := insn.Offset
					if offset+2 < uint64(len(code)) {
						pattern := uint32(code[offset]) | (uint32(code[offset+1]) << 8) | (uint32(code[offset+2]) << 16)
						if repl, ok := xorZero64[pattern]; ok {
							var newBytes []byte
							var newText string
							if rand.Intn(2) == 0 {
								newBytes = repl.mov
								newText = fmt.Sprintf("MOV %s, 0", repl.reg)
							} else {
								newBytes = repl.sub
								newText = fmt.Sprintf("SUB %s, %s", repl.reg, repl.reg)
							}
							code = patchBytes(code, offset, code[offset:offset+3], newBytes)
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

		// XOR r32,r32 -> zero (2 bytes, zero-extends to 64-bit)
		if insn.Inst.Op == x86asm.XOR && insn.Size == 2 {
			if len(insn.Inst.Args) >= 2 {
				arg0, ok0 := insn.Inst.Args[0].(x86asm.Reg)
				arg1, ok1 := insn.Inst.Args[1].(x86asm.Reg)
				if ok0 && ok1 && arg0 == arg1 {
					offset := insn.Offset
					if offset+1 < uint64(len(code)) {
						pattern := uint16(code[offset]) | (uint16(code[offset+1]) << 8)
						if repl, ok := xorZero32[pattern]; ok {
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

		// MOV r64, r64 (different registers) -> PUSH/POP or XOR-ADD
		if insn.Inst.Op == x86asm.MOV && insn.Size == 3 {
			if len(insn.Inst.Args) >= 2 {
				dst, okD := insn.Inst.Args[0].(x86asm.Reg)
				src, okS := insn.Inst.Args[1].(x86asm.Reg)

				if okD && okS && dst != src && is64BitGPR(dst) && is64BitGPR(src) {
					offset := insn.Offset
					if offset+2 < uint64(len(code)) {
						// Check REX prefix (48/49/4C/4D)
						rex := code[offset]
						if (rex & 0xF0) == 0x40 {
							opcode := code[offset+1]
							modRM := code[offset+2]

							// MOV r/m64, r64 (opcode 89) with mod=11b
							if opcode == 0x89 && (modRM>>6) == 3 {
								var newBytes []byte
								var newText string

								if rand.Intn(2) == 0 {
									// Strategy 1: PUSH src; POP dst
									pushOp := getPushOpcodeX64(src)
									popOp := getPopOpcodeX64(dst)
									newBytes = append(pushOp, popOp...)
									newText = fmt.Sprintf("PUSH %s; POP %s", src, dst)
								} else {
									// Strategy 2: XOR dst, dst; ADD dst, src
									xorOp := encodeXorX64(dst, dst)
									addOp := encodeAddX64(dst, src)
									newBytes = append(xorOp, addOp...)
									newText = fmt.Sprintf("XOR %s, %s; ADD %s, %s", dst, dst, dst, src)
								}

								oldBytes := code[offset : offset+3]
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
	}

	return code, replacements
}

func is64BitGPR(reg x86asm.Reg) bool {
	return reg == x86asm.RAX || reg == x86asm.RCX || reg == x86asm.RDX ||
		reg == x86asm.RBX || reg == x86asm.RSI || reg == x86asm.RDI ||
		reg == x86asm.R8 || reg == x86asm.R9 || reg == x86asm.R10 ||
		reg == x86asm.R11 || reg == x86asm.R12 || reg == x86asm.R13 ||
		reg == x86asm.R14 || reg == x86asm.R15
}

func getPushOpcodeX64(reg x86asm.Reg) []byte {
	switch reg {
	case x86asm.RAX:
		return []byte{0x50}
	case x86asm.RCX:
		return []byte{0x51}
	case x86asm.RDX:
		return []byte{0x52}
	case x86asm.RBX:
		return []byte{0x53}
	case x86asm.RSP:
		return []byte{0x54}
	case x86asm.RBP:
		return []byte{0x55}
	case x86asm.RSI:
		return []byte{0x56}
	case x86asm.RDI:
		return []byte{0x57}
	case x86asm.R8:
		return []byte{0x41, 0x50}
	case x86asm.R9:
		return []byte{0x41, 0x51}
	case x86asm.R10:
		return []byte{0x41, 0x52}
	case x86asm.R11:
		return []byte{0x41, 0x53}
	case x86asm.R12:
		return []byte{0x41, 0x54}
	case x86asm.R13:
		return []byte{0x41, 0x55}
	case x86asm.R14:
		return []byte{0x41, 0x56}
	case x86asm.R15:
		return []byte{0x41, 0x57}
	default:
		return []byte{0x50}
	}
}

func getPopOpcodeX64(reg x86asm.Reg) []byte {
	switch reg {
	case x86asm.RAX:
		return []byte{0x58}
	case x86asm.RCX:
		return []byte{0x59}
	case x86asm.RDX:
		return []byte{0x5A}
	case x86asm.RBX:
		return []byte{0x5B}
	case x86asm.RSP:
		return []byte{0x5C}
	case x86asm.RBP:
		return []byte{0x5D}
	case x86asm.RSI:
		return []byte{0x5E}
	case x86asm.RDI:
		return []byte{0x5F}
	case x86asm.R8:
		return []byte{0x41, 0x58}
	case x86asm.R9:
		return []byte{0x41, 0x59}
	case x86asm.R10:
		return []byte{0x41, 0x5A}
	case x86asm.R11:
		return []byte{0x41, 0x5B}
	case x86asm.R12:
		return []byte{0x41, 0x5C}
	case x86asm.R13:
		return []byte{0x41, 0x5D}
	case x86asm.R14:
		return []byte{0x41, 0x5E}
	case x86asm.R15:
		return []byte{0x41, 0x5F}
	default:
		return []byte{0x58}
	}
}

func encodeXorX64(dst, src x86asm.Reg) []byte {
	rex := byte(0x48)
	if isExtendedReg(dst) || isExtendedReg(src) {
		rex = calculateREX(dst, src)
	}
	modRM := getModRMX64(dst, src)
	return []byte{rex, 0x31, modRM}
}

func encodeAddX64(dst, src x86asm.Reg) []byte {
	rex := byte(0x48)
	if isExtendedReg(dst) || isExtendedReg(src) {
		rex = calculateREX(dst, src)
	}
	modRM := getModRMX64(dst, src)
	return []byte{rex, 0x01, modRM}
}

func isExtendedReg(reg x86asm.Reg) bool {
	return reg >= x86asm.R8 && reg <= x86asm.R15
}

func calculateREX(dst, src x86asm.Reg) byte {
	rex := byte(0x48) // REX.W = 1
	if isExtendedReg(src) {
		rex |= 0x04 // REX.R = 1
	}
	if isExtendedReg(dst) {
		rex |= 0x01 // REX.B = 1
	}
	return rex
}

func getModRMX64(dst, src x86asm.Reg) byte {
	dstBits := getRegBitsX64(dst)
	srcBits := getRegBitsX64(src)
	return 0xC0 | (srcBits << 3) | dstBits
}

func getRegBitsX64(reg x86asm.Reg) byte {
	switch reg {
	case x86asm.RAX, x86asm.R8:
		return 0
	case x86asm.RCX, x86asm.R9:
		return 1
	case x86asm.RDX, x86asm.R10:
		return 2
	case x86asm.RBX, x86asm.R11:
		return 3
	case x86asm.RSP, x86asm.R12:
		return 4
	case x86asm.RBP, x86asm.R13:
		return 5
	case x86asm.RSI, x86asm.R14:
		return 6
	case x86asm.RDI, x86asm.R15:
		return 7
	default:
		return 0
	}
}

func generateRandomX64Instruction() ([]byte, string) {
	registers := []struct {
		name string
		push byte
		pop  byte
	}{
		{"RAX", 0x50, 0x58}, {"RCX", 0x51, 0x59}, {"RDX", 0x52, 0x5A},
		{"RBX", 0x53, 0x5B}, {"RSI", 0x56, 0x5E}, {"RDI", 0x57, 0x5F},
	}

	choice := rand.Intn(3)
	switch choice {
	case 0:
		return []byte{0x90}, "NOP"
	case 1:
		reg := registers[rand.Intn(len(registers))]
		// CMP r64, r64 (48 39 C0 style)
		modRM := byte(0xC0) | (getRegBitsFromPush(reg.push) << 3) | getRegBitsFromPush(reg.push)
		return []byte{0x48, 0x39, modRM}, fmt.Sprintf("CMP %s, %s", reg.name, reg.name)
	case 2:
		reg := registers[rand.Intn(len(registers))]
		return []byte{reg.push, reg.pop}, fmt.Sprintf("PUSH %s; POP %s", reg.name, reg.name)
	}
	return []byte{0x90}, "NOP"
}

func getRegBitsFromPush(pushOp byte) byte {
	return (pushOp - 0x50) & 0x7
}

func patchBytesX64(code []byte, offset uint64, oldBytes, newBytes []byte) []byte {
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

func fixRelativeOffsetsx64(data []byte, insertOffset uint64, instructions []Instruction, injectSize int) {
	for _, insn := range instructions {
		if isRelativeJumpOrCallX64(insn.Inst.Op) {
			target := getRelativeTargetX64(insn.Inst, insn.Offset)
			if target == 0 {
				continue
			}

			insnEnd := insn.Offset + uint64(insn.Size)

			if insnEnd <= insertOffset && target > insertOffset {
				adjustRelativeJumpX64(data, insn.Offset, insn.Size, int32(injectSize))
			}
		}
	}
}

func isRelativeJumpOrCallX64(op x86asm.Op) bool {
	switch op {
	case x86asm.JMP, x86asm.JA, x86asm.JAE, x86asm.JB, x86asm.JBE,
		x86asm.JE, x86asm.JG, x86asm.JGE, x86asm.JL, x86asm.JLE,
		x86asm.JNE, x86asm.JNO, x86asm.JNP, x86asm.JNS, x86asm.JO,
		x86asm.JP, x86asm.JS, x86asm.CALL:
		return true
	}
	return false
}

func getRelativeTargetX64(inst x86asm.Inst, currentOffset uint64) uint64 {
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

func adjustRelativeJumpX64(data []byte, insnOffset uint64, insnSize int, adjustment int32) {
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
