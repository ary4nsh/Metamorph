package transformation

import (
	"fmt"
	"math/rand"

	"golang.org/x/arch/x86/x86asm"
)

type XorReplacement struct {
	Offset   uint64
	Original string
	Replaced string
}

// ReplaceXorPatterns replaces XOR and MOV reg,reg patterns with equivalent instructions
func ReplaceXorPatterns(code []byte, instructions []Instruction) ([]byte, []XorReplacement) {
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
							replacements = append(replacements, XorReplacement{
								Offset:   offset,
								Original: fmt.Sprintf("XOR %s, %s", repl.reg, repl.reg),
								Replaced: newText,
							})
							// Only replace one pattern
							return code, replacements
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

							replacements = append(replacements, XorReplacement{
								Offset:   offset,
								Original: fmt.Sprintf("MOV %s, %s", dst, src),
								Replaced: newText,
							})
							// Only replace one pattern
							return code, replacements
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

func getPushOpcode(reg x86asm.Reg) byte {
	switch reg {
	case x86asm.EAX:
		return 0x50
	case x86asm.ECX:
		return 0x51
	case x86asm.EDX:
		return 0x52
	case x86asm.EBX:
		return 0x53
	case x86asm.ESP:
		return 0x54
	case x86asm.EBP:
		return 0x55
	case x86asm.ESI:
		return 0x56
	case x86asm.EDI:
		return 0x57
	default:
		return 0x50
	}
}

func getPopOpcode(reg x86asm.Reg) byte {
	switch reg {
	case x86asm.EAX:
		return 0x58
	case x86asm.ECX:
		return 0x59
	case x86asm.EDX:
		return 0x5A
	case x86asm.EBX:
		return 0x5B
	case x86asm.ESP:
		return 0x5C
	case x86asm.EBP:
		return 0x5D
	case x86asm.ESI:
		return 0x5E
	case x86asm.EDI:
		return 0x5F
	default:
		return 0x58
	}
}
