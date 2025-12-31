package transformation

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"time"

	"golang.org/x/arch/x86/x86asm"
)

type MovRegRegReplacement struct {
	Offset   uint64
	Original string
	Replaced string
}

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

	transformationCount := 0

	// Try MOV reg, imm transformation
	code, movReplacements := ReplaceMovRegImm(code, instructions)
	if len(movReplacements) > 0 {
		fmt.Printf("Replaced 1 MOV reg, imm pattern:\n")
		for _, repl := range movReplacements {
			fmt.Printf("  0x%x: %s -> %s\n", repl.Offset, repl.Original, repl.Replaced)
		}
		transformationCount++
		// Re-disassemble after transformation
		instructions, _ = disassemble(code, 32)
	}

	// Try XOR/MOV reg,reg patterns
	code, xorReplacements := ReplaceXorPatterns(code, instructions)
	if len(xorReplacements) > 0 {
		fmt.Printf("Replaced 1 XOR/MOV pattern:\n")
		for _, repl := range xorReplacements {
			fmt.Printf("  0x%x: %s -> %s\n", repl.Offset, repl.Original, repl.Replaced)
		}
		transformationCount++
		// Re-disassemble after transformation
		instructions, _ = disassemble(code, 32)
	}

	// ----  MOV r,r  ->  PUSH r / POP r  ---------------------------------
	code, movRegReplacements := ReplaceMovRegReg(code, instructions)
	if len(movRegReplacements) > 0 {
		fmt.Printf("Replaced %d MOV reg,reg pattern(s):\n", len(movRegReplacements))
		for _, repl := range movRegReplacements {
			fmt.Printf("  0x%x: %s -> %s\n", repl.Offset, repl.Original, repl.Replaced)
		}
		transformationCount++
		// Re-disassemble after transformation
		instructions, _ = disassemble(code, 32)
	}

	// Inject random instruction
	if len(instructions) > 1 {
		randomIdx := rand.Intn(len(instructions) - 1)
		selectedInsn := instructions[randomIdx]
		insertOffset := selectedInsn.Offset + uint64(selectedInsn.Size)

		injectBytes, injectName := generateRandomInstruction()
		fmt.Printf("Injecting %s at offset 0x%x\n", injectName, insertOffset)

		// Validate insertOffset is within bounds
		if insertOffset > uint64(len(code)) {
			insertOffset = uint64(len(code))
		}

		// ---------- inject ----------
		newCode := make([]byte, len(code)+len(injectBytes))
		copy(newCode[:insertOffset], code[:insertOffset])
		copy(newCode[insertOffset:], injectBytes)
		copy(newCode[insertOffset+uint64(len(injectBytes)):], code[insertOffset:])

		// ---------- relocate ----------
		relocateCode(newCode,
			uint32(textBaseAddr),     // start of .text in memory
			uint32(insertOffset),     // file offset where we inserted
			uint32(len(injectBytes))) // how many bytes were inserted

		return newCode, nil
	}

	return code, nil
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

// ============================================================================
// MOV reg, imm Transformation (supports 8/16/32-bit registers)
// ============================================================================

type MovImmReplacement struct {
	Offset   uint64
	Original string
	Replaced string
}

func ReplaceMovRegImm(code []byte, instructions []Instruction) ([]byte, []MovImmReplacement) {
	var replacements []MovImmReplacement
	candidateCount := 0

	for i := len(instructions) - 1; i >= 0; i-- {
		insn := instructions[i]

		if insn.Inst.Op != x86asm.MOV {
			continue
		}

		if len(insn.Inst.Args) < 2 {
			continue
		}

		dst, okD := insn.Inst.Args[0].(x86asm.Reg)
		imm, okI := insn.Inst.Args[1].(x86asm.Imm)

		if !okD || !okI {
			continue
		}

		regSize := getRegisterSize(dst)
		if regSize == 0 {
			continue
		}

		candidateCount++

		if isStackPointerReg(dst) {
			continue
		}

		offset := insn.Offset
		value := int64(imm)

		var valueSize int
		var maxVal, minVal int64

		switch regSize {
		case 8:
			valueSize = 8
			maxVal = 127
			minVal = -128
			if value < minVal || value > 255 {
				continue
			}
		case 16:
			valueSize = 16
			maxVal = 32767
			minVal = -32768
			if value < minVal || value > 65535 {
				continue
			}
		case 32:
			if value >= -128 && value <= 127 {
				valueSize = 8
				maxVal = 127
				minVal = -128
			} else if value >= -32768 && value <= 32767 {
				valueSize = 16
				maxVal = 32767
				minVal = -32768
			} else {
				valueSize = 32
				maxVal = 0x7FFFFFFF
				minVal = -0x80000000
			}
		}

		tmp := chooseTempRegSameSize(dst, regSize)
		if tmp == 0 {
			continue
		}

		// Skip transformation if it would corrupt syscall arguments (CL/DL/BL are parts of ECX/EDX/EBX)
		// This is a heuristic: if destination is AL (syscall number) and temp is CL/DL/BL, skip
		// to avoid corrupting syscall arguments. This is conservative but safer.
		if regSize == 8 && dst == x86asm.AL && (tmp == x86asm.CL || tmp == x86asm.DL || tmp == x86asm.BL) {
			continue
		}

		strategy := rand.Intn(3)

		var key, encoded int64
		var newBytes []byte
		var description string

		switch strategy {
		case 0:
			key = generateRandomKey(valueSize, value)
			encoded = value - key
			if encoded < minVal || encoded > maxVal {
				continue
			}
			newBytes = encodeMovImmSequenceAnySize(dst, tmp, key, encoded, regSize, "add")
			description = fmt.Sprintf("MOV %s, 0x%X; MOV %s, 0x%X; ADD %s, %s",
				tmp, key&getMask(valueSize), dst, encoded&getMask(valueSize), dst, tmp)

		case 1:
			key = generateRandomKey(valueSize, value)
			encoded = value + key
			if encoded < minVal || encoded > maxVal {
				continue
			}
			newBytes = encodeMovImmSequenceAnySize(dst, tmp, key, encoded, regSize, "sub")
			description = fmt.Sprintf("MOV %s, 0x%X; MOV %s, 0x%X; SUB %s, %s",
				tmp, key&getMask(valueSize), dst, encoded&getMask(valueSize), dst, tmp)

		case 2:
			key = generateRandomKey(valueSize, value)
			encoded = value ^ key
			newBytes = encodeMovImmSequenceAnySize(dst, tmp, key, encoded, regSize, "xor")
			description = fmt.Sprintf("MOV %s, 0x%X; MOV %s, 0x%X; XOR %s, %s",
				tmp, key&getMask(valueSize), dst, encoded&getMask(valueSize), dst, tmp)
		}

		if len(newBytes) == 0 {
			continue
		}

		oldBytes := code[offset : offset+uint64(insn.Size)]
		code = patchBytes(code, offset, oldBytes, newBytes)

		replacements = append(replacements, MovImmReplacement{
			Offset:   offset,
			Original: fmt.Sprintf("MOV %s, 0x%X", dst, value&getMask(valueSize)),
			Replaced: description,
		})

		return code, replacements
	}

	if candidateCount > 0 {
		fmt.Printf("Found %d MOV reg, imm candidates but none were suitable for transformation\n", candidateCount)
	}

	return code, replacements
}

func getRegisterSize(reg x86asm.Reg) int {
	if reg >= x86asm.AL && reg <= x86asm.BH {
		return 8
	}
	if reg >= x86asm.AX && reg <= x86asm.DI {
		return 16
	}
	if reg >= x86asm.EAX && reg <= x86asm.EDI {
		return 32
	}
	return 0
}

func isStackPointerReg(reg x86asm.Reg) bool {
	return reg == x86asm.ESP || reg == x86asm.EBP ||
		reg == x86asm.SP || reg == x86asm.BP ||
		reg == x86asm.AH || reg == x86asm.BH
}

func chooseTempRegSameSize(dst x86asm.Reg, size int) x86asm.Reg {
	var candidates []x86asm.Reg

	switch size {
	case 8:
		// For 8-bit, CL/DL/BL are parts of ECX/EDX/EBX (syscall args).
		// When transforming MOV AL, imm, prefer DL over CL to avoid corrupting ECX.
		// Note: This still corrupts EDX, but EDX might be less critical in some cases.
		if dst == x86asm.AL {
			// For MOV AL, imm: prefer DL (EDX), then BL (EBX), avoid CL (ECX) if possible
			candidates = []x86asm.Reg{x86asm.DL, x86asm.BL, x86asm.CL}
		} else {
			// Prefer AL first, then others
			candidates = []x86asm.Reg{x86asm.AL, x86asm.DL, x86asm.BL, x86asm.CL}
		}
	case 16:
		// For 16-bit, prefer SI/DI (less commonly used in syscalls)
		candidates = []x86asm.Reg{x86asm.SI, x86asm.DI, x86asm.AX, x86asm.CX, x86asm.DX, x86asm.BX}
	case 32:
		// For 32-bit, prefer ESI/EDI (less commonly used in syscalls)
		candidates = []x86asm.Reg{x86asm.ESI, x86asm.EDI, x86asm.EAX, x86asm.ECX, x86asm.EDX, x86asm.EBX}
	}

	for _, reg := range candidates {
		if reg != dst && !isStackPointerReg(reg) {
			return reg
		}
	}

	return 0
}

func generateRandomKey(valueSize int, originalValue int64) int64 {
	var key int64

	switch valueSize {
	case 8:
		if originalValue >= 0 {
			key = int64(rand.Intn(128))
		} else {
			key = int64(rand.Intn(256) - 128)
		}
	case 16:
		if originalValue >= 0 {
			key = int64(rand.Intn(32768))
		} else {
			key = int64(rand.Intn(65536) - 32768)
		}
	case 32:
		if originalValue >= 0 {
			key = int64(rand.Int31())
		} else {
			// Generate a random key in the full int32 range
			key = int64(rand.Int31()) - int64(rand.Int31()*2)
		}
	}

	return key
}

func getMask(valueSize int) int64 {
	switch valueSize {
	case 8:
		return 0xFF
	case 16:
		return 0xFFFF
	case 32:
		return 0xFFFFFFFF
	default:
		return 0xFFFFFFFF
	}
}

func encodeMovImmSequenceAnySize(dst, tmp x86asm.Reg, key, encoded int64, regSize int, op string) []byte {
	var result []byte

	result = append(result, encodeMovRegImmAnySize(tmp, key, regSize)...)
	result = append(result, encodeMovRegImmAnySize(dst, encoded, regSize)...)

	switch op {
	case "add":
		result = append(result, encodeArithRegReg(dst, tmp, regSize, 0x00)...)
	case "sub":
		result = append(result, encodeArithRegReg(dst, tmp, regSize, 0x28)...)
	case "xor":
		result = append(result, encodeArithRegReg(dst, tmp, regSize, 0x30)...)
	}

	return result
}

func encodeMovRegImmAnySize(reg x86asm.Reg, imm int64, size int) []byte {
	var result []byte

	switch size {
	case 8:
		opcode := byte(0xB0 + getRegBits8(reg))
		result = []byte{opcode, byte(imm & 0xFF)}

	case 16:
		opcode := byte(0xB8 + getRegBits16(reg))
		result = []byte{0x66, opcode}
		immBytes := make([]byte, 2)
		binary.LittleEndian.PutUint16(immBytes, uint16(imm))
		result = append(result, immBytes...)

	case 32:
		opcode := byte(0xB8 + getRegBits(reg))
		result = []byte{opcode}
		immBytes := make([]byte, 4)
		binary.LittleEndian.PutUint32(immBytes, uint32(imm))
		result = append(result, immBytes...)
	}

	return result
}

func encodeArithRegReg(dst, src x86asm.Reg, size int, opcodeBase byte) []byte {
	var result []byte

	switch size {
	case 8:
		modRM := getModRM8(dst, src)
		result = []byte{opcodeBase, modRM}

	case 16:
		modRM := getModRM16(dst, src)
		result = []byte{0x66, opcodeBase + 1, modRM}

	case 32:
		modRM := getModRM(dst, src)
		result = []byte{opcodeBase + 1, modRM}
	}

	return result
}

func getRegBits8(reg x86asm.Reg) byte {
	switch reg {
	case x86asm.AL:
		return 0
	case x86asm.CL:
		return 1
	case x86asm.DL:
		return 2
	case x86asm.BL:
		return 3
	case x86asm.AH:
		return 4
	case x86asm.CH:
		return 5
	case x86asm.DH:
		return 6
	case x86asm.BH:
		return 7
	default:
		return 0
	}
}

func getRegBits16(reg x86asm.Reg) byte {
	switch reg {
	case x86asm.AX:
		return 0
	case x86asm.CX:
		return 1
	case x86asm.DX:
		return 2
	case x86asm.BX:
		return 3
	case x86asm.SP:
		return 4
	case x86asm.BP:
		return 5
	case x86asm.SI:
		return 6
	case x86asm.DI:
		return 7
	default:
		return 0
	}
}

func getModRM8(dst, src x86asm.Reg) byte {
	dstBits := getRegBits8(dst)
	srcBits := getRegBits8(src)
	return 0xC0 | (srcBits << 3) | dstBits
}

func getModRM16(dst, src x86asm.Reg) byte {
	dstBits := getRegBits16(dst)
	srcBits := getRegBits16(src)
	return 0xC0 | (srcBits << 3) | dstBits
}

// ============================================================================
// Shared Helper Functions
// ============================================================================

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

func getRegBits(reg x86asm.Reg) byte {
	switch reg {
	case x86asm.EAX:
		return 0
	case x86asm.ECX:
		return 1
	case x86asm.EDX:
		return 2
	case x86asm.EBX:
		return 3
	case x86asm.ESP:
		return 4
	case x86asm.EBP:
		return 5
	case x86asm.ESI:
		return 6
	case x86asm.EDI:
		return 7
	default:
		return 0
	}
}

func getModRM(dst, src x86asm.Reg) byte {
	dstBits := getRegBits(dst)
	srcBits := getRegBits(src)
	return 0xC0 | (srcBits << 3) | dstBits
}

func is32BitGPR(reg x86asm.Reg) bool {
	return reg == x86asm.EAX || reg == x86asm.ECX || reg == x86asm.EDX ||
		reg == x86asm.EBX || reg == x86asm.ESI || reg == x86asm.EDI ||
		reg == x86asm.ESP || reg == x86asm.EBP
}

// isAddrImm returns true if the immediate operand is a 32-bit address
// (we treat any imm32 that lies inside the current code segment as an address)
func isAddrImm(imm x86asm.Imm, codeBase, codeSize uint32) bool {
	addr := uint32(imm)
	return addr >= codeBase && addr < codeBase+codeSize
}

// patchImm32 replaces a 32-bit immediate inside the instruction encoding
func patchImm32(data []byte, off uint32, delta int32) {
	v := int32(binary.LittleEndian.Uint32(data[off : off+4]))
	binary.LittleEndian.PutUint32(data[off:], uint32(v+delta))
}

// relocateCode patches every absolute 32-bit immediate that points *after* the
// insertion site.  It handles:
//   - MOV  reg, imm32
//   - PUSH imm32
//   - CALL/JMP rel32   (already done by your old fixRelativeOffsets)
//   - LEA  reg, [disp32]
func relocateCode(data []byte, codeBase, insertOff, delta uint32) {
	instOff := uint32(0)
	for instOff < uint32(len(data)) {
		inst, err := x86asm.Decode(data[instOff:], 32)
		if err != nil {
			instOff++
			continue
		}
		next := instOff + uint32(inst.Len)

		switch inst.Op {
		case x86asm.MOV, x86asm.PUSH, x86asm.LEA:
			for _, a := range inst.Args {
				if imm, ok := a.(x86asm.Imm); ok && isAddrImm(imm, codeBase, uint32(len(data))) {
					addr := uint32(imm)
					if addr >= codeBase+insertOff { // only fix refs after insert
						immOff := immOffsetInEncoding(data, instOff)
						patchImm32(data, instOff+immOff, int32(delta))
					}
				}
			}
		}
		// let the old routine fix relative branches
		if isRelativeJumpOrCallX86(inst.Op) {
			tgt := getRelativeTargetX86(inst, uint64(instOff))
			if tgt != 0 && uint32(tgt) >= codeBase+insertOff {
				adjustRelativeJumpX86(data, uint64(instOff), inst.Len, int32(delta))
			}
		}
		instOff = next
	}
}

// immOffsetInEncoding returns the offset of the 32-bit immediate inside
// the instruction bytes.  We only need the common encodings we produce.
func immOffsetInEncoding(code []byte, instOff uint32) uint32 {
	b := code[instOff:]
	if len(b) == 0 {
		return 0
	}

	// Skip prefixes
	i := 0
	for i < len(b) && isPrefixByte(b[i]) {
		i++
	}
	if i >= len(b) {
		return uint32(i)
	}

	// Handle specific opcodes that have immediates without ModRM
	// MOV reg, imm32 (opcode 0xB8+reg): immediate follows opcode directly
	opcode := b[i]
	if opcode >= 0xB8 && opcode <= 0xBF {
		return uint32(i + 1)
	}

	// PUSH imm32 (opcode 0x68): immediate follows opcode directly
	if opcode == 0x68 {
		return uint32(i + 1)
	}

	// Skip opcode
	if opcode == 0x0F {
		i += 2
	} else {
		i++
	}

	// For other instructions with ModRM, we need to skip ModRM/SIB/displacement
	// This is a simplified approach - for shellcode, we typically don't need this
	// since shellcode doesn't use absolute addresses that need relocation
	return uint32(i)
}

func isPrefixByte(x byte) bool {
	return x == 0x66 || x == 0x67 || x == 0xF0 || x == 0xF2 || x == 0xF3 ||
		(x >= 0x26 && x <= 0x2E) || (x >= 0x36 && x <= 0x3E) || x == 0x64 || x == 0x65
}

func ReplaceMovRegReg(code []byte, instructions []Instruction) ([]byte, []MovRegRegReplacement) {
	var replacements []MovRegRegReplacement
	for _, insn := range instructions {
		// 1. must be MOV
		if insn.Inst.Op != x86asm.MOV {
			continue
		}
		// 2. exactly two register operands
		if len(insn.Inst.Args) != 2 {
			continue
		}
		dst, okD := insn.Inst.Args[0].(x86asm.Reg)
		src, okS := insn.Inst.Args[1].(x86asm.Reg)
		if !okD || !okS {
			continue
		}
		// 3. same size (16 or 32 bit)
		dSz := getRegisterSize(dst)
		sSz := getRegisterSize(src)
		if dSz != sSz || (dSz != 16 && dSz != 32) {
			continue
		}
		// 4. dest must not be stack pointer (we would lose the value)
		if isStackPointerReg(dst) {
			continue
		}
		// 5. src may be stack pointer, but then we must not use it again
		//    (still safe for PUSH/POP because the value is on the stack)
		//
		// 6. build the new byte sequence
		var newBytes []byte
		switch dSz {
		case 16:
			newBytes = []byte{
				0x66, 0x50 + getRegBits16(src), // PUSH src16
				0x66, 0x58 + getRegBits16(dst), // POP  dst16
			}
		case 32:
			newBytes = []byte{
				0x50 + getRegBits(src), // PUSH src32
				0x58 + getRegBits(dst), // POP  dst32
			}
		}

		// 7. patch the instruction stream
		oldBytes := code[insn.Offset : insn.Offset+uint64(insn.Size)]
		code = patchBytes(code, insn.Offset, oldBytes, newBytes)

		replacements = append(replacements, MovRegRegReplacement{
			Offset:   insn.Offset,
			Original: fmt.Sprintf("MOV %s, %s", dst, src),
			Replaced: fmt.Sprintf("PUSH %s; POP %s", src, dst),
		})
	}
	return code, replacements
}
