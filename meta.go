package main

import (
	"encoding/binary"
	"fmt"
	"os"

	transformation "Metamorph/transformations"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Printf("Usage: %s <input_elf> <output_elf>\n", os.Args[0])
		fmt.Printf("\nApplies metamorphic transformations to x86/x64 ELF binary.\n")
		os.Exit(1)
	}

	inputFile := os.Args[1]
	outputFile := os.Args[2]

	if err := processELF(inputFile, outputFile); err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("\nSuccess: %s\n", outputFile)
}

func processELF(inputPath, outputPath string) error {
	// Read entire file
	raw, err := os.ReadFile(inputPath)
	if err != nil {
		return fmt.Errorf("read file: %w", err)
	}

	if len(raw) < 64 || raw[0] != 0x7f || raw[1] != 'E' || raw[2] != 'L' || raw[3] != 'F' {
		return fmt.Errorf("not an ELF file")
	}

	is64Bit := raw[4] == 2
	is32Bit := raw[4] == 1

	if !is32Bit && !is64Bit {
		return fmt.Errorf("unsupported ELF class")
	}

	archStr := "32-bit"
	if is64Bit {
		archStr = "64-bit"
	}
	fmt.Printf("Original file: %d bytes (%s)\n", len(raw), archStr)

	if is64Bit {
		return processELF64(raw, outputPath)
	}
	return processELF32(raw, outputPath)
}

// ============================================================================
// 32-bit ELF Processing
// ============================================================================

func processELF32(raw []byte, outputPath string) error {
	secs, err := cloneSections32(raw)
	if err != nil {
		return err
	}

	textIdx := -1
	for i, s := range secs {
		if getSecName32(raw, s.name) == ".text" {
			textIdx = i
			break
		}
	}

	// Process with x86 transformations
	originalSize := len(secs[textIdx].data)
	modifiedText, err := transformation.ProcessX86Code(
		secs[textIdx].data,
		secs[textIdx].addr,
	)
	if err != nil {
		return err
	}

	secs[textIdx].data = modifiedText
	secs[textIdx].size = uint32(len(modifiedText))

	sizeDiff := len(modifiedText) - originalSize
	fmt.Printf("\n.text size change: %d -> %d bytes (%+d)\n", originalSize, len(modifiedText), sizeDiff)

	// Rebuild ELF
	newElf, err := rebuildELF32(raw, secs, textIdx, sizeDiff)
	if err != nil {
		return err
	}

	if err := os.WriteFile(outputPath, newElf, 0755); err != nil {
		return fmt.Errorf("write: %w", err)
	}

	fmt.Printf("\nOutput file: %d bytes\n", len(newElf))
	return nil
}

type secCp32 struct {
	name, typ, flags, addr, off, size, link, info, align, entsz uint32
	data                                                        []byte
}

func cloneSections32(raw []byte) ([]secCp32, error) {
	bo := binary.LittleEndian
	shoff := bo.Uint32(raw[32:])
	shnum := bo.Uint16(raw[48:50])

	var out []secCp32
	for i := 0; i < int(shnum); i++ {
		sh := int(shoff) + i*40
		if sh+40 > len(raw) {
			break
		}
		name := bo.Uint32(raw[sh:])
		typ := bo.Uint32(raw[sh+4:])
		flags := bo.Uint32(raw[sh+8:])
		addr := bo.Uint32(raw[sh+12:])
		off := bo.Uint32(raw[sh+16:])
		size := bo.Uint32(raw[sh+20:])
		link := bo.Uint32(raw[sh+24:])
		info := bo.Uint32(raw[sh+28:])
		align := bo.Uint32(raw[sh+32:])
		entsz := bo.Uint32(raw[sh+36:])

		data := make([]byte, size)
		if off != 0 && size != 0 && int(off)+int(size) <= len(raw) {
			copy(data, raw[off:off+size])
		}
		out = append(out, secCp32{name, typ, flags, addr, off, size, link, info, align, entsz, data})
	}
	return out, nil
}

func getSecName32(raw []byte, nameOff uint32) string {
	bo := binary.LittleEndian
	shoff := bo.Uint32(raw[32:])
	shstrndx := bo.Uint16(raw[50:52])
	shstrSh := int(shoff) + int(shstrndx)*40
	if shstrSh+20 > len(raw) {
		return ""
	}
	shstrOff := bo.Uint32(raw[shstrSh+16:])

	start := int(shstrOff) + int(nameOff)
	if start >= len(raw) {
		return ""
	}
	end := start
	for end < len(raw) && raw[end] != 0 {
		end++
	}
	return string(raw[start:end])
}

func rebuildELF32(original []byte, secs []secCp32, textIdx, sizeDiff int) ([]byte, error) {
	bo := binary.LittleEndian

	origShoff := bo.Uint32(original[32:])
	origPhoff := bo.Uint32(original[28:])
	phnum := bo.Uint16(original[44:])
	phentsize := bo.Uint16(original[42:])

	insertFileOff := secs[textIdx].off
	endOfPatch := insertFileOff + uint32(len(secs[textIdx].data))
	sizeDiffU32 := uint32(sizeDiff)

	// Slide sections that live after the patch
	for i := range secs {
		if i != textIdx && secs[i].off > secs[textIdx].off {
			secs[i].off += sizeDiffU32
			secs[i].addr += sizeDiffU32
		}
	}

	// New section-header table position
	newShoff := origShoff
	if origShoff >= endOfPatch {
		newShoff += sizeDiffU32
	}

	// Compute total file size
	var maxEnd uint32
	for _, s := range secs {
		if e := s.off + s.size; e > maxEnd {
			maxEnd = e
		}
	}
	shSize := uint32(40 * len(secs))
	if newShoff+shSize > maxEnd {
		maxEnd = newShoff + shSize
	}

	buf := make([]byte, maxEnd)

	// Copy everything up to program headers
	copy(buf[:origPhoff], original[:origPhoff])

	// Copy & fix program headers
	phTotal := uint32(phnum) * uint32(phentsize)
	copy(buf[origPhoff:origPhoff+phTotal], original[origPhoff:origPhoff+phTotal])

	for i := 0; i < int(phnum); i++ {
		base := int(origPhoff) + i*int(phentsize)
		if base+20 > len(buf) {
			continue
		}
		pType := bo.Uint32(buf[base:])
		if pType != 1 { // PT_LOAD only
			continue
		}

		pOffset := bo.Uint32(buf[base+4:])
		pFilesz := bo.Uint32(buf[base+16:])
		pMemsz := bo.Uint32(buf[base+20:])
		segEnd := pOffset + pFilesz

		vaddr := bo.Uint32(buf[base+8:])

		switch {
		case pOffset <= insertFileOff && segEnd > insertFileOff:
			bo.PutUint32(buf[base+16:], pFilesz+sizeDiffU32)
			bo.PutUint32(buf[base+20:], pMemsz+sizeDiffU32)
		case vaddr >= secs[textIdx].addr+secs[textIdx].size:
			bo.PutUint32(buf[base+4:], pOffset+sizeDiffU32)
		case pOffset >= endOfPatch:
			bo.PutUint32(buf[base+4:], pOffset+sizeDiffU32)
		}
	}

	// Copy up to .text
	copy(buf[:secs[textIdx].off], original[:secs[textIdx].off])

	// Write new .text
	copy(buf[secs[textIdx].off:], secs[textIdx].data)

	// Copy gap between old end-of-text and old shoff
	origGapStart := insertFileOff + uint32(len(secs[textIdx].data)) - sizeDiffU32
	origGapEnd := origShoff
	if origGapEnd > origGapStart {
		copyLen := int(origGapEnd) - int(origGapStart)
		newGapStart := insertFileOff + uint32(len(secs[textIdx].data))
		if int(origGapStart)+copyLen <= len(original) && int(newGapStart)+copyLen <= len(buf) {
			copy(buf[newGapStart:], original[origGapStart:origGapStart+uint32(copyLen)])
		}
	}

	// Write remaining sections
	for i, s := range secs {
		if i != textIdx && s.off != 0 && s.size != 0 {
			if int(s.off)+len(s.data) <= len(buf) {
				copy(buf[s.off:], s.data)
			}
		}
	}

	// Write section headers
	for i, s := range secs {
		sh := int(newShoff) + i*40
		if sh+40 > len(buf) {
			return nil, fmt.Errorf("section header %d out of bounds", i)
		}
		bo.PutUint32(buf[sh:], s.name)
		bo.PutUint32(buf[sh+4:], s.typ)
		bo.PutUint32(buf[sh+8:], s.flags)
		bo.PutUint32(buf[sh+12:], s.addr)
		bo.PutUint32(buf[sh+16:], s.off)
		bo.PutUint32(buf[sh+20:], s.size)
		bo.PutUint32(buf[sh+24:], s.link)
		bo.PutUint32(buf[sh+28:], s.info)
		bo.PutUint32(buf[sh+32:], s.align)
		bo.PutUint32(buf[sh+36:], s.entsz)
	}

	// Update ELF header
	bo.PutUint32(buf[32:], newShoff)
	bo.PutUint16(buf[48:], uint16(len(secs)))

	return buf, nil
}

// ============================================================================
// 64-bit ELF Processing
// ============================================================================

func processELF64(raw []byte, outputPath string) error {
	secs, err := cloneSections64(raw)
	if err != nil {
		return err
	}

	textIdx := -1
	for i, s := range secs {
		if getSecName64(raw, s.name) == ".text" {
			textIdx = i
			break
		}
	}

	// Process with x64 transformations
	originalSize := len(secs[textIdx].data)
	modifiedText, err := transformation.ProcessX64Code(secs[textIdx].data)
	if err != nil {
		return err
	}

	secs[textIdx].data = modifiedText
	secs[textIdx].size = uint64(len(modifiedText))

	sizeDiff := len(modifiedText) - originalSize
	fmt.Printf("\n.text size change: %d -> %d bytes (%+d)\n", originalSize, len(modifiedText), sizeDiff)

	// Rebuild ELF
	newElf, err := rebuildELF64(raw, secs, textIdx, sizeDiff)
	if err != nil {
		return err
	}

	if err := os.WriteFile(outputPath, newElf, 0755); err != nil {
		return fmt.Errorf("write: %w", err)
	}

	fmt.Printf("\nOutput file: %d bytes\n", len(newElf))
	return nil
}

type secCp64 struct {
	name, typ       uint32
	flags           uint64
	addr, off, size uint64
	link, info      uint32
	align, entsz    uint64
	data            []byte
}

func cloneSections64(raw []byte) ([]secCp64, error) {
	bo := binary.LittleEndian
	shoff := bo.Uint64(raw[40:48])
	shnum := bo.Uint16(raw[60:62])

	var out []secCp64
	for i := 0; i < int(shnum); i++ {
		sh := int(shoff) + i*64
		if sh+64 > len(raw) {
			break
		}
		name := bo.Uint32(raw[sh:])
		typ := bo.Uint32(raw[sh+4:])
		flags := bo.Uint64(raw[sh+8:])
		addr := bo.Uint64(raw[sh+16:])
		off := bo.Uint64(raw[sh+24:])
		size := bo.Uint64(raw[sh+32:])
		link := bo.Uint32(raw[sh+40:])
		info := bo.Uint32(raw[sh+44:])
		align := bo.Uint64(raw[sh+48:])
		entsz := bo.Uint64(raw[sh+56:])

		data := make([]byte, size)
		if off != 0 && size != 0 && int(off)+int(size) <= len(raw) {
			copy(data, raw[off:off+size])
		}
		out = append(out, secCp64{name, typ, flags, addr, off, size, link, info, align, entsz, data})
	}
	return out, nil
}

func getSecName64(raw []byte, nameOff uint32) string {
	bo := binary.LittleEndian
	shoff := bo.Uint64(raw[40:48])
	shstrndx := bo.Uint16(raw[62:64])
	shstrSh := int(shoff) + int(shstrndx)*64
	if shstrSh+32 > len(raw) {
		return ""
	}
	shstrOff := bo.Uint64(raw[shstrSh+24:])

	start := int(shstrOff) + int(nameOff)
	if start >= len(raw) {
		return ""
	}
	end := start
	for end < len(raw) && raw[end] != 0 {
		end++
	}
	return string(raw[start:end])
}

func rebuildELF64(original []byte, secs []secCp64, textIdx, sizeDiff int) ([]byte, error) {
	bo := binary.LittleEndian

	origShoff := bo.Uint64(original[40:48])
	origPhoff := bo.Uint64(original[32:40])
	phnum := bo.Uint16(original[56:58])
	phentsize := bo.Uint16(original[54:56])

	insertFileOff := secs[textIdx].off
	endOfPatch := insertFileOff + uint64(len(secs[textIdx].data))
	sizeDiffU64 := uint64(sizeDiff)

	// Slide sections that live after the patch
	for i := range secs {
		if i != textIdx && secs[i].off > secs[textIdx].off {
			secs[i].off += sizeDiffU64
			secs[i].addr += sizeDiffU64
		}
	}

	// New section-header table position
	newShoff := origShoff
	if origShoff >= endOfPatch {
		newShoff += sizeDiffU64
	}

	// Compute total file size
	var maxEnd uint64
	for _, s := range secs {
		if e := s.off + s.size; e > maxEnd {
			maxEnd = e
		}
	}
	shSize := uint64(64 * len(secs))
	if newShoff+shSize > maxEnd {
		maxEnd = newShoff + shSize
	}

	buf := make([]byte, maxEnd)

	// Copy everything up to program headers
	copy(buf[:origPhoff], original[:origPhoff])

	// Copy & fix program headers
	phTotal := uint64(phnum) * uint64(phentsize)
	copy(buf[origPhoff:origPhoff+phTotal], original[origPhoff:origPhoff+phTotal])

	for i := 0; i < int(phnum); i++ {
		base := int(origPhoff) + i*int(phentsize)
		if base+56 > len(buf) {
			continue
		}
		pType := bo.Uint32(buf[base:])
		if pType != 1 { // PT_LOAD only
			continue
		}

		pOffset := bo.Uint64(buf[base+8:])
		pFilesz := bo.Uint64(buf[base+32:])
		pMemsz := bo.Uint64(buf[base+40:])
		segEnd := pOffset + pFilesz

		vaddr := bo.Uint64(buf[base+16:])

		switch {
		case pOffset <= insertFileOff && segEnd > insertFileOff:
			bo.PutUint64(buf[base+32:], pFilesz+sizeDiffU64)
			bo.PutUint64(buf[base+40:], pMemsz+sizeDiffU64)
		case vaddr >= secs[textIdx].addr+secs[textIdx].size:
			bo.PutUint64(buf[base+8:], pOffset+sizeDiffU64)
		case pOffset >= endOfPatch:
			bo.PutUint64(buf[base+8:], pOffset+sizeDiffU64)
		}
	}

	// Copy up to .text
	copy(buf[:secs[textIdx].off], original[:secs[textIdx].off])

	// Write new .text
	copy(buf[secs[textIdx].off:], secs[textIdx].data)

	// Copy gap between old end-of-text and old shoff
	origGapStart := insertFileOff + uint64(len(secs[textIdx].data)) - sizeDiffU64
	origGapEnd := origShoff
	if origGapEnd > origGapStart {
		copyLen := int(origGapEnd) - int(origGapStart)
		newGapStart := insertFileOff + uint64(len(secs[textIdx].data))
		if int(origGapStart)+copyLen <= len(original) && int(newGapStart)+copyLen <= len(buf) {
			copy(buf[newGapStart:], original[origGapStart:origGapStart+uint64(copyLen)])
		}
	}

	// Write remaining sections
	for i, s := range secs {
		if i != textIdx && s.off != 0 && s.size != 0 {
			if int(s.off)+len(s.data) <= len(buf) {
				copy(buf[s.off:], s.data)
			}
		}
	}

	// Write section headers
	for i, s := range secs {
		sh := int(newShoff) + i*64
		if sh+64 > len(buf) {
			return nil, fmt.Errorf("section header %d out of bounds", i)
		}
		bo.PutUint32(buf[sh:], s.name)
		bo.PutUint32(buf[sh+4:], s.typ)
		bo.PutUint64(buf[sh+8:], s.flags)
		bo.PutUint64(buf[sh+16:], s.addr)
		bo.PutUint64(buf[sh+24:], s.off)
		bo.PutUint64(buf[sh+32:], s.size)
		bo.PutUint32(buf[sh+40:], s.link)
		bo.PutUint32(buf[sh+44:], s.info)
		bo.PutUint64(buf[sh+48:], s.align)
		bo.PutUint64(buf[sh+56:], s.entsz)
	}

	// Update ELF header
	bo.PutUint64(buf[40:], newShoff)
	bo.PutUint16(buf[60:], uint16(len(secs)))

	return buf, nil
}
