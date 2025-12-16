package main

import (
	"encoding/binary"
	"fmt"
	"os"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Printf("Usage: %s <input_elf> <output_elf>\n", os.Args[0])
		fmt.Printf("\nApplies metamorphic transformations to x86 32-bit ELF binary.\n")
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

	if len(raw) < 52 || raw[0] != 0x7f || raw[1] != 'E' || raw[2] != 'L' || raw[3] != 'F' {
		return fmt.Errorf("not an ELF file")
	}

	if raw[4] != 1 {
		return fmt.Errorf("not a 32-bit ELF")
	}

	fmt.Printf("Original file: %d bytes\n", len(raw))

	// Clone all sections
	secs, err := cloneSections(raw)
	if err != nil {
		return err
	}

	fmt.Printf("Found %d sections\n", len(secs))

	// Find and process .text section
	textIdx := -1
	for i, s := range secs {
		name := getSecName(raw, s.name)
		if name == ".text" {
			textIdx = i
			fmt.Printf(".text section: offset=0x%x, size=%d bytes\n", s.off, s.size)
		} else if s.size > 0 {
			fmt.Printf("%s section: offset=0x%x, size=%d bytes\n", name, s.off, s.size)
		}
	}

	if textIdx < 0 {
		return fmt.Errorf(".text section not found")
	}

	// Process with x86 transformations
	originalSize := len(secs[textIdx].data)
	modifiedText, err := ProcessX86Code(secs[textIdx].data)
	if err != nil {
		return err
	}

	secs[textIdx].data = modifiedText
	secs[textIdx].size = uint32(len(modifiedText))
	
	sizeDiff := len(modifiedText) - originalSize
	fmt.Printf("\n.text size change: %d -> %d bytes (%+d)\n", originalSize, len(modifiedText), sizeDiff)

	// Rebuild ELF with adjusted offsets
	newElf, err := rebuildELF32(raw, secs, textIdx, sizeDiff)
	if err != nil {
		return err
	}

	// Write output
	if err := os.WriteFile(outputPath, newElf, 0755); err != nil {
		return fmt.Errorf("write: %w", err)
	}

	fmt.Printf("\nOutput file: %d bytes\n", len(newElf))
	return nil
}

type secCp struct {
	name, typ, flags, addr, off, size, link, info, align, entsz uint32
	data                                                          []byte
}

func cloneSections(raw []byte) ([]secCp, error) {
	bo := binary.LittleEndian
	shoff := bo.Uint32(raw[32:])
	shnum := bo.Uint16(raw[48:50])

	var out []secCp
	for i := 0; i < int(shnum); i++ {
		sh := int(shoff) + i*40
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
		out = append(out, secCp{name, typ, flags, addr, off, size, link, info, align, entsz, data})
	}
	return out, nil
}

func getSecName(raw []byte, nameOff uint32) string {
	bo := binary.LittleEndian
	shoff := bo.Uint32(raw[32:])
	shstrndx := bo.Uint16(raw[50:52])
	shstrSh := int(shoff) + int(shstrndx)*40
	shstrOff := bo.Uint32(raw[shstrSh+16:])

	start := int(shstrOff) + int(nameOff)
	end := start
	for end < len(raw) && raw[end] != 0 {
		end++
	}
	return string(raw[start:end])
}

func rebuildELF32(original []byte, secs []secCp, textIdx, sizeDiff int) ([]byte, error) {
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
			bo.PutUint32(buf[base+16:], pFilesz+sizeDiffU32)
			bo.PutUint32(buf[base+20:], pMemsz+sizeDiffU32)
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
		copy(buf[newGapStart:], original[origGapStart:origGapStart+uint32(copyLen)])
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