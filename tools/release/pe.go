package main

// PE subsystem gate for the Windows GUI helper.
//
// The helper is released as a windowed-subsystem binary
// (-H=windowsgui): it must never pop a console window when the scheduler
// or a user session starts it. A plain `go build` of the same source
// produces a console-subsystem (CUI) executable that would flash a window
// on every start, so the assembler refuses to pack anything but a
// WINDOWS_GUI image as the helper, failing closed at assembly time
// instead of shipping a console build to users.

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
)

// PE subsystem values (IMAGE_OPTIONAL_HEADER.Subsystem).
const (
	peSubsystemWindowsGUI = 2 // IMAGE_SUBSYSTEM_WINDOWS_GUI
	peSubsystemWindowsCUI = 3 // IMAGE_SUBSYSTEM_WINDOWS_CUI
)

// verifyWindowsGUISubsystem checks that path is a PE image whose optional
// header declares the Windows GUI subsystem (2). It parses only the fixed
// headers (DOS e_lfanew, PE signature, COFF, optional-header magic and
// Subsystem field) and fails closed on anything malformed, truncated, or
// non-PE.
func verifyWindowsGUISubsystem(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	size := info.Size()

	// DOS header: "MZ" and the PE offset at 0x3c.
	var dos [64]byte
	if err := readFull(f, 0, dos[:]); err != nil {
		return fmt.Errorf("read DOS header: %w", err)
	}
	if dos[0] != 'M' || dos[1] != 'Z' {
		return fmt.Errorf("not a PE image (missing MZ DOS header)")
	}
	peOff := int64(binary.LittleEndian.Uint32(dos[60:64]))
	if peOff < 64 || peOff+24+70 > size {
		return fmt.Errorf("PE header offset %d out of bounds for a %d byte file", peOff, size)
	}

	// PE signature "PE\0\0".
	var sig [4]byte
	if err := readFull(f, peOff, sig[:]); err != nil {
		return fmt.Errorf("read PE signature: %w", err)
	}
	if sig[0] != 'P' || sig[1] != 'E' || sig[2] != 0 || sig[3] != 0 {
		return fmt.Errorf("not a PE image (missing PE signature)")
	}

	// COFF header: SizeOfOptionalHeader is at offset 16 of the 20-byte
	// header that follows the signature.
	var coff [20]byte
	if err := readFull(f, peOff+4, coff[:]); err != nil {
		return fmt.Errorf("read COFF header: %w", err)
	}
	optSize := int64(binary.LittleEndian.Uint16(coff[16:18]))
	optOff := peOff + 24
	if optSize < 70 || optOff+optSize > size {
		return fmt.Errorf("optional header size %d out of bounds for a %d byte file", optSize, size)
	}

	// Optional header: magic (PE32 0x10b / PE32+ 0x20b), Subsystem is the
	// uint16 at offset 68 of the optional header.
	var opt [70]byte
	if err := readFull(f, optOff, opt[:]); err != nil {
		return fmt.Errorf("read optional header: %w", err)
	}
	magic := binary.LittleEndian.Uint16(opt[0:2])
	if magic != 0x10b && magic != 0x20b {
		return fmt.Errorf("unknown PE optional header magic %#x", magic)
	}
	subsystem := binary.LittleEndian.Uint16(opt[68:70])
	if subsystem != peSubsystemWindowsGUI {
		return fmt.Errorf("PE subsystem is %d (%s), want %d (IMAGE_SUBSYSTEM_WINDOWS_GUI); the helper must be built with -H=windowsgui, not a plain go build", subsystem, subsystemName(subsystem), peSubsystemWindowsGUI)
	}
	return nil
}

func subsystemName(sub uint16) string {
	if sub == peSubsystemWindowsCUI {
		return "console"
	}
	return "unknown"
}

func readFull(f *os.File, off int64, buf []byte) error {
	if _, err := f.Seek(off, io.SeekStart); err != nil {
		return err
	}
	if _, err := io.ReadFull(f, buf); err != nil {
		return err
	}
	return nil
}
