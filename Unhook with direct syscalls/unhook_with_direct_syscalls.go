package direct

import (
	"debug/pe"
	"os"
	"path/filepath"
	"syscall"
	"unsafe"

	banana "github.com/C-Sto/BananaPhone/pkg/BananaPhone" // amazing repo for make direct syscalls in Go, but seems broken in some Windows 11 versions
	"golang.org/x/sys/windows"
)

var systemPath string

func getSystemPath() string {
	path := os.Getenv("SystemRoot")
	if path == "" {
		return ""
	}

	path = filepath.Join(path, "System32")
	return path + "\\"
}

func getDirectSyscalls() (uint16, uint16) {
	bp, err := banana.NewBananaPhone(banana.AutoBananaPhoneMode)
	if err != nil {
		panic(err)
	}

	zwWriteVirtualMemory, err := bp.GetSysID("ZwWriteVirtualMemory")
	if err != nil {
		panic(err)
	}

	ntProtectVirtualMemory, err := bp.GetSysID("NtProtectVirtualMemory")
	if err != nil {
		panic(err)
	}

	return zwWriteVirtualMemory, ntProtectVirtualMemory
}

func getFreshDll(dll string) error {
	bytes, err := os.ReadFile(dll)
	if err != nil {
		return err
	}

	file, err := pe.Open(dll)
	if err != nil {
		return err
	}

	textSection := file.Section(".text")
	interestingBytes := bytes[textSection.Offset:textSection.Size]
	return writeFreshData(interestingBytes, dll, textSection.VirtualAddress)
}

func writeFreshData(bytes []byte, dllName string, virtualOffset uint32) error {
	zwWriteVirtualMemory, ntProtectVirtualMemory := getDirectSyscalls()

	dll, err := syscall.LoadDLL(dllName)
	if err != nil {
		return err
	}
	defer dll.Release()

	dllHandle := dll.Handle
	dllBase := uintptr(dllHandle)
	dllOffset := uint(dllBase) + uint(virtualOffset)

	var old uint32
	sizet := len(bytes)
	var thisThread = uintptr(0xffffffffffffffff)

	_, r := banana.Syscall(
		ntProtectVirtualMemory,
		uintptr(thisThread),
		uintptr(unsafe.Pointer(&dllOffset)),
		uintptr(unsafe.Pointer(&sizet)),
		windows.PAGE_EXECUTE_READWRITE,
		uintptr(unsafe.Pointer(&old)),
	)
	if r != nil {
		return r
	}

	_, r = banana.Syscall(
		zwWriteVirtualMemory,
		uintptr(thisThread),
		uintptr(dllOffset),
		uintptr(unsafe.Pointer(&bytes[0])),
		uintptr(len(bytes)),
		0,
	)

	if r != nil {
		return r
	}

	return nil
}

func UnhookDllDirectSyscalls() {
	dll_list := []string{"kernel32.dll", "kernelbase.dll", "ntdll.dll", "user32.dll", "apphelp.dll", "msvcrt.dll"}
	systemPath = getSystemPath()

	for _, dll := range dll_list {
		getFreshDll(systemPath + dll)
	}
}
