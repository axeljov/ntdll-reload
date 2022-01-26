package main

import (
	"fmt"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

func main() {

	var in string

	// load DLLs
	var kern32Handle, _ = windows.LoadLibrary("kernel32.dll")
	var psapiHandle, _ = windows.LoadLibrary("psapi.dll")

	// get win API addresses
	getModuleHandle, _ := windows.GetProcAddress(kern32Handle, "GetModuleHandleA")
	getCurrentProcessHandle, _ := windows.GetProcAddress(kern32Handle, "GetCurrentProcess")
	getModuleInfoHandle, _ := windows.GetProcAddress(psapiHandle, "GetModuleInformation")
	createFileAHandle, _ := windows.GetProcAddress(kern32Handle, "CreateFileA")
	createFileMappingHandle, _ := windows.GetProcAddress(kern32Handle, "CreateFileMappingA")
	mapViewOfFileHandle, _ := windows.GetProcAddress(kern32Handle, "MapViewOfFile")
	virtualProtectHandle, _ := windows.GetProcAddress(kern32Handle, "VirtualProtect")
	rtlCopyMemoryHandle, _ := windows.GetProcAddress(kern32Handle, "RtlCopyMemory")

	// get ntdll module address
	ntdllName := StringToCharPtr("C:\\windows\\system32\\ntdll.dll")
	ntdllModuleHandle, _, err := syscall.Syscall(getModuleHandle,
		1,
		uintptr(unsafe.Pointer(ntdllName)),
		0, 0)

	// get current process
	processHandle, _, err := syscall.Syscall(getCurrentProcessHandle,
		0,
		0, 0, 0)

	// get module info
	var modInfo windows.ModuleInfo
	_, _, err = syscall.Syscall6(getModuleInfoHandle,
		4,
		processHandle,
		ntdllModuleHandle,
		uintptr(unsafe.Pointer(&modInfo)),
		unsafe.Sizeof(modInfo),
		0, 0)
	fmt.Printf("%+v\n", modInfo)

	// get ntdll file handle
	fileName := StringToCharPtr("C:\\windows\\system32\\ntdll.dll")
	ntdllHandle, _, err := syscall.Syscall9(createFileAHandle,
		7,
		uintptr(unsafe.Pointer(fileName)), // filename
		windows.GENERIC_READ,              // open for read
		windows.FILE_SHARE_READ,           // share
		0,                                 // default sec desc
		windows.OPEN_EXISTING,             // open existing file
		0, 0, 0, 0)                        // no attributes. no template

	fmt.Printf("return val CreateFileA: %x\n", ntdllHandle)
	if syscall.Handle(ntdllHandle) == syscall.InvalidHandle {
		fmt.Println(err)
		return
	}

	// create file mapping object
	fileMapObj, _, err := syscall.Syscall6(createFileMappingHandle,
		6,
		ntdllHandle,
		0,
		windows.PAGE_READONLY|0x01000000, // PAGE_READONLY | SEC_IMAGE
		0, 0, 0)

	fmt.Printf("return val createFileMapping: %x\n", fileMapObj)
	if syscall.Handle(fileMapObj) == 0 {
		fmt.Println(err)
		return
	}

	// map the view of the file
	ntdllMapping, _, err := syscall.Syscall6(mapViewOfFileHandle,
		5,
		fileMapObj,
		windows.FILE_MAP_READ,
		0, 0, 0, 0)
	fmt.Printf("return val MapViewOfFile: %x\n", ntdllMapping)
	if syscall.Handle(ntdllMapping) == 0 {
		fmt.Println(err)
		return
	}

	dosHeaderELfanewOffset := uintptr(0x3c)      // e_lfanew offset
	ntHeaderNumOfSectionsOffset := uintptr(0x06) // NumberOfSections offset
	dosHeaderAddr := modInfo.BaseOfDll
	ntHeaderAddr := uintptr(modInfo.BaseOfDll + uintptr(*((*uint32)(unsafe.Pointer(dosHeaderAddr + dosHeaderELfanewOffset)))))
	//binary.LittleEndian.Uint32(([]byte)(unsafe.Pointer(dosHeaderAddr + dosHeaderELfanewOffset)))

	//test := dosHeaderAddr + dosHeaderELfanewOffset

	fmt.Printf("hookedDosHeaderAddr: %x\n", dosHeaderAddr)
	fmt.Printf("hookedNtHeaderAddr:  %x\n", ntHeaderAddr)

	sizeSectionHeader := uintptr(40)
	numOfSections := *(*uint16)(unsafe.Pointer(ntHeaderAddr + ntHeaderNumOfSectionsOffset))
	sizeOfOptionalheader := uintptr(*(*uint16)(unsafe.Pointer(ntHeaderAddr + 0x4 + 0x10))) // nt header + magic number + offset to SizeOfOptionalHeader
	sectionHeadersAddr := ntHeaderAddr + 0x04 + 0x14 + sizeOfOptionalheader

	fmt.Printf("sizeOfOptionalheader: %x\n", sizeOfOptionalheader)

	for i := uintptr(0); i < uintptr(numOfSections); i++ {
		curSectionHeaderAddr := sectionHeadersAddr + uintptr(unsafe.Pointer(sizeSectionHeader*i))
		sectionName := unsafe.Slice((*byte)(unsafe.Pointer(curSectionHeaderAddr)), 8)
		//sectionName := "Wtf"
		//fmt.Printf("sectionHeaderAddr: %x\n", curSectionHeaderAddr)
		//fmt.Printf("sectionname:       %s\n", sectionName)

		if strings.Contains(string(sectionName), ".text") {
			var oldProtect uint32 = 0

			// add WRITE access to ntdll
			ntdllVirtualAddress := uintptr(*(*int32)(unsafe.Pointer(curSectionHeaderAddr + 0x0C))) // virtual address offset
			ntdllVirtualSize := uintptr(*(*int32)(unsafe.Pointer(curSectionHeaderAddr + 0x08)))    // virtual size offset

			fmt.Printf("virtualAddress:       %x\n", ntdllVirtualAddress)

			syscall.Syscall6(virtualProtectHandle,
				4,
				ntdllModuleHandle+ntdllVirtualAddress,
				ntdllVirtualSize,
				windows.PAGE_EXECUTE_READWRITE,
				uintptr(unsafe.Pointer(&oldProtect)),
				0, 0)

			fmt.Printf("oldProtect: %x\n", oldProtect)
			fmt.Printf("ntdllModuleHandle: %x\n", ntdllModuleHandle)
			fmt.Printf("modInfo.BaseOfDll: %x\n", modInfo.BaseOfDll)
			fmt.Printf("ntdllMapping: %x\n", ntdllMapping)
			fmt.Printf("ntdllVirtualSize: %x\n", ntdllVirtualSize)
			fmt.Printf("copyMemoryHandle: %x\n", rtlCopyMemoryHandle)

			// copy the new ntdll
			fmt.Scanln(&in)

			r1, _, err := syscall.Syscall(rtlCopyMemoryHandle,
				3,
				ntdllModuleHandle+ntdllVirtualAddress,
				ntdllMapping+ntdllVirtualAddress,
				ntdllVirtualSize)

			fmt.Printf("rtlCopyMem return: %x\n", r1)
			fmt.Printf("rtlCopyMem err: %s\n", err)

			// set original permissions
			syscall.Syscall6(virtualProtectHandle,
				4,
				ntdllModuleHandle+ntdllVirtualAddress,
				ntdllVirtualSize,
				uintptr(oldProtect),
				uintptr(unsafe.Pointer(&oldProtect)),
				0, 0)

		}
	}
	fmt.Printf("%x\n", numOfSections)

	fmt.Scanln(&in)
}

// convert go strings to c-style strings needed for win API calls
func StringToCharPtr(str string) *uint8 {
	chars := append([]byte(str), 0) // null terminated
	return &chars[0]
}
