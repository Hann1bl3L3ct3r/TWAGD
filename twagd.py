import ctypes
import os
import sys
import time
from ctypes import wintypes

def get_process_id_by_name(proc_name):
    snapshot = ctypes.windll.kernel32.CreateToolhelp32Snapshot(0x00000002, 0)
    if snapshot == -1:
        return None
    
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
    if ctypes.windll.kernel32.Process32First(snapshot, ctypes.byref(entry)):
        while True:
            if entry.szExeFile.decode().lower() == proc_name.lower():
                ctypes.windll.kernel32.CloseHandle(snapshot)
                return entry.th32ProcessID
            if not ctypes.windll.kernel32.Process32Next(snapshot, ctypes.byref(entry)):
                break
    
    ctypes.windll.kernel32.CloseHandle(snapshot)
    return None

def is_driver_loaded(service_name):
    h_sc = ctypes.windll.advapi32.OpenSCManagerW(None, None, 0x0001)
    if not h_sc:
        return False
    
    h_service = ctypes.windll.advapi32.OpenServiceW(h_sc, service_name, 0x0004)
    ctypes.windll.advapi32.CloseServiceHandle(h_sc)
    if h_service:
        ctypes.windll.advapi32.CloseServiceHandle(h_service)
        print("[!] Driver is already loaded. Skipping installation.")
        return True
    return False

def install_driver(driver_path, service_name):
    os.system(f'sc create {service_name} binPath= "{driver_path}" type= kernel start= auto error= normal')
    print("[!] Driver service created successfully.")

def start_driver(service_name):
    os.system(f'sc start {service_name}')
    print("[!] Driver started successfully.")

def stop_driver(service_name):
    os.system(f'sc stop {service_name}')
    time.sleep(2)
    os.system(f'sc delete {service_name}')
    print("[!] Driver service deleted successfully.")

class IoctlStruct(ctypes.Structure):
    _fields_ = [
        ("padding", ctypes.c_uint32),
        ("pid", ctypes.c_uint32),
        ("extra_padding", ctypes.c_ubyte * 16)
    ]

def kill_process_with_driver(device_name, ioctl_code, process_id):
    device_handle = ctypes.windll.kernel32.CreateFileW(
        device_name, 0xC0000000, 0x00000003, None, 3, 0, None
    )
    if device_handle == -1 or device_handle == 0xFFFFFFFF:
        print("[X] Failed to open driver device.")
        return
    
    ioctl_code = ctypes.c_ulong(ioctl_code & 0xFFFFFFFF)
    ioctl_struct = IoctlStruct(0, process_id, (ctypes.c_ubyte * 16)(*([0] * 16)))
    
    output_buffer = ctypes.create_string_buffer(4)
    bytes_returned = ctypes.c_ulong(0)
    ioctl_result = ctypes.windll.kernel32.DeviceIoControl(
        device_handle, ioctl_code, ctypes.byref(ioctl_struct),
        ctypes.sizeof(ioctl_struct), ctypes.byref(output_buffer),
        ctypes.sizeof(output_buffer), ctypes.byref(bytes_returned), None
    )
    
    ctypes.windll.kernel32.CloseHandle(device_handle)
    
    if ioctl_result == 0:
        print("[X] Failed to send IOCTL.")
    else:
        print(f"[!] Process with PID {process_id} termination requested via driver.")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python script.py <ProcessName>")
        sys.exit(1)
    
    process_name = sys.argv[1]
    service_name = "SysMon"
    script_dir = os.path.dirname(os.path.abspath(__file__))
    driver_path = os.path.join(script_dir, "sysmon.sys")
    device_name = "\\\\.\\TfSysMon"
    ioctl_code = 0xB4A00404 & 0xFFFFFFFF
    
    if not is_driver_loaded(service_name):
        print("[!] Installing and starting the driver...")
        install_driver(driver_path, service_name)
        start_driver(service_name)
    
    process_id = get_process_id_by_name(process_name)
    if process_id is None:
        print("[X] Process not found.")
        sys.exit(1)
    
    print(f"[!] Killing process with PID: {process_id}")
    kill_process_with_driver(device_name, ioctl_code, process_id)
    
    print("[!] Stopping and removing the driver...")
    stop_driver(service_name)
