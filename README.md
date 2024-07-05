# VTRS
VirusTotal (recursive?) scannning script

## What it does?
It list all your processes on your device, and all DLLs loaded by these processes. Then it calculate hashes for the files, and finally submit it to VirusTotal for detection result.

## What it's used for?
Probably for quickly scan running processes on your device, in case you have a reason not to believe them.

## Why I have to use this? Can't I just use Process Explorer?
While Process Explorer **does** submit hashes to VT and then get back the results, it does not submit all of them. You have to manually select the process for submission of its DLLs, and you might never know in time which DLL in which process might be harmful if you have to manually select each process.

Also, now you have a script for extending yourself!

## License
MIT
