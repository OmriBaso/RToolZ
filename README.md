# RToolZ
A Stealthy Lsass Dumper - can abuse ProcExp152.sys driver to dump PPL Lsass.  
# What is so special about it?
No calls to MiniDump or any dbghelp.lib methods, all of the dumping process is done MANUALLY by the dumper while  
reducing the dump size to minimal by removing unessacery data .  

# Methods && How to use 
  
The OmriToolZ have 3 methods to dump lsass:  
1. The first method is simply using direct syscalls to get an lsass handle.  
2. The second method, an handle to lsass is being requested with the `PROCESS_CREATE_PROCESS` permissions, create a new process in the name of lsass  
and forks the new process in order to get `PROCESS_ALL_ACCESS` to lsass.exe (some kind of handle privilege escaltion).  
3. The third method can only work with `PROCEXP152.sys` loaded, this method will obtain an HANDLE to the driver and abuse it to get an handle on the LSASS.exe process  
this can be used to bypass `"RunAsPPL"` lsass defense.   

#### Flags:
----------------------------------------------------------------
`--valid` flag will be used to generate a dump without randomizing the signiture, if it is not used you must use the restore_signature.sh script.  
`--write` spesifics the path where you throw the dump into the disk.  
`-m` spesifics the methods listed above.  

# Credits
1. Some of the code was taken and modified from the https://github.com/helpsystems/nanodump project.


