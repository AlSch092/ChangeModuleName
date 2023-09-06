# ChangeModuleName  
MITRE ATT&amp;CK Submission - Changing Module names at runtime  

This topic has been accepted into MITRE's research queue as of Sept. 6 2023, and is pending real-world adversary usage examples. Have you seen an example of this technique being used in the wild? I'd love to hear from you, and my e-mail can be found on my profile page. Please view the .pdf file if you'd like a more cleanly formatted read.   

**By: AlSch092 For: MITRE ATT&CK**  

**Technique Name**: Change Module Names in Running Processes   
**Tactic**: Defense Evasion  
**Platform**: Windows  
**Required Permissions**: User  
**Sub-techniques**: This is a technique of TA0005.  
**Data Sources**: Windows API, Process Environment Block  
**Description**:  
The names of loaded modules in a process can be modified at runtime to avoid detection
mechanisms. This is done by determining the address of a module's string name and then writing
another value over it. Any process can perform this technique on itself or other processes as long as the
memory where module names are located is writable.
In the context of a running process, calls to the Windows API `GetModuleHandle` will return
NULL if one queries a module name which has been changed previously by this technique, which
potentially increases the evasion abilities of a module. Program behavior may also be altered on the
basis that `GetModuleHandle` returns NULL. Loaded modules names can also be changed to the same
or duplicate values, making it harder to determine which module is the original.
This technique can also be used to hijack or intercept program execution. If a process queries the
address of a module which has had it's name replaced with a malicious one, the malicious module can
potentially export a function with the same name and parameters as one that is looked up and called by
the victim process.  

**Detection**:  
Read the entire path including the file name when querying loaded modules, and check for the existence
of the module's file name at the path's location.
If two or more of the same module name is found loaded in a running process, then it means at least
one of those modules had their names modified  

**Mitigation**:  
Ensure that memory is non-writable for locations on the heap where module string names reside at.
Save the names of all loaded modules and their memory addresses at program startup, such that if any
are later modified it can be clearly determined  

**Adversary Use**: No examples could be found as this is a newly discovered technique. Further data must
be collected to determine if any past malware samples have used this technique. Please contact me if you've seen this being used in malware, and I can reference you in the submission!  

**Additional References**:  

A published and peer-reviewed reference to this technique can also be found at:
(https://unprotect.it/technique/change-module-name-at-runtime/)
