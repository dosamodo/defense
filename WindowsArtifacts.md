# Windows Artifacts

### Notes on various windows artifacts; mainly Windows 10/Server 201x



## Table of Contents

[Unsorted](#unsorted)

[Active Directory](#active-directory)

[ActivitiesCache.db](#activitiescache.db)

[Amcache](#amcache)

[Browser History](#browser-history)

[CCM_RecentlyUsedApps](#ccm_recentlyusedapps)

[Clipboard](#clipboard)

[cmd.exe](#cmd.exe)

[Event Logs](#event-logs)

[Group Policy](#group-policy)

[IIS Logs](#iis-logss)

[Kerberos](#kerberos)

[Memory](#memory)

[MUICache](#muicache)

[Named Pipes](#named-pipes)

[Networking](#networking)

[PCAP](#pcap)

[PowerShell](#powershell)

[Prefetch](#prefetch)

[RDP](#rdp)

[Registry](#registry)

[RunMRU](#runmru)

[Scheduled Tasks](#scheduled-tasks)

[Services](#services)

[ShellBags](#shellbags)

[Shimcache](#shimcache)

[Volume Shadow Copies](#volume-shadow-copies)

[WMI](#wmi)



## TODO

- Add details of what artifacts can be obtained from each i.e. Shimcache, Amcache, RecentFIleCache, etc.
- Add section for WsMan
- Add section for PsRemoting
- Populate Active Directory section with dataz
- Add section for "General Resources" to include Nirsoft, Didier Stevens, and Eric Zimmerman



## Unsorted commands

- List WsMan Sessions: `Get-WSManInstance -ResourceURI Shell -Enumerate`
  - `-ComputerName` supported
- List PsRemoting Sessions: `GetPSSession | fl *`
  - `-ComputerName` supported







## Active Directory









## ActivitiesCache.db

A file in Windows 10(1803)+ that provides chronological history of applications opened on a machine by a specific user

Default Location: c:\users\\<username>\AppData\Local\ConnectedDevicesPlatform\AAD.*\\<username>\ActivitiesCache.db

#### Resources

- [Github - An Examination of Win10 ActivitiesCache.db database](https://kacos2000.github.io/WindowsTimeline/WindowsTimeline.pdf)
- [Blog - Windows 10 for Timeline Forensics](https://www.group-ib.com/blog/windows10_timeline_for_forensics)
- [Blog - ActivitiesCache.db vs NTUSER.DAT](http://windowsir.blogspot.com/2019/11/activitescachedb-vs-ntuserdat.html)

#### Useful Tools

- [Github/kacos2000/WindowsTimeline](https://github.com/kacos2000/WindowsTimeline): A bunch of awesome and well-maintained tools for parsing ActivityCache.db. Exports to CSV or SQLite db.

- [WxTCmd:](https://github.com/EricZimmerman/WxTCmd) Windows 10 Timeline Database Parser

  `WxTCmd.exe -f <file path to ActivitiesCache.db> --csv <folder to place CSVs>`

- [Timeline ActivitiesCache Parser(tac):](https://tzworks.net/prototype_page.php?proto_id=41) Yet another Windows 10 Timeline Database Parser

- [Activities Cache Parser written in Python](https://github.com/forensicmatt/ActivitiesCacheParser)





## Amcache

AKA RecentFileCache.bcf in Windows 7d

Default Location: `\%SystemRoot%\AppCompat\Programs\Amcache.hve`

#### Resources

- https://www.andreafortuna.org/2017/10/16/amcache-and-shimcache-in-forensic-analysis/
- https://github.com/keydet89/RegRipper2.8







## AutoRuns

Places where things can get put to run automatically under various circumstances

```
HKLM\Software\Microsoft\Windows\CurrentVersion\Runonce
HKLM\Software\Microsoft\Windows\CurrentVersion\policies\Explorer\Run
HKLM\Software\Microsoft\Windows\CurrentVersion\Run
HKCU\Software\Microsoft\Windows NT\CurrentVersion\Windows\Run
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
(ProfilePath)\Start Menu\Programs\Startup
```

#### Resources

- [Whitepaper: A Forensic Analysis Of The Windows Registry](https://www.forensicfocus.com/a-forensic-analysis-of-the-windows-registry)

#### Useful Tools

- SysInternals AutoRuns
- NirSoft



## Background Activity Monitor

AKA BAM

*a Windows service that Controls activity of background applications.*

Registry Location: `HKLM\SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}`

#### Resources

- [Blog: Forensic artifacts: Evidences of program execution on Windows Systems](https://www.andreafortuna.org/2018/05/23/forensic-artifacts-evidences-of-program-execution-on-windows-systems/)





## Browser History

### Google Chrome

Default Location: `$profile\AppData\Local\Google\Chrome\User Data\Default\History`



### Microsoft Internet Explorer

Default Location: `$profile\AppData\AppData\Local\Microsoft\Windows\History\`



### Microsoft Edge



### Mozilla Firefox

Default Location: `$profile\AppData\Roaming\Mozilla\Firefox\Profiles`





## CCM_RecentlyUsedApps

Default Location: `C:\windows\system32\wbem\repository\OBJECTS.DATA`

#### Useful Tools

- CCM_RUA_Finder.py
- woanware/wmi-parser: C# implementation of CCM_RUA_Finder.py plus CSV export
- 





## Clipboard

#### Useful commands:

- Get clipboard data of current user context: `Get-Clipboard`







## cmd.exe

Command Prompt for Windows....since way back when

#### Notable Event Codes

- Sysmon > ProcessCreate
  - OriginalFileName = `Cmd.Exe`
- Security > 4688/4689: ProcessCreate/ProcessTerminate



#### Relevant Commands

- Obtain Process Audit logs via Powershell>Get-CimInstance: `Get-CimInstance -Query 'select * FROM Win32_NTLogEvent WHERE LogFile = "Security" AND (EventCode = "4688" OR EventCode = "4689")'`

- Enable Process Audit(4688) logging AND Process Command Line Field:

  `AuditPol.exe /set  /subcategory:"Process Creation" /success:enable /failure:enable`

  `set-itemproperty -path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -Name 'ProcessCreationIncludeCmdLine_Enabled' -value 1 -type dword`







## Event Logs

Located in: `C:\Windows\System32\winevt\Logs\`

#### Notable Event Codes

- Security Event log cleared: Security > 517

#### Useful Tools

- [DeepBlueCLI](https://github.com/sans-blue-team/DeepBlueCLI)

- [LogParser](https://www.microsoft.com/en-us/download/details.aspx?id=24659)

- [LogParser Studio(LPS)](https://gallery.technet.microsoft.com/office/Log-Parser-Studio-cd458765): GUI wrapper for LogParser. Much Great!


#### Relevant Commands

- Audit policy settings: `AuditPol /get /category:*`

- Increase EVTX log retention size:

  - Application.evtx: `limit-eventlog -logname Application -maximumsize 200000Kb`
  - Security.evtx: `limit-eventlog -logname Security -maximumsize 200000Kb`
  - System.evtx: `limit-eventlog -logname System -maximumsize 200000Kb`
  - Sysmon evtx: `wevtutil sl Microsoft-Windows-Sysmon/Operational /ms:209715200`

- Enable Process Audit(4688) logging AND Process Command Line Field:

  `AuditPol.exe /set  /subcategory:"Process Creation" /success:enable /failure:enable`

  `set-itemproperty -path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -Name 'ProcessCreationIncludeCmdLine_Enabled' -value 1 -type dword`

  





## Filesystem



#### Relevant Commands

- File listing via PowerShell>Get-ChildItem(gci): `Get-ChildItem`
- Open files: `openfiles /query`
  - Enable this capability(disabled by default): `openfiles /local on`
- Listing of suspicious file types located in various folders to include file properties and MD5 hash: 

```
ls c:\users\*,c:\temp\*,C:\ProgramData\* -r | Where-Object {$_.FullName -notmatch "VirusDefs|Symantec Endpoint Protection|Documents and Settings|nuget" -and $_.Extension -match ".zip|.rar|.7z|.docx|.pptx|.xlsx|.ps1|.bat|.rb|.php|.asp|.aspx|.scr|.vbs|.docm|pptm|.potm|.xltm|.xlam|.ppam|.ppsm|.sldm|.xlsm|.js|.hta|.msi|.cpl|.jar|.vbs|.exe|.wsh|.wsc|.ps2|.ps1m|.ps1xml|.ps2xml|.scf|.inf|.reg|.dll|.py|.pyc" -and $_.Extension -notmatch ".json|.appinfo"} | Select DirectoryName,Name,@{N='Version';E={$_.VersionInfo.ProductVersion}},LastWriteTime,Length,@{N='FileHash';E={(Get-FileHash $_).Hash}},@{N='OriginalFileName';E={$_.VersionInfo.OriginalFileName}},@{N='FileDescription';E={$_.VersionInfo.FileDescription}},@{N='Product';E={$_.VersionInfo.Product}},@{N='Debug';E={$_.VersionInfo.Debug}},@{N='Patched';E={$_.VersionInfo.Patched}},@{N='PreRelease';E={$_.VersionInfo.PreRelease}},@{N='PrivateBuild';E={$_.VersionInfo.PrivateBuild}},@{N='SpecialBuild';E={$_.VersionInfo.SpecialBuild}},@{N='Language';E={$_.VersionInfo.Language}},LastWriteTimeUtc,CreationTimeUtc,LastAccessTimeUtc,PSIsContainer,Mode,BaseName,IsReadOnly,Exists,Extension,Attributes,FullName | Select-object DirectoryName,Name,Version,LastWriteTime,Length,FileHash,OriginalFileName,FileDescription,Product,Debug,Patched,PreRelease,PrivateBuild,SpecialBuild,Language,LastWriteTimeUtc,CreationTimeUtc,LastAccessTimeUtc,PSIsContainer,Mode,BaseName,IsReadOnly,Exists,Extension,Attributes,FullName
```

#### Useful Tools

- [Invoke-NinjaCopy.ps1:](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) *can copy files off an NTFS volume by opening a read handle to the entire volume (such as c:) and parsing the NTFS structures. This requires you are an administrator of the server. This allows you to bypass multiple protections*








## Group Policy



#### Relevant Commands:

- Group Policy settings: `gpresult /z`
- Obtain Resultant Set of Policy(RSoP) from remote host via gwmi: `Get-WmiObject -namespace 		root\rsop\computer -class RSOP_PolicySetting -computername $remotehost`
- 





## IIS Logs

Default Location: `c:\inetpub\logs\LogFiles\W3SVC1\`

Registry location containing current logging directory: `HKLM\SOFTWARE\Microsoft\WebManagement\Server\LoggingDirectory`

#### Relevant Commands:

- Iterate through IIS log folder and copy log files created between 10 and 30 days ago: 
  `Get-ChildItem -Path 'c:\inetpub\logs\LogFiles\W3SVC*\' -recurse -Filter *.* -include *.* |? {$_.LastWriteTime -lt (Get-Date).AddDays(-10) }|? {$_.LastWriteTime -gt (Get-Date).AddDays(-30)} | Select -ExpandProperty FullName,BaseName, | copy-item -destination c:\temp`

#### Resources

- [Microsoft technet - Registry Keys used by IIS](https://support.microsoft.com/en-us/help/954864/description-of-the-registry-keys-that-are-used-by-iis-7-0-iis-7-5-and)





## Jump Lists



#### Resources

[Blog: Forensic artifacts: Evidences of program execution on Windows Systems](https://www.andreafortuna.org/2018/05/23/forensic-artifacts-evidences-of-program-execution-on-windows-systems/)



#### Useful Tools

- [JLECmd by Eric Zimmerman:](https://f001.backblazeb2.com/file/EricZimmermanTools/JLECmd.zip) Jump list parser
- [JumpList Explorer by Eric Zimmerman:](https://f001.backblazeb2.com/file/EricZimmermanTools/JumpListExplorer.zip) GUI-based Jump List viewer 







## Kerberos

#### Relevant Commands

- List Kerberos dataz: `klist.exe`
  - Sessions: `klist.exe sessions`
  - TGTs: `klist.exe tgt`
  - Session Tickets: `klist.exe tickets`

#### Useful Tools

- [PowerShell tool to list all Cached Kerberos Tickets](https://gallery.technet.microsoft.com/List-All-Cached-Kerberos-5ba41829)





## Memory



#### Useful Tools

- [Out-Minidump.ps1](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Out-Minidump.ps1): A post-exploitation script by PowerShellMafia to "write a process dump file with all process memory to disk."
- [Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) 
  - Dump memory of specific Process ID(pid): `procdump.exe -accepteula -c 0 -ma <pid>`
  - Dump memory by EXE name: `procdump.exe -e -h file.exe`







## MUICache









## Named Pipes

#### Useful Tools

- IONinja(not free) - Named pipe monitoring and tampering

- handle.exe/handle64.exe - SysInternals tool that provides handles, including named pipes by PID

  `handle.exe -a | findstr NamedPipe`

  

#### Relevant Commands

- List named pipes via Get-ChildItem(gci):
  `gci \\.\pipe\ | fl PSPATH,PSParentPath,PSChildName,PSDrive,PSProvider,Mode,BaseName,Target,LinkType,Name,FullName,Parent,Exists,Root,Extension,CreationTimeUtc,LastAccessTimeUtc,LastWriteTimeUtc`
  - __SLOW AND NOISY!__







## Networking

Interfaces, netstat, arpcache, dns cache, etc

#### Relevant Commands:

- netstat:
- ARP cache: `arp -a`
- DNS cache: `ipconfig -displaydns`
- Network adapter information: `ipconfig /all`







## PCAP

AKA Packet Capture

#### Resources

- Packet capture on Windows without drivers: https://www.nospaceships.com/2018/09/19/packet-capture-on-windows-without-drivers.html

  

#### Useful Tools

- Wireshark(obvz!)
- [Invoke-NetRipper.ps1](https://github.com/EmpireProject/Empire/blob/master/data/module_source/collection/Invoke-NetRipper.ps1): "a post exploitation tool targeting Windows systems which uses API hooking in order to intercept network traffic and encryption related functions from a low privileged user, being able to capture both plain-text traffic and encrypted traffic before encryption/after decryption."
- NetworkMiner: Useful for extracting files and streams from PCAP data.







## PowerShell

Default Location of PowerShell Console Logging: `$profile\appdata\roaming\microsoft\windows\powershell\PSreadline\ConsoleHost_History.txt`

#### Notable Event Codes:

- Sysmon ProcessCreate

  - OriginalFileName = `PowerShell.EXE`

- PowerShell CommandStart: EventID: 4104: Microsoft-Windows-PowerShell%4Operational.evtx

  - Requires Script Block Logging to be enabled: 

    ```
    New-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1 -Force
    ```

    

#### Relevant Commands

- Current version of PowerShell: `Get-Host | Select-Object Version` OR `$PSVersionTable`









## Prefetch

Location: `C:\Windows\Prefetch`

Summary of artifacts: 



## Psexec/Paexec/Pyexec

Remote execution tools

#### Notable Event Codes

- Sysmon ProcessCreate:

  - Psexec.exe
    - OriginalFileName = `psexec.c`
    - Product = `Sysinternals PsExec`
    - Description = `Execute processes remotely`
    - CommandLine contains `-accepteula`

  - PAexec.exe
    - Company = `Power Admin LLC`
    - Product = `PAExec Application`
    - OriginalFileName = `PAExec.exe`
  - Pyexec.exe
    - CommandLine contains `*.exe--cmd*`
    - Company = `?`
    - Product = `?`

- Sysmon PipeCreated:
  - PAExec
    - PipeName contains `\\PAExec-*-*.exe`



## RDP

AKA Remote Desktop Protocol

#### Notable Event Codes:

- Logon/Logoff: EventID: 4778(Logon)/4779(Logoff) - Security.evtx



#### Relevant Commands

RDP session data:

- List user sessions:`quser` OR `query user`
- List Session Info: `qwinsta` OR `query session`
- List Processes associated with RDP sessions: `qprocess`





## RecentApps

*Program execution launched on a **Win10** system is tracked in the RecentApps key*

Registry Location: `HKCU\Software\Microsoft\Windows\Current Version\Search\RecentApps`

#### Resources

- [Blog: Forensic artifacts: Evidences of program execution on Windows Systems](https://www.andreafortuna.org/2018/05/23/forensic-artifacts-evidences-of-program-execution-on-windows-systems/)





## Recycle Bin

The place where files go when lamers delete them







## Registry

#### Relevant Commands:

- Save SYSTEM hive: `reg save HKLM\SYSTEM <dest\path>`

- Save SOFTWARE hive: `reg save HKLM\SOFTWARE`

- Save SAM hive: `reg save HKLM\SAM`

- Save HKU hives:

```
$RegistryUsers = (Get-Content ($artifacts_folder + "\Registry\HKU-list.txt")) -replace "HKEY_USERS\\",""

ForEach ($RegistryUser in $RegistryUsers)
{
    if (!$SCRIPT:silent){write-host "Trying to save $RegistryUser"}
      $regsavepath = ($artifacts_folder + "\Registry\" + $SCRIPT:Computer + "_" + $RegistryUser + "-$(get-date -f MMddyyyy_HHmm)")
    reg save HKU\$RegistryUser $regsavepath
  }
```







## RunMRU

Everything entered in to the Run dialog box is stored in the registry for each user
Registry Location: `HKEY_CURRENT_USER\Software\Microsoft\Windows\Current Version\Explorer\RunMRU`






## Scheduled Tasks

#### Notable Event Codes:

- Scheduled Task Creation: EventID: 200/201 - Microsoft-Windows-TaskScheduler; 
- 

#### Relevant Commands

- Get a list of scheduled tasks from PowerShell > Get-CimInstance:

  `Get-CimInstance Win32_ScheduledJob`

- Get a list of scheduled tasks from schtasks: 
  - Output as list: `schtasks /query /v /fo LIST`
  - Output as CSV: `schtasks /query /v /fo CSV` 

- at.exe: DEPRECATED...upgrade that OS yo!

#### Resources

- [Microsoft docs: Schtasks usage](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/schtasks)
- [Microsoft docs: At.exe usage](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/at)



## Services

Per Microsoft, services *enable you to create long-running executable applications that run in their own Windows sessions. These services can be automatically started when the computer boots, can be paused and restarted, and do not show any user interface.*



#### Notable Event Codes:

- Service Start/Stop: EventID: 7035 - System.evtx
- Service Creation: EventID: 4697: Security.evtx
  - https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4697



#### Relevant Commands:

- Get a list of Services via Get-CimInstance: `Get-CimInstance Win32_Service`
- Get a list of Services via Get-WmiObject(gwmi): `gwmi -Class Win32_Service`
- Get a list of Services via Get-Service: `Get-Service`
  - https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-service?view=powershell-7
- Get a list of services via cmd.exe: `sc query`
  - https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/sc-query

#### Resources

- [Microsoft Docs: Introduction to Windows Service Applications](https://docs.microsoft.com/en-us/dotnet/framework/windows-services/introduction-to-windows-service-applications)





## ShellBags

A nested, hierarchal set of subkeys in the registry that provides insight in to 

Registry Location on Windows 7+: `HKCR\Local Settings\Software\Microsoft\Windows\Shell`

#### Resources

- [SANS(2014): Shellbag forensics in-depth](https://www.sans.org/reading-room/whitepapers/forensics/paper/34545)
- [Magnet Forensics: Forensic analysis of Windows ShellBags](https://www.magnetforensics.com/blog/forensic-analysis-of-windows-shellbags/)
- [Blog: Shellbags & Windows 10 Feature Updates](https://df-stream.com/2019/10/shellbags-windows-10-feature-updates/)





## Shimcache

AKA Application Compatibility Cache

Location: `HKLM\SYSTEM\CurrentControlSet\Control\SessionManager\AppCompatCache\AppCompatCache`



#### Resources

- https://www.fireeye.com/blog/threat-research/2015/06/caching_out_the_val.html
- https://github.com/mandiant/ShimCacheParser
- [AppCompatCache Parser by Eric Zimmerman](https://github.com/EricZimmerman/AppCompatCacheParser)







## Sysmon

See Sysmon.md







## UserAssist

Tracks programs executed on a Windows system to include a run count and the last execution date/time

#### Useful Tools

- [UserAssist Utility by Didier Stevens:](https://blog.didierstevens.com/programs/userassist/) displays a table of programs executed on a Windows machine, complete with running count and last execution date and time.





## User Profiles

Default Location: `C:\Users\<username>`

#### Relevant Commands

- List user profile info via PowerShell > WMI: `gwmi win32_logonsession | fl *`
- 





## Volume Shadow Copies



#### Useful Tools

- [VolumeShadowCopyTools.ps1:](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/VolumeShadowCopyTools.ps1) A PowerShell script by PowerShellMafia that allows for various actions to be performed against Volume Shadow Copies







## WMI

AKA Windows Management Instrumentation

Default Location: `C:\Windows\System32\wbem\repository`



#### Resources

- [FireEye: Windows Management Instrumentation(WMI) Offense, Defense, and Forensics](https://www.fireeye.com/content/dam/fireeye-www/global/en/current-threats/pdfs/wp-windows-management-instrumentation.pdf)

#### Useful Tools

- wmic.exe
- Get-CimInstance
- Get-WmiObject
- winrm.exe
- wbemtest.exe

#### Relevant Commands

- Services: `Get-CimInstance Win32_Service`

- Scheduled Tasks: `Get-CimInstance Win32_ScheduledJob`
- Startup Commands: `Get-CimInstance win32_startupcommand`
- Computer System: `Get-CimInstance -ClassName Win32_ComputerSystem`
- Operating System: `Get-CimInstance -ClassName Win32_OperatingSystem`
- Local User Accounts: `get-ciminstance -class win32_UserAccount -Filter "LocalAccount='True'" | select-object Status,Caption,PasswordExpires,Description,InstallDate,Name,SID,SIDType,AccountType,Disabled,FullName,Lockout,PasswordChangeable,PasswordRequired`
- Event Subscribers: 
  - Active Scripts: `get-ciminstance -namespace root\subscription -class ActiveScriptEventConsumer`
  - Commandline: `get-ciminstance -namespace root\subscription -class CommandLineEventConsumer | where-object {($_.CommandLineTemplate -ne "cscript KernCap.vbs") -and ($_.WorkingDirectory -ne "C:\\tools\\kernrate")}`
  - SMTP: `get-ciminstance -namespace root\subscription -class SMTPEventConsumer`
- Userland EXEs:
  `$SCRIPT:WMI_Processes = Get-CimInstance win32_process #gwmi win32_process -ComputerName $SCRIPT:Computer
  $SCRIPT:WMI_SuspiciousEXEs = $SCRIPT:WMI_Processes | where-object {($_.ExecutablePath -notlike "C:\Program Files*") -and ($_.ExecutablePath -notlike "C:\windows*") -and ($_.ProcessId -ne "4") -and ($_.ProcessId -ne "0") -and ($_.CommandLine -ne "\SystemRoot\System32\smss.exe")} | fl Caption,CommandLine,ExecutablePath,ProcessId,CreationDate`
- Userland DLLs:
  `$SCRIPT:WMI_DLLs = Get-CimInstance -Class CIM_ProcessExecutable #gwmi -Namespace root\cimv2 -Class CIM_ProcessExecutable -ComputerName $SCRIPT:Computer
  $SCRIPT:WMI_SuspiciousDLLs = $SCRIPT:WMI_DLLs | where-object {($_.Antecedent -notlike "*C:\\WINDOWS*") -and ($_.Antecedent -notlike "*C:\\Program Files*") -and ($_.Antecedent -notlike "*C:\\PROGRA~1*") -and ($_.Antecedent -notlike "*C:\\ProgramData*")} | fl Dependent,Antecedent`

#### Raw Queries:

| Summary                                                      | `Query`                                                      | REF  |
| ------------------------------------------------------------ | ------------------------------------------------------------ | ---- |
| Process Audit logs                                           | `select * FROM Win32_NTLogEvent WHERE LogFile = "Security" AND (EventCode = "4688" OR EventCode = "4689")` |      |
| catch a userland LoadLibrary call to ntoskrnl.exe for offset calculations - a common primitive. *ntoskrnl.exe does not actually show up in win32_process. Instead it only appears in $_.Caption as "SYSTEM". However it does seem to always be ProcessId = 4. Based upon the text from the REF tweet it appears to be specific to the EXE being loaded by a different executable | `SELECT * FROM Win32_ModuleLoadTrace WHERE FileName LIKE "%ntoskrnl.exe" and ProcessId != 4 ` | REF  |
| Print routing table                                          | `SELECT * FROM Win32_IP4RouteTable`                          | REF  |
| Trigger on any process that loads PowerShell DLL             | `SELECT * FROM Win32_ModuleLoadTrace WHERE FileName LIKE "%System.Management.Automation%.dll%"' gwmi -Namespace root\cimv2 -Class CIM_ProcessExecutable &#124; where-object {$_.antecedent -like "*System.Management.Automation.ni.dll*"}` | REF1 |
| Trigger upon creation of a permanent WMI event subscription - i.e. WMI persistence | `SELECT * FROM __InstanceCreationEvent WITHIN 5 Where TargetInstance ISA "__FilterToConsumerBinding"` |      |
| Trigger upon creation of a WMI class - Used by APT 28        | `SELECT * FROM __ClassCreationEvent`                         |      |
| Trigger upon process enumeration                             | `SELECT * FROM MSFT_WmiProvider_CreateInstanceEnumAsyncEvent_Pre WHERE ClassName="Win32_Process"` |      |
| Trigger on any method invocation on the StdRegProv class Note: the following extrinsic classes are great for detecting registry modification but they only detect changes to the HKLM hive: RegistryKeyChangeEvent, RegistryTreeChangeEvent, RegistryValueChangeEvent | `SELECT * FROM MSFT_WmiProvider_ExecMethodAsyncEvent_Pre WHERE ObjectPath="StdRegProv"` |      |
| Trigger on executing code via the Win32_Process Create method | `SELECT * FROM MSFT_WmiProvider_ExecMethodAsyncEvent_Pre WHERE ObjectPath="Win32_Process" AND MethodName="Create"` |      |
| Search PowerShell v5 Transaction logs for keywords via WMI   | `gwmi -query 'select * FROM Win32_NTLogEvent WHERE LogFile = "Microsoft-Windows-PowerShell/Operational" AND EventCode = "4104" AND (message LIKE "%ReadProcessMemory.Invoke%" OR message LIKE "%harmj0y" OR message LIKE "%AdjustTokenPrivileges%" OR message LIKE "%IMAGE_NT_OPTIONAL_HDR64_MAGIC%" OR message LIKE "%Management.Automation.RuntimeException%" OR message LIKE "%Microsoft.Win32.UnsafeNativeMethods%" OR message LIKE "%ReadProcessMemory.Invoke%" OR message LIKE "%Runtime.InteropServices%" OR message LIKE "%SE_PRIVILEGE_ENABLED%" OR message LIKE "%System.Security.Cryptography%" OR message LIKE "%System.Reflection.AssemblyName%" OR message LIKE "%System.Runtime.InteropServices%" OR message LIKE "%LSA_UNICODE_STRING%" OR message LIKE "%MiniDumpWriteDump%" OR message LIKE "%PAGE_EXECUTE_READ%" OR message LIKE "%Net.Sockets.SocketFlags%" OR message LIKE "%Reflection.Assembly%" OR message LIKE "%SECURITY_DELEGATION%" OR message LIKE "%TOKEN_ADJUST_PRIVILEGES%" OR message LIKE "%TOKEN_ALL_ACCESS%" OR message LIKE "%TOKEN_ASSIGN_PRIMARY%" OR message LIKE "%TOKEN_DUPLICATE%" OR message LIKE "%TOKEN_ELEVATION%" OR message LIKE "%TOKEN_IMPERSONATE%" OR message LIKE "%TOKEN_INFORMATION_CLASS%" OR message LIKE "%TOKEN_PRIVILEGES%" OR message LIKE "%TOKEN_QUERY%" OR message LIKE "%Metasploit%" OR message LIKE "%Advapi32.dll%" OR message LIKE "%kernel32.dll%" OR message LIKE "%msvcrt.dll%" OR message LIKE "%ntdll.dll%" OR message LIKE "%secur32.dll%" OR message LIKE "%user32.dll%")` |      |


```

```