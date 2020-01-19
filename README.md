# defense
Small defense(blueteam/DFIR) projects


# LOLBAS Regexes

|```regex```|vague_summary                |References|Notes                                        |
|-----------|-----------------------------|----------|---------------------------------------------|
|```mimi``` |Command referencing Mimi     |          |                                             |
|```whoami```|whoami command executed      |          |                                             |
|```^hostname```|hostname command executed    |          |                                             |
|```\\csc\.exe```|Use of C Sharp compiler csc.exe|https://lolbas-project.github.io/lolbas/Binaries/Csc/|                                             |
|```cmdkey```|cmdkey command executed      |https://lolbas-project.github.io/lolbas/Binaries/Cmdkey/|                                             |
|```rundll32.*setupapi.dll```|rundll32 command specifying setupapi.dll executed|https://lolbas-project.github.io/lolbas/Libraries/Setupapi/|                                             |
|```csc.*-target:library```|csc.exe command specifying -target:library executed|https://lolbas-project.github.io/lolbas/Binaries/Csc/|                                             |
|```appvlp.*(\.bat\|powershell|cmd|shellexecute|registerxll|\.exe)```|AppVLP.exe command performed |https://lolbas-project.github.io/lolbas/OtherMSBinaries/Appvlp/|                                             |
|```atbroker.*\/start.*```|atbroker command performed   |https://lolbas-project.github.io/lolbas/Binaries/Atbroker/|                                             |
|```bginfo.*bginfo.bgi.*\/popup.*\/nolicprompt```|bginfo command performed     |https://lolbas-project.github.io/lolbas/OtherMSBinaries/Bginfo/|                                             |
|```bitsadmin.*\/create.*bitsadmin.*\/addfile.*\/resume```|bitsadmin.exe command performed|https://lolbas-project.github.io/lolbas/Binaries/Bitsadmin/|                                             |
|```cdb.*-cf.*-o```|cdb command performed        |https://lolbas-project.github.io/lolbas/OtherMSBinaries/Cdb/|                                             |
|```certutil.*(-urlcache -split -f|-verifyctl -f -split|-encode|-decode)```|certutil.exe command performed|https://lolbas-project.github.io/lolbas/Binaries/Certutil/|                                             |
|```cmd.*- <.*:\w*\d*\.\w{3}```|cmd.exe used to execute data from an ADS|https://lolbas-project.github.io/lolbas/Binaries/Cmd/|                                             |
|```cmstp.*\/ni.*\/s.*(:\\|https*:\/\/)```|cmstp command executed       |https://lolbas-project.github.io/lolbas/Binaries/Cmstp/|                                             |
|```control.*\.dll```|control.exe command specifying .dll executed|https://lolbas-project.github.io/lolbas/Binaries/Control/|                                             |
|```cscript.*:.*\.\w{3}```|cscript.exe command used to execute file from ADS|https://lolbas-project.github.io/lolbas/Binaries/Cscript/|                                             |
|```csi\.exe```|csi command executed to execute unsigned C# code|https://lolbas-project.github.io/lolbas/OtherMSBinaries/Csi/|                                             |
|```diskshadow```|diskshadow command executed  |https://lolbas-project.github.io/lolbas/Binaries/Diskshadow/|                                             |
|```dnx\.exe```|dnx command executed         |https://lolbas-project.github.io/lolbas/OtherMSBinaries/Dnx/|                                             |
|```dxcap.*-c```|dxcap command executed       |https://lolbas-project.github.io/lolbas/OtherMSBinaries/Dxcap/|                                             |
|```excel.*https*```|Excel.exe used to download file from web|https://lolbas-project.github.io/lolbas/OtherMSBinaries/Excel/|                                             |
|```rundll32.*dfshim.dll```|xwizard.exe command executed |https://lolbas-project.github.io/lolbas/Binaries/Dfsvc/|                                             |
|```dnscmd.*\/config.*\/serverlevelplugindll```|rundll32.exe used to bypass AWL to hit URL|https://lolbas-project.github.io/lolbas/Binaries/Dnscmd/|                                             |
|```esentutl.*\/y.*\.vbs.*\/d.*\/o```|esentutl command performed to copy VBS|https://lolbas-project.github.io/lolbas/Binaries/Esentutl/|                                             |
|```esentutl.*\/y.*\.exe.*\/d.*\/o```|esentutl command performed to copy EXE to ADS|https://lolbas-project.github.io/lolbas/Binaries/Esentutl/|                                             |
|```esentutl.*\/y.*\.dit.*\/d.*.dit```|esentutl command performed to copy a locked file using Volume Shadow Copy|https://lolbas-project.github.io/lolbas/Binaries/Esentutl/|                                             |
|```esentutl.*\/y.*\\\\.*\.*\/d.*:\\.*:.*\.*\/o```|esentutl command performed to copy remote file to ADS|https://lolbas-project.github.io/lolbas/Binaries/Esentutl/|                                             |
|```esentutl.*\/y.*\\\\.*\.\w{3}.*\/d.*\\\\.*\.\w{3}.*\/o```|esentutl command performed to copy remote file to remote file|https://lolbas-project.github.io/lolbas/Binaries/Esentutl/|                                             |
|```expand.*(:\\|\\\\)```|expand command executed      |https://lolbas-project.github.io/lolbas/Binaries/Expand/|                                             |
|```extexport.*(:\\|\\\\)```|extexport command executed   |https://lolbas-project.github.io/lolbas/Binaries/Extexport/|                                             |
|```extrac32.*(:\\|\\\\).*:```|extrac32 command executed    |https://lolbas-project.github.io/lolbas/Binaries/Extrac32/|                                             |
|```findstr.*\/V|\/S.*\/L|\/I.*:\\|\\\\.*```|findstr command executed     |https://lolbas-project.github.io/lolbas/Binaries/Findstr/|                                             |
|```forfiles.*\/p.*:\\.*\/m.*\/c```|forfiles command executed    |https://lolbas-project.github.io/lolbas/Binaries/Forfiles/|                                             |
|```ftp.*-s:```|ftp command executed to execute commands from a file|https://lolbas-project.github.io/lolbas/Binaries/Ftp/|                                             |
|```gpscript.*(\/logon|\/startup)```|gpscript.exe command executed|https://lolbas-project.github.io/lolbas/Binaries/Gpscript/|                                             |
|```hh.*(:\\|https*:\/\/)```|HH.exe(HTML Help) command executed|https://lolbas-project.github.io/lolbas/Binaries/Hh/|                                             |
|```ie4uinit.*-BaseSettings```|ie4uinit.exe command executed with -BaseSettings argument|https://lolbas-project.github.io/lolbas/Binaries/Ie4uinit/|                                             |
|```ieexec.*(:\\|https*:\/\/)```|ieexec command executed      |https://lolbas-project.github.io/lolbas/Binaries/Ieexec/|                                             |
|```InfDefaultInstall.*Infdefaultinstall.inf```|Infdefaultinstall.exe command executed|https://lolbas-project.github.io/lolbas/Binaries/Infdefaultinstall/|                                             |
|```installutil.*\/logfile.*\/U.*\.dll```|InstallUtil command executed |https://lolbas-project.github.io/lolbas/Binaries/Installutil/|                                             |
|```jsc.*(\/t)*.*\.js```|jsc.exe command executed     |https://lolbas-project.github.io/lolbas/Binaries/Jsc/|                                             |
|```makecab.*(:\\|https*:\/\/)```|makecab.exe command executed |https://lolbas-project.github.io/lolbas/Binaries/Makecab/|                                             |
|```mavinject.*\d+.*\/INJECTRUNNING.*:\\.*\.dll```|MavInject.exe command executed to inject DLL in to running thread|https://lolbas-project.github.io/lolbas/Binaries/Mavinject/|                                             |
|```mftrace.*\.exe```|Mftrace.exe used to run EXE as subprocess of it|https://lolbas-project.github.io/lolbas/OtherMSBinaries/Mftrace/|                                             |
|```Microsoft\.Workflow\.Compiler```|Microsoft.Workflow.Compiler.exe command executed|https://lolbas-project.github.io/lolbas/Binaries/Microsoft.Workflow.Compiler/|                                             |
|```mmc.*-Embedding.*\.msc```|mmc.exe command executed possibly to run COM payload in background|https://lolbas-project.github.io/lolbas/Binaries/Mmc/|                                             |
|```msbuild.*(\.xml|\.csproj)```|msbuild.exe command executed to compile csproj or xml file|https://lolbas-project.github.io/lolbas/Binaries/Msbuild/|                                             |
|```msconfig.*-5```|msconfig.exe command executed|https://lolbas-project.github.io/lolbas/Binaries/Msconfig/|                                             |
|```msdeploy.*-verb:sync.*-source:RunCommand.*-dest:runCommand=```|msdeploy.exe command executed|https://lolbas-project.github.io/lolbas/OtherMSBinaries/Msdeploy/|                                             |
|```msdt.*-path.*\.xml.*-af.*\/skip.*TRUE```|msdt.exe command executed    |https://lolbas-project.github.io/lolbas/Binaries/Msdt/|                                             |
|```mshta```|mshta.exe command executed   |https://lolbas-project.github.io/lolbas/Binaries/Mshta/|                                             |
|```msiexec.*(\/q|\/quiet|\/y|\z).*```|Suspicious msiexec.exe command executed|https://lolbas-project.github.io/lolbas/Binaries/Msiexec/|                                             |
|```msxsl```|msxsl.exe command executed   |https://lolbas-project.github.io/lolbas/OtherMSBinaries/Msxsl/|                                             |
|```odbconf.*-f.*\.rsp```|odbconf.exe command executed |https://lolbas-project.github.io/lolbas/Binaries/Odbcconf/|                                             |
|```pcalua.*-a```|pcalua.exe command executed  |https://lolbas-project.github.io/lolbas/Binaries/Pcalua/|                                             |
|```pcwrun.*\.exe```|pcwrun.exe command executed  |https://lolbas-project.github.io/lolbas/Binaries/Pcwrun/|                                             |
|```powerpnt.*https*```|PowerPnt.exe used to download file from web|https://lolbas-project.github.io/lolbas/OtherMSBinaries/Powerpnt/|                                             |
|```presentationhost.*\.xbap```|Presentationhost.exe command executed|https://lolbas-project.github.io/lolbas/Binaries/Presentationhost/|                                             |
|```print.*\/D:\w{1}:\\.*(:\\|\\\\).*\.exe```|print.exe command executed   |https://lolbas-project.github.io/lolbas/Binaries/Print/|                                             |
|```rcsi``` |rcsi.exe command executed    |https://lolbas-project.github.io/lolbas/OtherMSBinaries/Rcsi/|                                             |
|```reg.*export.*:.*\.reg```|reg.exe used to execute file in ADS|https://lolbas-project.github.io/lolbas/Binaries/Reg/|                                             |
|```regasm.*\.dll```|regasm.exe used to load DLL and execute the RegisterClass function|https://lolbas-project.github.io/lolbas/Binaries/Regasm/|                                             |
|```register-cimprovider.*-path.*\.dll```|Register-cimprovider.exe used to load DLL|https://lolbas-project.github.io/lolbas/Binaries/Register-cimprovider/|                                             |
|```regsvcs.*\.dll```|regsvcs.exe used to load DLL and execute the RegisterClass function|https://lolbas-project.github.io/lolbas/Binaries/Regsvcs/|                                             |
|```regsvr32.*\/s.*\/n*.*\/i:.*\.dll```|regsvr32.exe used to load DLL|https://lolbas-project.github.io/lolbas/Binaries/Regsvr32/|                                             |
|```replace.*(:\\|\\\\).*\/A```|replace.exe used to download and/or copy a file|https://lolbas-project.github.io/lolbas/Binaries/Replace/|                                             |
|```rpcping.*-s.*-e.*-a privacy -u NTLM```|rpcping.exe used to send NTLM hash to remote host|https://lolbas-project.github.io/lolbas/Binaries/Rpcping/|                                             |
|```rundll32.*javascript:.*RunHTMLApplication```|Rundll32.exe used to execute javascript code|https://lolbas-project.github.io/lolbas/Binaries/Rundll32/|                                             |
|```rundll32.*EntryPoint```|Rundll32.exe used to load a DLL|https://lolbas-project.github.io/lolbas/Binaries/Rundll32/|                                             |
|```rundll32.*-sta.*{.*}```|Rundll32.exe used to load a registered or hijacked COM Server payload|https://lolbas-project.github.io/lolbas/Binaries/Rundll32/|                                             |
|```rundll32.*:.*DllMain```|Rundll32.exe used to load a DLL|https://lolbas-project.github.io/lolbas/Binaries/Rundll32/|                                             |
|```rundll32.*advpack\.dll.*```|Rundll32.exe used with advpack.dll|https://lolbas-project.github.io/lolbas/Binaries/Rundll32/|                                             |
|```rundll32.*(comsvcs\.dll|ieadvpack\.dll|ieframe\.dll|mshtml\.dll|pcwutl\.dll|setupapi\.dll|shdocvw\.dll|shell32\.dll|syssetup\.dll|url\.dll|zipfldr\.dll)```|Rundll32.exe executed with suspicious DLL called|https://lolbas-project.github.io/lolbas/Binaries/Rundll32/|                                             |
|```Runonce.*/AlternateShellStartup```|Runonce.exe used to load custom RunOnce task|https://lolbas-project.github.io/lolbas/Binaries/Runonce/|                                             |
|```runscripthelper.*surfacecheck.*\z\\\\?\\.*:\\```|runscripthelper.exe used to execute a powershell script|https://lolbas-project.github.io/lolbas/Binaries/Runscripthelper/|                                             |
|```sc.*create.*binpath=.*(cmd.exe|powershell.exe)```|Suspicious service created with sc.exe|https://lolbas-project.github.io/lolbas/Binaries/Sc/|                                             |
|```schtasks.*\/create.*\/sc.*\/tr.*\.exe```|Scheduled Task created to launch EXE|https://lolbas-project.github.io/lolbas/Binaries/Schtasks/|                                             |
|```scriptrunner.*-appvscript.*(\.exe|\.cmd|\.bat)```|ScriptRunner used to launch exe or bat/cmd|https://lolbas-project.github.io/lolbas/Binaries/Scriptrunner/|                                             |
|```reg.*import.*&.*cscript.*\/b.*slmgr.vbs```|Slmgr.vbs being used to execute code|https://lolbas-project.github.io/lolbas/Scripts/Slmgr/|                                             |
|```sqldumper```|sqldumper.exe command executed|https://lolbas-project.github.io/lolbas/OtherMSBinaries/Sqldumper/|                                             |
|```sqlps```|sqlps.exe command executed\  |https://lolbas-project.github.io/lolbas/OtherMSBinaries/Sqlps/|                                             |
|```sqltoolsps```|sqltoolsps.exe command executed|https://lolbas-project.github.io/lolbas/OtherMSBinaries/Sqltoolsps/|                                             |
|```squirrel.*--download.*https*```|squirrel.exe command executed to download file from web|https://lolbas-project.github.io/lolbas/OtherMSBinaries/Squirrel/|                                             |
|```SyncAppvPublishingServer.*(\.ps1|\.webclient|\.downloadstring|https*)```|SyncAppvPublishingServer used to execute PowerShell|https://lolbas-project.github.io/lolbas/Binaries/Syncappvpublishingserver/|                                             |
|```te.*\.wsc```|te.exe command executed to call WSC file|https://lolbas-project.github.io/lolbas/OtherMSBinaries/Te/|                                             |
|```tracker.*\/d.*\/c```|Tracker.exe command executed |https://lolbas-project.github.io/lolbas/OtherMSBinaries/Tracker/|                                             |
|```update.*--(download|update|updateRollback|processstart)```|Update.exe command executed  |https://lolbas-project.github.io/lolbas/OtherMSBinaries/Update/|                                             |
|```verclsid.*\/S.*\/C.*{.*}```|verclsid.exe used to load a COM object|https://lolbas-project.github.io/lolbas/Binaries/Verclsid/|                                             |
|```Vsjitdebugger.*\.exe```|Vsjitdebugger.exe command executed to run EXE as subprocess|https://lolbas-project.github.io/lolbas/OtherMSBinaries/Vsjitdebugger/|                                             |
|```wab.exe```|wab.exe command executed     |https://lolbas-project.github.io/lolbas/Binaries/Wab/|                                             |
|```winword.*https*```|Winword.exe used to download file from web|https://lolbas-project.github.io/lolbas/OtherMSBinaries/Winword/|                                             |
|```wmic.*call create```|wmic.exe command executed    |https://lolbas-project.github.io/lolbas/Binaries/Wmic/|                                             |
|```winrm.*(quickconfig|win32_process|win32_service)```|winrm.vbs command executed   |https://lolbas-project.github.io/lolbas/Scripts/Winrm/|                                             |
|```wscript.*:.*```|wscript.exe command executed |https://lolbas-project.github.io/lolbas/Binaries/Wscript/|                                             |
|```wsl.*-e```|WSL.exe command executed - Windows Subsystem for Linux|https://lolbas-project.github.io/lolbas/OtherMSBinaries/Wsl/|                                             |
|```wsreset.exe```|wsreset.exe command executed |https://lolbas-project.github.io/lolbas/Binaries/Wsreset/|                                             |
|```xwizard.*{.*}```|xwizard.exe command executed |https://lolbas-project.github.io/lolbas/Binaries/Xwizard/|                                             |

