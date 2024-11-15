**==Find a machine with domain admin session1. Invoke-SessionHunter.ps1 from the student VM to list sessions on all the remote machines. 
```
	1.  . C:\AD\Tools\Invoke-SessionHunter.ps1
	2. Invoke-SessionHunter -NoPortScan -RawResults | select Hostname,UserSession,Access
```
Look for domain admin sessions (svcadmin) on dcorp-mgmt machine.

if we find a session, we can try abusing it. (refer abusing chapter for it)

---

 ==find out the machines on which we have local admin privileges==
```
 . C:\AD\Tools\Find-PSRemotingLocalAdminAccess.ps1
 Find-PSRemotingLocalAdminAccess
```
