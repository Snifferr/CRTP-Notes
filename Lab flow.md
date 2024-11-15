1. we escalated privs to admin on student VM by adding our user to admin group
2. Then we check if the the student user that has been added to admin, has local admin on any other machine.
3. It has on admin-srv, we connect to admin-srv
4. then we have Jenkins and we do a reverse shell to gain access to that server.
5. we get a shell to dcorp-ci as dcorp\ciadmin
6. we then look for admin session (svcadmin) which we find on dcorp-mgmt (can be found directly from student VM)
7. we then try to execute command using winrs from dcorp-ci  (ciadmin) on dcorp-mgmt and we try to extract creds of svcadmin
8. Then we use those creds to have a cmd session in student Vm as SVCadmin ( from this session we can try to access dcorp-dc) since svcadmin is domain adminstrator.
Now this was us getting domain admin from dcorp-ci, we will see how we can do derivative admin from dcorp\admin-srv
9. we check if applocker is there and how we can execute scripts, since we can drop scripts in the directory where we can execute scripts. we need to disable firewall there first.
10. we run the script to get credentials and we get(srvadmin, appadmin and websvc users.) we will use aes256 hash with rebeus.
11. we do the same thing and get CMD session with srvadmin !
12. Check if srvadmin has admin privileges on any other machine. (since it has, we follow the process to extract credetials and use rebeus to overpassthehash)
**Now that we have domain admin, we will now extract all the hashes from the DC by running a process from student VM as svcadmin and then continuing**
13. we will run cmd as svcadmin and copy loader exe and extract the creds, then we will make a golden ticket
14.  after making golden ticket, we will connect to dcorp-dc and get access to DC

Now we will try to get ADMIN on Dc using diff methods like silver ticket for HTTP and WMI
follow abuse

Now we come to persistence which we skip since it's not needed for the exam and can be read later 

------

then we follow the abuse section to find access to appadmin machine (we had the hashes or secrets from the previous steps)

