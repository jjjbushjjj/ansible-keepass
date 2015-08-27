# ansible-keepass

Attempt to get root passwords for hosts and provide ansible with this info.

So you can store root password for your servers in keepass
Be careful adding records in you keepass datababase. 
The base needs to meet main requirement. 
Entry Title = servername (used for ssh connect)
Entry UserName = root (default ansible user for su)
and it must be uniq

Store this file as `vars_plugins/password_from_keepass.py` and specify the
following in `ansible.cfg`:
```
    [defaults]
    vars_plugins=./vars_plugins
```
In your inventory specify:
```
[all:vars]
ansible_ask_su_pass=true
x_auth_system="keepass"
x_auth_system_kdb="<path to your kdbx file>"
x_auth_system_master_key="<Your keepass master key>" (This one is a bad idea, don't store master key in cleartext here)

Pretty much all.
Right now it asks for vault password for each host in you ansible play. I will try to fix this.
