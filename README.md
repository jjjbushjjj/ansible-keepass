# ansible-keepass

Attempt to get root passwords for hosts and provide ansible with this info.

So you can store root password for your servers in keepass
The Title of Entry in keepass must be a servername.

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


Pretty much all.
Right now it asks for vault password for each host in you ansible play. I will try to fix this.
