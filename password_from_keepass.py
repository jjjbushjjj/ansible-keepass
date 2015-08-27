import getpass
import os
import sys
import libkeepass

class VarsModule(object):

    """
    Loads variables for groups and/or hosts
    """

    def __init__(self, inventory):
        """ constructor """
        self.inventory = inventory
        self.inventory_basedir = inventory.basedir()


    def get_host_vars(self, host, vault_password=None):
        """ Get host specific variables. """
        print "Invoke for %s" % host.name
        if "--ask-su-pass" in sys.argv:
            x_auth_system = host.get_variables().get("x_auth_system")
            x_auth_system_kdb = host.get_variables().get("x_auth_system_kdb")
            x_auth_system_master_key = host.get_variables().get("x_auth_system_master_key")

            if x_auth_system_kdb is None:
                x_auth_system_kdb = raw_input( "Provide full path to keepass kdb file: ")
                host.set_variable('x_auth_system_kdb', x_auth_system_kdb)

            if x_auth_system_master_key is None:
                x_auth_system_master_key = getpass.getpass(prompt = 'Enter keepass vault password: ')
                host.set_variable('x_auth_system_master_key', x_auth_system_master_key)

            ps  = host.get_variables().get("ansible_su_pass")
            if ps is None:
                if x_auth_system == "keepass":
                    # All interesting begins here!
                    rez = {}
#                    ps = getpass.getpass(prompt = 'Enter keepass vault password: ')
                    with libkeepass.open( x_auth_system_kdb , password = x_auth_system_master_key ) as kdb:
                        for el in kdb.obj_root.findall('.//Entry'):
                            uuid =  el.find('UUID').text
                            rez[uuid] = {}
                            for elem in el.findall('.//String'):
                                key = elem.find('Key').text
                                val = elem.find('Value').text
                                rez[uuid][key] = val
                    for elem in rez.keys():
                        if rez[elem]['Title'] == host.name and rez[elem]['UserName'] == 'root' :
                            passwd = rez[elem]['Password']
#                            print passwd, host.name

                else:
                    raise Exception("Unknown Authentication System %s for host %s" % (x_auth_system, host.name))
                if passwd is None:
                    passwd = getpass.getpass(prompt="%s: su password" % x_auth_system)
                host.set_variable('ansible_su_pass', passwd)
