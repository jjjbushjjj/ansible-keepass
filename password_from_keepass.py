import getpass
import os
import sys
import libkeepass
import lxml.etree as ET

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
#        print "Host Invoke for %s with wars: %s" % (host.name, host.get_vars())
        if "--ask-su-pass" in sys.argv: 

            # first get vars from groups
            x_auth_system = host.get_group_vars().get("x_auth_system")
            x_auth_system_kdb = host.get_group_vars().get("x_auth_system_kdb")
            x_auth_system_master_key = host.get_group_vars().get("x_auth_system_master_key")
            # set all from groups or from host
            if x_auth_system and x_auth_system_kdb and x_auth_system_master_key:
                host.set_variable('x_auth_system', x_auth_system)
                host.set_variable('x_auth_system_kdb', x_auth_system_kdb)
                host.set_variable('x_auth_system_master_key', x_auth_system_master_key)
            else:
                x_auth_system = host.get_vars().get("x_auth_system")
                x_auth_system_kdb = host.get_vars().get("x_auth_system_kdb")
                x_auth_system_master_key = host.get_vars().get("x_auth_system_master_key")

            # skip hosts without x_auth_system
            if not x_auth_system:
                return

            passwd = ""
            ps  = host.get_vars().get("ansible_su_pass")
            if ps is None:
                if x_auth_system == "keepass":
                    if x_auth_system_kdb is None:
                        x_auth_system_kdb = raw_input( "Provide full path to keepass kdb file: ")
                        host.set_variable('x_auth_system_kdb', x_auth_system_kdb)

                    if x_auth_system_master_key is None:
                        prmt = "Enter keepass vault password for host "+host.name+": "
                        x_auth_system_master_key = getpass.getpass(prompt = prmt)
                        host.set_variable('x_auth_system_master_key', x_auth_system_master_key)

                    rez = {}
                    with libkeepass.open( x_auth_system_kdb , password = x_auth_system_master_key ) as kdb:
                        xmldata = ET.fromstring(kdb.pretty_print())
                        for history in xmldata.xpath(".//History"):
                            history.getparent().remove(history)

                        for el in xmldata.findall('.//Entry'):
                            uuid =  el.find('./UUID').text
                            rez[uuid] = {}
                            for elem in el.findall('./String'):
                                key = elem.find('./Key').text
                                val = elem.find('./Value').text
                                rez[uuid][key] = val
                    for elem in rez.keys():
                        if rez[elem]['Title'] == host.name and rez[elem]['UserName'] == 'root' :
                            passwd = rez[elem]['Password']
#                           print passwd, host.name

                else:
                    raise Exception("Unknown Authentication System %s for host %s" % (x_auth_system, host.name))
                if passwd == "":
                    passwd = getpass.getpass(prompt="%s su password: " % host.name)
                host.set_variable('ansible_su_pass', passwd)

    def get_group_vars(self, group, vault_password=None):
        """ Get group specific variables. """
#        print "GROUP: %s VARS: %s" % (group.name, group.get_vars()) 
        if "--ask-su-pass" in sys.argv: 
            x_auth_system = group.get_vars().get("x_auth_system")
            x_auth_system_kdb = group.get_vars().get("x_auth_system_kdb")
            x_auth_system_master_key = group.get_vars().get("x_auth_system_master_key")
            if x_auth_system == "keepass":
                if x_auth_system_kdb is None:
                    x_auth_system_kdb = raw_input( "Provide full path to keepass kdb file: ")
                    group.set_variable('x_auth_system_kdb', x_auth_system_kdb)

                if x_auth_system_master_key is None:
                    prmt = "Enter keepass vault password for group "+group.name+": "
                    x_auth_system_master_key = getpass.getpass(prompt = prmt)
                    group.set_variable('x_auth_system_master_key', x_auth_system_master_key)

