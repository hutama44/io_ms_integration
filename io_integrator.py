from tenable.io import TenableIO
import pprint
import sys
import webbrowser
import pexpect

class color:
   PURPLE = '\033[1;35;48m'
   CYAN = '\033[1;36;48m'
   BOLD = '\033[1;37;48m'
   BLUE = '\033[1;34;48m'
   GREEN = '\033[1;32;48m'
   YELLOW = '\033[1;33;48m'
   RED = '\033[1;31;48m'
   BLACK = '\033[1;30;48m'
   UNDERLINE = '\033[4;37;48m'
   END = '\033[1;37;0m'


ip = sys.argv[1]
vpr = sys.argv[2]
tio = TenableIO('', '')
mn = []
cv = []
words = ["Microsoft","Windows","Linux","Apache"]

def openlink(cve):
    cve = cve.replace('CVE-','')
    url = "https://www.exploit-db.com/search?cve=" + cve
    webbrowser.open_new_tab(url)

def openms(name):
    for a in words:
        name = name.replace(a,'')
    name = name.lstrip()
    tar = pexpect.spawn('msfconsole')
    tar.expect_exact('Metasploit')
    tar.sendline('search type:exploit description:"'+name+'"')
    print(color.GREEN + '(+) Escape character is \'^]\'.' + color.END)
    tar.interact()
    tar.kill(1)

#for asset in tio.workbenches.assets():
#  pprint.pprint(asset)

print(color.BLUE + "(+)   Exploits available in Metasploit" + color.END)
for vuln in tio.exports.vulns(severity=['critical'],cidr_range=ip,vpr_score={"gt":vpr}):
    if "metasploit_name" in vuln["plugin"]:
        mn.append(vuln["plugin"]["metasploit_name"])
#        pprint.pprint(vuln["plugin"]["metasploit_name"])
mn = list(dict.fromkeys(mn))
for i in mn:
    response = input(color.RED + "(+) Do you want to chek MS for " + i + "? (y/n)" + color.END)
    if response == "y":
     openms(i)
#pprint.pprint(mn)
print(color.BLUE + "(+)  CVE to search in other tools" + color.END)
for vuln in tio.exports.vulns(severity=['critical'],cidr_range=ip,vpr_score={"gt":vpr}):
    if "cve" in vuln["plugin"]:
        cv.extend(vuln["plugin"]["cve"])
cv = list(dict.fromkeys(cv))
for i in cv:
    response = input(color.RED + "(+) Do you want to check exploitdb for " + i + "? (y/n)" + color.END)
    if response == "y":
     openlink(i)
    if response == "k":
        break

#pprint.pprint(cv)

#https://www.exploit-db.com/search?cve=2018-8625
#print("(+)   Vuln Names")
#for vuln in tio.exports.vulns(severity=['critical'],cidr_range=ip,vpr_score={"gt":8}):
#        pprint.pprint(vuln["plugin"]["name"])
#vuln = tio.workbenches.asset_vuln_info(asset_id,19506)
#pprint.pprint(vuln)
