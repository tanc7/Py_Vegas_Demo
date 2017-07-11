#!/usr/bin/env python
# coding=UTF-8

import os
import sys
import operator
import socket
from termcolor import colored
sys.stdout.write("\x1b[8;{rows};{cols}t".format(rows=64, cols=200)) # sets window to full screen

sys.path.append("/root/Documents/")
import toolkits


def red(string):
    string = colored(string,'red',attrs=['bold'])

    return string
def green(string):
    string = colored(string,'green',attrs=['bold'])

    return string
def yellow(string):
    string = colored(string,'yellow',attrs=['bold'])

    return string
def cyan(string):
    string = colored(string,'cyan',attrs=['bold'])

    return string


os.chdir("/root/Documents")

# Metasploit Manual Start up Commands
print red("Starting up Metasploit services")
os.system('service postgresql start')
os.system('msfdb init')
os.system('msfdb start')

print red("Starting up Tor Service")
os.system("gnome-terminal -e 'bash -c \"tor; exec bash\"'")


def scan_by_metasploit(script_chosen, scan_str):
    os.chdir("/root/Documents")

    target_ip = str(raw_input(cyan("Enter either a IP address, range, or hostname to scan: ")))

    # FIN SCAN, gets past firewalls
    # print "Starting PASS ONE: A FIN Scan"
    print cyan("Starting PASS ONE: A FIN Scan")
    cmd_str = """db_nmap -v -O -sF -Pn -T4 -O -F --script={0} {1}
    exit""".format(
        script_chosen,
        target_ip
    )

    print cmd_str
    w = open(tmp_resource_file,'w')
    w.write(cmd_str)
    w.close()

    debug_str = "cat {0}".format(cmd_str)
    os.system(debug_str)
    print "RESOURCE FILE CREATED: %s" % tmp_resource_file

    run_resource_file_str = "tsocks msfconsole -r ./db_nmap_temp_file.rc"

    print "RUNNING RESOURCE FILE: %s" % run_resource_file_str


    os.system(run_resource_file_str)

    # XMAS scan
    # print "Starting PASS TWO: A XMas Scan"
    print cyan("Starting PASS TWO: A XMas Scan")
    cmd_str = """db_nmap -v -O -sX -Pn -T4 -O -F --script={0} {1}
    exit""".format(
        script_chosen,
        target_ip
    )

    w = open(tmp_resource_file,'w')
    w.write(cmd_str)
    w.close()

    debug_str = "cat {0}".format(cmd_str)
    os.system(debug_str)
    print "RESOURCE FILE CREATED: %s" % tmp_resource_file

    run_resource_file_str = "tsocks msfconsole -r ./db_nmap_temp_file.rc"

    print "RUNNING RESOURCE FILE: %s" % run_resource_file_str

    os.system(run_resource_file_str)

    #Comprehensive Scan
    # print "Starting PASS THREE: A COMPREHENSIVE Scan"
    print cyan("Starting PASS THREE: A COMPREHENSIVE Scan")
    cmd_str = """db_nmap -sS -sU -T4 -A -v -PE -PP -PS80,443 -PA3389 -PU40125 -PY -g 53 --script={0} {1}
    exit""".format(
        script_chosen,
        target_ip
    )

    w = open(tmp_resource_file,'w')
    w.write(cmd_str)
    w.close()

    debug_str = "cat {0}".format(cmd_str)
    os.system(debug_str)
    print "RESOURCE FILE CREATED: %s" % tmp_resource_file

    run_resource_file_str = "tsocks msfconsole -r ./db_nmap_temp_file.rc"

    print "RUNNING RESOURCE FILE: %s" % run_resource_file_str

    os.system(run_resource_file_str)

    return

def scan_by_regular_nmap(script_chosen, scan_str):
    os.chdir("/root/Documents")

    target_ip = str(raw_input("Enter either a IP address, range, or hostname to scan: "))
    savefile_name = str(raw_input("Enter a savefile name WITHOUT a file extension, example ('testname'): "))

    # FIN SCAN, gets past firewalls
    # print "Starting PASS ONE: A FIN Scan"
    print cyan("Starting PASS ONE: A FIN Scan")
    cmd_str = """tsocks nmap -v -O -sF -Pn -T4 -O -F -oA {0} --script={1} {2}
    exit""".format(
        savefile_name,
        script_chosen,
        target_ip
    )
    os.system(cmd_str)
    # XMAS scan
    # print "Starting PASS TWO: A XMas Scan"
    print cyan("Starting PASS TWO: A XMas Scan")
    cmd_str = """tsocks nmap -v -O -sX -Pn -T4 -O -F -oA {0} --script={1} {2}
    exit""".format(
        savefile_name,
        script_chosen,
        target_ip
    )
    os.system(cmd_str)

    #Comprehensive Scan
    # print "Starting PASS THREE: A COMPREHENSIVE Scan"
    print cyan("Starting PASS THREE: A COMPREHENSIVE Scan")
    cmd_str = """tsocks nmap -sS -sU -T4 -A -v -PE -PP -PS80,443 -PA3389 -PU40125 -PY -g 53 -oA {0} --script={1} {2}
    exit""".format(
        savefile_name,
        script_chosen,
        target_ip
    )
    os.system(cmd_str)

    complete_str = """NMAP scans complete, check your scans at: /root/Documents/{0}
    """.format(
        savefile_name
    )
    print green(complete_str)

    return

def metasploit_or_regular_nmap(script_chosen):
    print """
    Which scan would you like to use?

    1. Metasploit + Tor Socks proxy
    2. Regular NMap + Tor Socks proxy
    """

    opt_choice = int(raw_input(cyan("Enter a OPTION: ")))

    if opt_choice == 1:
        scan_str = "tsocks nmap"
        scan_by_metasploit(script_chosen, scan_str)
    elif opt_choice == 2:
        scan_str = "tsocks db_nmap"
        scan_by_regular_nmap(script_chosen, scan_str)
    else:
        print red("You have entered a invalid option")
        metasploit_or_regular_nmap()



def all_other_script_categories(): # must be separately defined. This was meant to organize the 190+ different categories
    def acarsd():
        options_dict = {

        }
        options_str = str(options_dict)
        options_str = options_str.replace(',','\n')

        print options_str

        opt_choice = int(raw_input(cyan("Enter a SCRIPT OPTION: ")))
        script_chosen = options_dict[opt_choice]
        metasploit_or_regular_nmap(script_chosen)
        return script_chosen
    def afp():
        options_dict = {

        }
        options_str = str(options_dict)
        options_str = options_str.replace(',','\n')

        print options_str

        opt_choice = int(raw_input(cyan("Enter a SCRIPT OPTION: ")))
        script_chosen = options_dict[opt_choice]
        metasploit_or_regular_nmap(script_chosen)
        return script_chosen
    def allseeingeye():
        options_dict = {

        }
        options_str = str(options_dict)
        options_str = options_str.replace(',','\n')

        print options_str

        opt_choice = int(raw_input(cyan("Enter a SCRIPT OPTION: ")))
        script_chosen = options_dict[opt_choice]
        metasploit_or_regular_nmap(script_chosen)
        return script_chosen
    def amqp():
        options_dict = {

        }
        options_str = str(options_dict)
        options_str = options_str.replace(',','\n')

        print options_str

        opt_choice = int(raw_input(cyan("Enter a SCRIPT OPTION: ")))
        script_chosen = options_dict[opt_choice]
        metasploit_or_regular_nmap(script_chosen)
        return script_chosen
    def asn():
        options_dict = {

        }
        options_str = str(options_dict)
        options_str = options_str.replace(',','\n')

        print options_str

        opt_choice = int(raw_input(cyan("Enter a SCRIPT OPTION: ")))
        script_chosen = options_dict[opt_choice]
        metasploit_or_regular_nmap(script_chosen)
        return script_chosen
    def auth():
        options_dict = {

        }
        options_str = str(options_dict)
        options_str = options_str.replace(',','\n')

        print options_str

        opt_choice = int(raw_input(cyan("Enter a SCRIPT OPTION: ")))
        script_chosen = options_dict[opt_choice]
        metasploit_or_regular_nmap(script_chosen)
        return script_chosen
    def backorifice():
    	return
    def bacnet():
    	return
    def banner():
    	return
    def bitcoin():
    	return
    def bittorrent():
    	return
    def bjnpdiscover():
    	return
    def broadcast():
    	return
    def cassandra():
    	return
    def cccamversion():
    	return
    def cicsenum():
    	return
    def citrixxml():
    	return
    def clamav():
    	return
    def clarkcounty_nmap_smtp_enum_users():
    	return
    def clock():
    	return
    def coapresources():
    	return
    def couchdbdatabases():
    	return
    def credssummary():
    	return
    def cups():
    	return
    def cvs():
    	return
    def daapgetlibrary():
    	return
    def daytime():
    	return
    def db2das():
    	return
    def dhcpdiscover():
    	return
    def dict():
    	return
    def distcccve20042687():
    	return
    def dnsblacklist():
    	return
    def dockerversion():
    	return
    def domcon():
    	return
    def dominoenumusers():
    	return
    def dpap():
    	return
    def drda():
    	return
    def duplicates():
    	return
    def eap():
    	return
    def enip():
    	return
    def epmd():
    	return
    def eppcenumprocesses():
    	return
    def fcrdns():
    	return
    def finger():
    	return
    def fingerprintstrings():
    	return
    def firewalk():
    	return
    def firewallbypass():
    	return
    def flumemaster():
    	return
    def fox():
    	return
    def freelancer():
    	return
    def ftpanon():
    	return
    def ganglia():
    	return
    def giop():
    	return
    def gkrellm():
    	return
    def gopherls():
    	return
    def gpsd():
    	return
    def hadoopdatanode():
    	return
    def hbasemaster():
    	return
    def hddtemp():
    	return
    def hnap():
    	return
    def hostmapbfk():
    	return
    def httpadobecoldfusionapsa1301():
    	return
    def iax2():
    	return
    def icap():
    	return
    def ikeversion():
    	return
    def imap():
    	return
    def impressremotediscover():
    	return
    def informix():
    	return
    def ipforwarding():
    	return
    def ipgeolocationgeoplugin():
    	return
    def iphttpsdiscover():
    	return
    def ipidseq():
    	return
    def ipmi():
    	return
    def ipv6multicastmldlist():
    	return
    def ircbotnetchannels():
    	return
    def iscsi():
    	return
    def isns():
    	return
    def jdwp():
    	return
    def knxgatewaydiscover():
    	return
    def krb5enumusers():
    	return
    def ldap():
    	return
    def lexmarkconfig():
    	return
    def llmnrresolve():
    	return
    def lltd():
    	return
    def maxdb():
    	return
    def mcafeeepoagent():
    	return
    def membase():
    	return
    def metasploit():
    	return
    def mikrotikrouteros():
    	return
    def mmouse():
    	return
    def modbusdiscover():
    	return
    def mongodb():
    	return
    def mqttsubscribe():
    	return
    def mrinfo():
    	return
    def msrpcenum():
    	return
    def mssql():
    	return
    def mtrace():
    	return
    def murmurversion():
    	return
    def mysqlaudit():
    	return
    def natpmp():
    	return
    def nbstat():
    	return
    def ncpenumusers():
    	return
    def ncpserverinfo():
    	return
    def ndmpfs():
    	return
    def ndmpversion():
    	return
    def nessus():
    	return
    def netbusauthbypass():
    	return
    def nexpose():
    	return
    def nfsls():
    	return
    def njenode():
    	return
    def nntpntlm():
    	return
    def nping():
    	return
    def nrpeenum():
    	return
    def ntp():
    	return
    def omp2():
    	return
    def omron():
    	return
    def openlookup():
    	return
    def openvasotp():
    	return
    def oracle():
    	return
    def oracletnsversion():
    	return
    def ovsagentversion():
    	return
    def p2pconficker():
    	return
    def pathmtu():
    	return
    def pcanywhere():
    	return
    def pcworx():
    	return
    def pgsql():
    	return
    def pjlreadymessage():
    	return
    def pop3():
    	return
    def pptpversion():
    	return
    def qconn():
    	return
    def qscan():
    	return
    def quake1():
    	return
    def rdpenumencryption():
    	return
    def realvncauthbypass():
    	return
    def redis():
    	return
    def resolveall():
    	return
    def reverseindex():
    	return
    def rexec():
    	return
    def rfc868time():
    	return
    def riakhttp():
    	return
    def rlogin():
    	return
    def rmidumpregistry():
    	return
    def rpcap():
    	return
    def rpcgrind():
    	return
    def rsync():
    	return
    def rtspmethods():
    	return
    def rusers():
    	return
    def s7():
    	return
    def sambavulncve20121182():
    	return
    def scriptdb():
    	return
    def servicetags():
    	return
    def shodanapi():
    	return
    def sip():
    	return
    def skypev2version():
    	return
    def smb():
    	return
    def smtp():
    	return
    def snifferdetect():
    	return
    def snmp():
    	return
    def socksauth():
    	return
    def ssh2enumalgos():
    	return
    def sshhostkey():
    	return
    def sslccsinjection():
    	return
    def stun():
    	return
    def stuxnetdetect():
    	return
    def supermicroipmiconf():
    	return
    def svn():
    	return
    def targetsasn():
    	return
    def teamspeak2version():
    	return
    def telnet():
    	return
    def tftpenum():
    	return
    def tlsnextprotoneg():
    	return
    def tn3270screen():
    	return
    def torconsensuschecker():
    	return
    def traceroutegeolocation():
    	return
    def tso():
    	return
    def tsoenum():
    	return
    def unittest():
    	return
    def unusualport():
    	return
    def upnp():
    	return
    def urlsnarf():
    	return
    def ventrilo():
    	return
    def versant():
    	return
    def vmauthd():
    	return
    def vmwareversion():
    	return
    def vnc():
    	return
    def voldemort():
    	return
    def vtamenum():
    	return
    def vuzedht():
    	return
    def wdbversion():
    	return
    def weblogict3():
    	return
    def whoisdomain():
    	return
    def wsdddiscover():
    	return
    def x11access():
    	return
    def xdmcpdiscover():
    	return
    def xmlrpcmethods():
    	return
    def xmpp():
    	return


    return

dict_generic_script_options = {
    1: 'auth',
    2: 'broadcast',
    3: 'brute',
    4: 'default',
    5: 'discovery',
    6: 'dos',
    7: 'exploit',
    8: 'external',
    9: 'fuzzer',
    10: 'intrusive',
    11: 'malware',
    12: 'safe',
    13: 'version',
    14: 'vuln',
    15: 'auth,brute,discovery,dos,exploit,external,fuzzer,intrusive,malware,version,vuln',
    16: 'auth,discovery,external,safe,version,vuln',
    17: 'ssl-enum-ciphers',
    18: 'ssl-known-key',
    19: 'sip-enum-users',
    20: 'smb-enum-users',
    21: 'dns-srv-enum',
    22: 'http-wordpress-enum',
    23: 'http-enum',
    24: 'http-userdir-enum',
    25: 'cics-enum',
    26: 'cics-user-enum',
    27: 'krb5-enum-users',
    28: 'msrpc-enum',
    29: 'mysql-enum',
    30: 'rdp-enum-encryption',
    31: 'smtp-enum-users',
    32: 'ssh2-enum-algos'
}

dict_all_nmap_scripts = {

    1: "acarsd-info.nse",
    2: "address-info.nse",
    3: "afp-brute.nse",
    4: "afp-ls.nse",
    5: "afp-path-vuln.nse",
    6: "afp-serverinfo.nse",
    7: "afp-showmount.nse",
    8: "ajp-auth.nse",
    9: "ajp-brute.nse",
    10: "ajp-headers.nse",
    11: "ajp-methods.nse",
    12: "ajp-request.nse",
    13: "allseeingeye-info.nse",
    14: "amqp-info.nse",
    15: "asn-query.nse",
    16: "auth-owners.nse",
    17: "auth-spoof.nse",
    18: "backorifice-brute.nse",
    19: "backorifice-info.nse",
    20: "bacnet-info.nse",
    21: "banner.nse",
    22: "bitcoin-getaddr.nse",
    23: "bitcoin-info.nse",
    24: "bitcoinrpc-info.nse",
    25: "bittorrent-discovery.nse",
    26: "bjnp-discover.nse",
    27: "broadcast-ataoe-discover.nse",
    28: "broadcast-avahi-dos.nse",
    29: "broadcast-bjnp-discover.nse",
    30: "broadcast-db2-discover.nse",
    31: "broadcast-dhcp6-discover.nse",
    32: "broadcast-dhcp-discover.nse",
    33: "broadcast-dns-service-discovery.nse",
    34: "broadcast-dropbox-listener.nse",
    35: "broadcast-eigrp-discovery.nse",
    36: "broadcast-igmp-discovery.nse",
    37: "broadcast-listener.nse",
    38: "broadcast-ms-sql-discover.nse",
    39: "broadcast-netbios-master-browser.nse",
    40: "broadcast-networker-discover.nse",
    41: "broadcast-novell-locate.nse",
    42: "broadcast-ospf2-discover.nse",
    43: "broadcast-pc-anywhere.nse",
    44: "broadcast-pc-duo.nse",
    45: "broadcast-pim-discovery.nse",
    46: "broadcast-ping.nse",
    47: "broadcast-pppoe-discover.nse",
    48: "broadcast-rip-discover.nse",
    49: "broadcast-ripng-discover.nse",
    50: "broadcast-sonicwall-discover.nse",
    51: "broadcast-sybase-asa-discover.nse",
    52: "broadcast-tellstick-discover.nse",
    53: "broadcast-upnp-info.nse",
    54: "broadcast-versant-locate.nse",
    55: "broadcast-wake-on-lan.nse",
    56: "broadcast-wpad-discover.nse",
    57: "broadcast-wsdd-discover.nse",
    58: "broadcast-xdmcp-discover.nse",
    59: "cassandra-brute.nse",
    60: "cassandra-info.nse",
    61: "cccam-version.nse",
    62: "cics-enum.nse",
    63: "cics-info.nse",
    64: "cics-user-brute.nse",
    65: "cics-user-enum.nse",
    66: "citrix-brute-xml.nse",
    67: "citrix-enum-apps.nse",
    68: "citrix-enum-apps-xml.nse",
    69: "citrix-enum-servers.nse",
    70: "citrix-enum-servers-xml.nse",
    71: "clamav-exec.nse",
    72: "clarkcounty_nmap_smtp_enum_users",
    73: "clock-skew.nse",
    74: "coap-resources.nse",
    75: "couchdb-databases.nse",
    76: "couchdb-stats.nse",
    77: "creds-summary.nse",
    78: "cups-info.nse",
    79: "cups-queue-info.nse",
    80: "cvs-brute.nse",
    81: "cvs-brute-repository.nse",
    82: "daap-get-library.nse",
    83: "daytime.nse",
    84: "db2-das-info.nse",
    85: "dhcp-discover.nse",
    86: "dict-info.nse",
    87: "distcc-cve2004-2687.nse",
    88: "dns-blacklist.nse",
    89: "dns-brute.nse",
    90: "dns-cache-snoop.nse",
    91: "dns-check-zone.nse",
    92: "dns-client-subnet-scan.nse",
    93: "dns-fuzz.nse",
    94: "dns-ip6-arpa-scan.nse",
    95: "dns-nsec3-enum.nse",
    96: "dns-nsec-enum.nse",
    97: "dns-nsid.nse",
    98: "dns-random-srcport.nse",
    99: "dns-random-txid.nse",
    100: "dns-recursion.nse",
    101: "dns-service-discovery.nse",
    102: "dns-srv-enum.nse",
    103: "dns-update.nse",
    104: "dns-zeustracker.nse",
    105: "dns-zone-transfer.nse",
    106: "docker-version.nse",
    107: "domcon-brute.nse",
    108: "domcon-cmd.nse",
    109: "domino-enum-users.nse",
    110: "dpap-brute.nse",
    111: "drda-brute.nse",
    112: "drda-info.nse",
    113: "duplicates.nse",
    114: "eap-info.nse",
    115: "enip-info.nse",
    116: "epmd-info.nse",
    117: "eppc-enum-processes.nse",
    118: "fcrdns.nse",
    119: "finger.nse",
    120: "fingerprint-strings.nse",
    121: "firewalk.nse",
    122: "firewall-bypass.nse",
    123: "flume-master-info.nse",
    124: "fox-info.nse",
    125: "freelancer-info.nse",
    126: "ftp-anon.nse",
    127: "ftp-bounce.nse",
    128: "ftp-brute.nse",
    129: "ftp-libopie.nse",
    130: "ftp-proftpd-backdoor.nse",
    131: "ftp-vsftpd-backdoor.nse",
    132: "ftp-vuln-cve2010-4221.nse",
    133: "ganglia-info.nse",
    134: "giop-info.nse",
    135: "gkrellm-info.nse",
    136: "gopher-ls.nse",
    137: "gpsd-info.nse",
    138: "hadoop-datanode-info.nse",
    139: "hadoop-jobtracker-info.nse",
    140: "hadoop-namenode-info.nse",
    141: "hadoop-secondary-namenode-info.nse",
    142: "hadoop-tasktracker-info.nse",
    143: "hbase-master-info.nse",
    144: "hbase-region-info.nse",
    145: "hddtemp-info.nse",
    146: "hnap-info.nse",
    147: "hostmap-bfk.nse",
    148: "hostmap-ip2hosts.nse",
    149: "hostmap-robtex.nse",
    150: "http-adobe-coldfusion-apsa1301.nse",
    151: "http-affiliate-id.nse",
    152: "http-apache-negotiation.nse",
    153: "http-apache-server-status.nse",
    154: "http-aspnet-debug.nse",
    155: "http-auth-finder.nse",
    156: "http-auth.nse",
    157: "http-avaya-ipoffice-users.nse",
    158: "http-awstatstotals-exec.nse",
    159: "http-axis2-dir-traversal.nse",
    160: "http-backup-finder.nse",
    161: "http-barracuda-dir-traversal.nse",
    162: "http-brute.nse",
    163: "http-cakephp-version.nse",
    164: "http-chrono.nse",
    165: "http-cisco-anyconnect.nse",
    166: "http-coldfusion-subzero.nse",
    167: "http-comments-displayer.nse",
    168: "http-config-backup.nse",
    169: "http-cookie-flags.nse",
    170: "http-cors.nse",
    171: "http-cross-domain-policy.nse",
    172: "http-csrf.nse",
    173: "http-date.nse",
    174: "http-default-accounts.nse",
    175: "http-devframework.nse",
    176: "http-dlink-backdoor.nse",
    177: "http-dombased-xss.nse",
    178: "http-domino-enum-passwords.nse",
    179: "http-drupal-enum.nse",
    180: "http-drupal-enum-users.nse",
    181: "http-enum.nse",
    182: "http-errors.nse",
    183: "http-exif-spider.nse",
    184: "http-favicon.nse",
    185: "http-feed.nse",
    186: "http-fetch.nse",
    187: "http-fileupload-exploiter.nse",
    188: "http-form-brute.nse",
    189: "http-form-fuzzer.nse",
    190: "http-frontpage-login.nse",
    191: "http-generator.nse",
    192: "http-git.nse",
    193: "http-gitweb-projects-enum.nse",
    194: "http-google-malware.nse",
    195: "http-grep.nse",
    196: "http-headers.nse",
    197: "http-huawei-hg5xx-vuln.nse",
    198: "http-icloud-findmyiphone.nse",
    199: "http-icloud-sendmsg.nse",
    200: "http-iis-short-name-brute.nse",
    201: "http-iis-webdav-vuln.nse",
    202: "http-internal-ip-disclosure.nse",
    203: "http-joomla-brute.nse",
    204: "http-litespeed-sourcecode-download.nse",
    205: "http-ls.nse",
    206: "http-majordomo2-dir-traversal.nse",
    207: "http-malware-host.nse",
    208: "http-mcmp.nse",
    209: "http-methods.nse",
    210: "http-method-tamper.nse",
    211: "http-mobileversion-checker.nse",
    212: "http-ntlm-info.nse",
    213: "http-open-proxy.nse",
    214: "http-open-redirect.nse",
    215: "http-passwd.nse",
    216: "http-phpmyadmin-dir-traversal.nse",
    217: "http-phpself-xss.nse",
    218: "http-php-version.nse",
    219: "http-proxy-brute.nse",
    220: "http-put.nse",
    221: "http-qnap-nas-info.nse",
    222: "http-referer-checker.nse",
    223: "http-rfi-spider.nse",
    224: "http-robots.txt.nse",
    225: "http-robtex-reverse-ip.nse",
    226: "http-robtex-shared-ns.nse",
    227: "http-security-headers.nse",
    228: "http-server-header.nse",
    229: "http-shellshock.nse",
    230: "http-sitemap-generator.nse",
    231: "http-slowloris-check.nse",
    232: "http-slowloris.nse",
    233: "http-sql-injection.nse",
    234: "http-stored-xss.nse",
    235: "http-svn-enum.nse",
    236: "http-svn-info.nse",
    237: "http-title.nse",
    238: "http-tplink-dir-traversal.nse",
    239: "http-trace.nse",
    240: "http-traceroute.nse",
    241: "http-unsafe-output-escaping.nse",
    242: "http-useragent-tester.nse",
    243: "http-userdir-enum.nse",
    244: "http-vhosts.nse",
    245: "http-virustotal.nse",
    246: "http-vlcstreamer-ls.nse",
    247: "http-vmware-path-vuln.nse",
    248: "http-vuln-cve2006-3392.nse",
    249: "http-vuln-cve2009-3960.nse",
    250: "http-vuln-cve2010-0738.nse",
    251: "http-vuln-cve2010-2861.nse",
    252: "http-vuln-cve2011-3192.nse",
    253: "http-vuln-cve2011-3368.nse",
    254: "http-vuln-cve2012-1823.nse",
    255: "http-vuln-cve2013-0156.nse",
    256: "http-vuln-cve2013-6786.nse",
    257: "http-vuln-cve2013-7091.nse",
    258: "http-vuln-cve2014-2126.nse",
    259: "http-vuln-cve2014-2127.nse",
    260: "http-vuln-cve2014-2128.nse",
    261: "http-vuln-cve2014-2129.nse",
    262: "http-vuln-cve2014-3704.nse",
    263: "http-vuln-cve2014-8877.nse",
    264: "http-vuln-cve2015-1427.nse",
    265: "http-vuln-cve2015-1635.nse",
    266: "http-vuln-cve2017-1001000.nse",
    267: "http-vuln-cve2017-5638.nse",
    268: "http-vuln-cve2017-5689.nse",
    269: "http-vuln-misfortune-cookie.nse",
    270: "http-vuln-wnr1000-creds.nse",
    271: "http-waf-detect.nse",
    272: "http-waf-fingerprint.nse",
    273: "http-webdav-scan.nse",
    274: "http-wordpress-brute.nse",
    275: "http-wordpress-enum.nse",
    276: "http-wordpress-users.nse",
    277: "http-xssed.nse",
    278: "iax2-brute.nse",
    279: "iax2-version.nse",
    280: "icap-info.nse",
    281: "ike-version.nse",
    282: "imap-brute.nse",
    283: "imap-capabilities.nse",
    284: "imap-ntlm-info.nse",
    285: "impress-remote-discover.nse",
    286: "informix-brute.nse",
    287: "informix-query.nse",
    288: "informix-tables.nse",
    289: "ip-forwarding.nse",
    290: "ip-geolocation-geoplugin.nse",
    291: "ip-geolocation-ipinfodb.nse",
    292: "ip-geolocation-map-bing.nse",
    293: "ip-geolocation-map-google.nse",
    294: "ip-geolocation-map-kml.nse",
    295: "ip-geolocation-maxmind.nse",
    296: "ip-https-discover.nse",
    297: "ipidseq.nse",
    298: "ipmi-brute.nse",
    299: "ipmi-cipher-zero.nse",
    300: "ipmi-version.nse",
    301: "ipv6-multicast-mld-list.nse",
    302: "ipv6-node-info.nse",
    303: "ipv6-ra-flood.nse",
    304: "irc-botnet-channels.nse",
    305: "irc-brute.nse",
    306: "irc-info.nse",
    307: "irc-sasl-brute.nse",
    308: "irc-unrealircd-backdoor.nse",
    309: "iscsi-brute.nse",
    310: "iscsi-info.nse",
    311: "isns-info.nse",
    312: "jdwp-exec.nse",
    313: "jdwp-info.nse",
    314: "jdwp-inject.nse",
    315: "jdwp-version.nse",
    316: "knx-gateway-discover.nse",
    317: "knx-gateway-info.nse",
    318: "krb5-enum-users.nse",
    319: "ldap-brute.nse",
    320: "ldap-novell-getpass.nse",
    321: "ldap-rootdse.nse",
    322: "ldap-search.nse",
    323: "lexmark-config.nse",
    324: "llmnr-resolve.nse",
    325: "lltd-discovery.nse",
    326: "maxdb-info.nse",
    327: "mcafee-epo-agent.nse",
    328: "membase-brute.nse",
    329: "membase-http-info.nse",
    330: "memcached-info.nse",
    331: "metasploit-info.nse",
    332: "metasploit-msgrpc-brute.nse",
    333: "metasploit-xmlrpc-brute.nse",
    334: "mikrotik-routeros-brute.nse",
    335: "mmouse-brute.nse",
    336: "mmouse-exec.nse",
    337: "modbus-discover.nse",
    338: "mongodb-brute.nse",
    339: "mongodb-databases.nse",
    340: "mongodb-info.nse",
    341: "mqtt-subscribe.nse",
    342: "mrinfo.nse",
    343: "msrpc-enum.nse",
    344: "ms-sql-brute.nse",
    345: "ms-sql-config.nse",
    346: "ms-sql-dac.nse",
    347: "ms-sql-dump-hashes.nse",
    348: "ms-sql-empty-password.nse",
    349: "ms-sql-hasdbaccess.nse",
    350: "ms-sql-info.nse",
    351: "ms-sql-ntlm-info.nse",
    352: "ms-sql-query.nse",
    353: "ms-sql-tables.nse",
    354: "ms-sql-xp-cmdshell.nse",
    355: "mtrace.nse",
    356: "murmur-version.nse",
    357: "mysql-audit.nse",
    358: "mysql-brute.nse",
    359: "mysql-databases.nse",
    360: "mysql-dump-hashes.nse",
    361: "mysql-empty-password.nse",
    362: "mysql-enum.nse",
    363: "mysql-info.nse",
    364: "mysql-query.nse",
    365: "mysql-users.nse",
    366: "mysql-variables.nse",
    367: "mysql-vuln-cve2012-2122.nse",
    368: "nat-pmp-info.nse",
    369: "nat-pmp-mapport.nse",
    370: "nbstat.nse",
    371: "ncp-enum-users.nse",
    372: "ncp-serverinfo.nse",
    373: "ndmp-fs-info.nse",
    374: "ndmp-version.nse",
    375: "nessus-brute.nse",
    376: "nessus-xmlrpc-brute.nse",
    377: "netbus-auth-bypass.nse",
    378: "netbus-brute.nse",
    379: "netbus-info.nse",
    380: "netbus-version.nse",
    381: "nexpose-brute.nse",
    382: "nfs-ls.nse",
    383: "nfs-showmount.nse",
    384: "nfs-statfs.nse",
    385: "nje-node-brute.nse",
    386: "nje-pass-brute.nse",
    387: "nntp-ntlm-info.nse",
    388: "nping-brute.nse",
    389: "nrpe-enum.nse",
    390: "ntp-info.nse",
    391: "ntp-monlist.nse",
    392: "omp2-brute.nse",
    393: "omp2-enum-targets.nse",
    394: "omron-info.nse",
    395: "openlookup-info.nse",
    396: "openvas-otp-brute.nse",
    397: "oracle-brute.nse",
    398: "oracle-brute-stealth.nse",
    399: "oracle-enum-users.nse",
    400: "oracle-sid-brute.nse",
    401: "oracle-tns-version.nse",
    402: "ovs-agent-version.nse",
    403: "p2p-conficker.nse",
    404: "path-mtu.nse",
    405: "pcanywhere-brute.nse",
    406: "pcworx-info.nse",
    407: "pgsql-brute.nse",
    408: "pjl-ready-message.nse",
    409: "pop3-brute.nse",
    410: "pop3-capabilities.nse",
    411: "pop3-ntlm-info.nse",
    412: "pptp-version.nse",
    413: "qconn-exec.nse",
    414: "qscan.nse",
    415: "quake1-info.nse",
    416: "quake3-info.nse",
    417: "quake3-master-getservers.nse",
    418: "rdp-enum-encryption.nse",
    419: "rdp-vuln-ms12-020.nse",
    420: "realvnc-auth-bypass.nse",
    421: "redis-brute.nse",
    422: "redis-info.nse",
    423: "resolveall.nse",
    424: "reverse-index.nse",
    425: "rexec-brute.nse",
    426: "rfc868-time.nse",
    427: "riak-http-info.nse",
    428: "rlogin-brute.nse",
    429: "rmi-dumpregistry.nse",
    430: "rmi-vuln-classloader.nse",
    431: "rpcap-brute.nse",
    432: "rpcap-info.nse",
    433: "rpc-grind.nse",
    434: "rpcinfo.nse",
    435: "rsync-brute.nse",
    436: "rsync-list-modules.nse",
    437: "rtsp-methods.nse",
    438: "rtsp-url-brute.nse",
    439: "rusers.nse",
    440: "s7-info.nse",
    441: "samba-vuln-cve-2012-1182.nse",
    442: "script.db",
    443: "servicetags.nse",
    444: "shodan-api.nse",
    445: "sip-brute.nse",
    446: "sip-call-spoof.nse",
    447: "sip-enum-users.nse",
    448: "sip-methods.nse",
    449: "skypev2-version.nse",
    450: "smb-brute.nse",
    451: "smb-double-pulsar-backdoor.nse",
    452: "smb-enum-domains.nse",
    453: "smb-enum-groups.nse",
    454: "smb-enum-processes.nse",
    455: "smb-enum-sessions.nse",
    456: "smb-enum-shares.nse",
    457: "smb-enum-users.nse",
    458: "smb-flood.nse",
    459: "smb-ls.nse",
    460: "smb-mbenum.nse",
    461: "smb-os-discovery.nse",
    462: "smb-print-text.nse",
    463: "smb-psexec.nse",
    464: "smb-security-mode.nse",
    465: "smb-server-stats.nse",
    466: "smb-system-info.nse",
    467: "smbv2-enabled.nse",
    468: "smb-vuln-conficker.nse",
    469: "smb-vuln-cve2009-3103.nse",
    470: "smb-vuln-cve-2017-7494.nse",
    471: "smb-vuln-ms06-025.nse",
    472: "smb-vuln-ms07-029.nse",
    473: "smb-vuln-ms08-067.nse",
    474: "smb-vuln-ms10-054.nse",
    475: "smb-vuln-ms10-061.nse",
    476: "smb-vuln-ms17-010.nse",
    477: "smb-vuln-regsvc-dos.nse",
    478: "smtp-brute.nse",
    479: "smtp-commands.nse",
    480: "smtp-enum-users.nse",
    481: "smtp-ntlm-info.nse",
    482: "smtp-open-relay.nse",
    483: "smtp-strangeport.nse",
    484: "smtp-vuln-cve2010-4344.nse",
    485: "smtp-vuln-cve2011-1720.nse",
    486: "smtp-vuln-cve2011-1764.nse",
    487: "sniffer-detect.nse",
    488: "snmp-brute.nse",
    489: "snmp-hh3c-logins.nse",
    490: "snmp-info.nse",
    491: "snmp-interfaces.nse",
    492: "snmp-ios-config.nse",
    493: "snmp-netstat.nse",
    494: "snmp-processes.nse",
    495: "snmp-sysdescr.nse",
    496: "snmp-win32-services.nse",
    497: "snmp-win32-shares.nse",
    498: "snmp-win32-software.nse",
    499: "snmp-win32-users.nse",
    500: "socks-auth-info.nse",
    501: "socks-brute.nse",
    502: "socks-open-proxy.nse",
    503: "ssh2-enum-algos.nse",
    504: "ssh-hostkey.nse",
    505: "sshv1.nse",
    506: "ssl-ccs-injection.nse",
    507: "ssl-cert-intaddr.nse",
    508: "ssl-cert.nse",
    509: "ssl-date.nse",
    510: "ssl-dh-params.nse",
    511: "ssl-enum-ciphers.nse",
    512: "ssl-heartbleed.nse",
    513: "ssl-known-key.nse",
    514: "ssl-poodle.nse",
    515: "sslv2-drown.nse",
    516: "sslv2.nse",
    517: "sstp-discover.nse",
    518: "stun-info.nse",
    519: "stun-version.nse",
    520: "stuxnet-detect.nse",
    521: "supermicro-ipmi-conf.nse",
    522: "svn-brute.nse",
    523: "targets-asn.nse",
    524: "targets-ipv6-map4to6.nse",
    525: "targets-ipv6-multicast-echo.nse",
    526: "targets-ipv6-multicast-invalid-dst.nse",
    527: "targets-ipv6-multicast-mld.nse",
    528: "targets-ipv6-multicast-slaac.nse",
    529: "targets-ipv6-wordlist.nse",
    530: "targets-sniffer.nse",
    531: "targets-traceroute.nse",
    532: "targets-xml.nse",
    533: "teamspeak2-version.nse",
    534: "telnet-brute.nse",
    535: "telnet-encryption.nse",
    536: "telnet-ntlm-info.nse",
    537: "tftp-enum.nse",
    538: "tls-nextprotoneg.nse",
    539: "tls-ticketbleed.nse",
    540: "tn3270-screen.nse",
    541: "tor-consensus-checker.nse",
    542: "traceroute-geolocation.nse",
    543: "tso-brute.nse",
    544: "tso-enum.nse",
    545: "unittest.nse",
    546: "unusual-port.nse",
    547: "upnp-info.nse",
    548: "url-snarf.nse",
    549: "ventrilo-info.nse",
    550: "versant-info.nse",
    551: "vmauthd-brute.nse",
    552: "vmware-version.nse",
    553: "vnc-brute.nse",
    554: "vnc-info.nse",
    555: "vnc-title.nse",
    556: "voldemort-info.nse",
    557: "vtam-enum.nse",
    558: "vuze-dht-info.nse",
    559: "wdb-version.nse",
    560: "weblogic-t3-info.nse",
    561: "whois-domain.nse",
    562: "whois-ip.nse",
    563: "wsdd-discover.nse",
    564: "x11-access.nse",
    565: "xdmcp-discover.nse",
    566: "xmlrpc-methods.nse",
    567: "xmpp-brute.nse",
    568: "xmpp-info.nse"

}
options_list = """
    For this question, type the corresponding number that represents the type of script you want to use.

    ### GENERIC USE-ALL SCRIPTS ###

    Note that this is a GENERIC USE-ALL scripts of the selected category.

    I do not recommend using #15 or #16 because it will attempt to run EVERYTHING, which takes days to complete for a single IP

    1: 'auth',
    2: 'broadcast',
    3: 'brute', Attempt to brute-force commonly and easily guessed credentials
    4: 'default',
    5: 'discovery', Find more information about the target, encryption method, etc.
    6: 'dos', Scan for Denial-Of-Service Vulnerabilities, may cause the target to crash
    7: 'exploit', Actively attempt to run exploits during the NMap scan
    8: 'external', Query third party sources online for enumeration
    9: 'fuzzer', Enter unexpected data during the scan to trigger errors and locate possible vulnerabilities
    10: 'intrusive',
    11: 'malware', Check if the target is infected with known malware
    12: 'safe',
    13: 'version',
    14: 'vuln', Check commonly known vulnerabilities
    15: AGGRESSIVE AND LOUD (and may crash a server) 'auth,brute,discovery,dos,exploit,external,fuzzer,intrusive,malware,version,vuln',
    16: DISCRETE AND STEALTHY 'auth,discovery,external,safe,version,vuln'

    ### CUSTOM FAVORITES ###

    17: 'ssl-enum-ciphers',
    18: 'ssl-known-key',
    19: 'sip-enum-users',
    20: 'smb-enum-users',
    21: 'dns-srv-enum',
    22: 'http-wordpress-enum',
    23: 'http-enum',
    24: 'http-userdir-enum',
    25: 'cics-enum',
    26: 'cics-user-enum',
    27: 'krb5-enum-users',
    28: 'msrpc-enum',
    29: 'mysql-enum',
    30: 'rdp-enum-encryption',
    31: 'smtp-enum-users',
    32: 'ssh2-enum-algos.nse'
"""
tmp_resource_file = "./db_nmap_temp_file.rc"

def use_individual_script():
    print str(dict_all_nmap_scripts).replace(',','\n')
    script_chosen = int(raw_input(cyan("Which script would you like to use? Enter a number: ")))
    try:
        script_chosen = dict_all_nmap_scripts[script_chosen]
        script_selected_str = """NMap Script Selected: {0}
        """.format(
            str(script_chosen)
        )

        print green(script_selected_str)
    except KeyError:
        os.system('clear')
        print red("Selection not found in database, please enter a number listed in the database!")
        main()

    metasploit_or_regular_nmap(script_chosen)
    return
def db_nmap():
    os.chdir("/root/Documents")

    print options_list
    script_chosen = int(raw_input("Enter a number to select the type of nmap scan you want to perform: "))
    script_chosen = dict_generic_script_options[script_chosen]
    target_ip = str(raw_input(cyan("Enter either a IP address, range, or hostname to scan: ")))

    # FIN SCAN, gets past firewalls
    # print "Starting PASS ONE: A FIN Scan"
    print cyan("Starting PASS ONE: A FIN Scan")
    cmd_str = """db_nmap -v -O -sF -Pn -T4 -O -F --script={0} {1}
    exit""".format(
        script_chosen,
        target_ip
    )

    print cmd_str
    w = open(tmp_resource_file,'w')
    w.write(cmd_str)
    w.close()

    print "RESOURCE FILE CREATED: %s" % tmp_resource_file

    run_resource_file_str = "tsocks msfconsole -r ./db_nmap_temp_file.rc"

    print "RUNNING RESOURCE FILE: %s" % run_resource_file_str


    os.system(run_resource_file_str)

    # XMAS scan
    # print "Starting PASS TWO: A XMas Scan"
    print cyan("Starting PASS TWO: A XMas Scan")
    cmd_str = """db_nmap -v -O -sX -Pn -T4 -O -F --script={0} {1}
    exit""".format(
        script_chosen,
        target_ip
    )

    w = open(tmp_resource_file,'w')
    w.write(cmd_str)
    w.close()

    debug_str = "cat {0}".format(cmd_str)
    os.system(debug_str)
    print "RESOURCE FILE CREATED: %s" % tmp_resource_file

    run_resource_file_str = "tsocks msfconsole -r ./db_nmap_temp_file.rc"

    print "RUNNING RESOURCE FILE: %s" % run_resource_file_str

    os.system(run_resource_file_str)

    #Comprehensive Scan
    # print "Starting PASS THREE: A COMPREHENSIVE Scan"
    print cyan("Starting PASS THREE: A COMPREHENSIVE Scan")
    cmd_str = """db_nmap -sS -sU -T4 -A -v -PE -PP -PS80,443 -PA3389 -PU40125 -PY -g 53 --script={0} {1}
    exit""".format(
        script_chosen,
        target_ip
    )

    w = open(tmp_resource_file,'w')
    w.write(cmd_str)
    w.close()

    debug_str = "cat {0}".format(cmd_str)
    os.system(debug_str)
    print "RESOURCE FILE CREATED: %s" % tmp_resource_file

    run_resource_file_str = "tsocks msfconsole -r ./db_nmap_temp_file.rc"

    print "RUNNING RESOURCE FILE: %s" % run_resource_file_str

    os.system(run_resource_file_str)
    return

def tsocks_nmap():
    os.chdir("/root/Documents")
    print options_list


    script_chosen = int(raw_input("Enter a number to select the type of nmap scan you want to perform: "))
    script_chosen = dict_generic_script_options[script_chosen]


    target_ip = str(raw_input("Enter either a IP address, range, or hostname to scan: "))
    savefile_name = str(raw_input("Enter a savefile name WITHOUT a file extension, example ('testname'): "))

    # FIN SCAN, gets past firewalls
    # print "Starting PASS ONE: A FIN Scan"
    print cyan("Starting PASS ONE: A FIN Scan")
    cmd_str = """tsocks nmap -v -O -sF -Pn -T4 -O -F -oA {0} --script={1} {2}
    exit""".format(
        savefile_name,
        script_chosen,
        target_ip
    )
    os.system(cmd_str)
    # XMAS scan
    # print "Starting PASS TWO: A XMas Scan"
    print cyan("Starting PASS TWO: A XMas Scan")
    cmd_str = """tsocks nmap -v -O -sX -Pn -T4 -O -F -oA {0} --script={1} {2}
    exit""".format(
        savefile_name,
        script_chosen,
        target_ip
    )
    os.system(cmd_str)

    #Comprehensive Scan
    # print "Starting PASS THREE: A COMPREHENSIVE Scan"
    print cyan("Starting PASS THREE: A COMPREHENSIVE Scan")
    cmd_str = """tsocks nmap -sS -sU -T4 -A -v -PE -PP -PS80,443 -PA3389 -PU40125 -PY -g 53 -oA {0} --script={1} {2}
    exit""".format(
        savefile_name,
        script_chosen,
        target_ip
    )
    os.system(cmd_str)

    complete_str = """NMAP scans complete, check your scans at: /root/Documents/{0}
    """.format(
        savefile_name
    )
    print green(complete_str)
    return

def help_me():
    print str(dict_all_nmap_scripts).replace(',','\n')

    opt_choice = int(raw_input(yellow("Enter the NUMBER of a script you want to see help for: ")))

    try:
        script_chosen = dict_all_nmap_scripts[opt_choice]
        script_selected_str = """NMap Script Selected: {0}
        """.format(
            str(script_chosen)
        )

        print green(script_selected_str)

    except KeyError:
        os.system('clear')
        print red("The selection is not in the database, please choose a number in the database")
        main()

    cmd_str = "nmap --script-help={0}".format(
        script_chosen
    )
    os.system(cmd_str)
    metasploit_nmap_question()
    return
def metasploit_nmap_question():
    intro_str = """
    Dear User,

    You have two options for the NMap scripting engine automater (name tentative to change)

    1. Run NMap through METASPLOIT FRAMEWORK -- Scans are automatically added to your MSF Hosts Database file
    2. Or run NMap INDEPENDENTLY -- Scans will generate three output results that are located in your /root/Documents directory
    3. Or run a NMap script INDIVIDUALLY -- Helps save time since certain scripts can take forever by itself
    4. HELP ME, learn details about a script from a selectable menu

    All methods are properly anonymized via Tor and TSocks (which comes with your Arms-Commander Installation)

    """

    print yellow(intro_str)
    # question = str(raw_input(cyan("Would you like to run the scan through Metasploit? (db_nmap, auto adds to your hosts file)? Y or N: ")))
    question = int(raw_input(cyan("Choose a OPTION: ")))
    if question == 1:
        db_nmap()
        main()
    elif question == 2:
        tsocks_nmap()
        main()
    #elif question == 4:
        select_by_category()
        main()
    elif question == 3:
        use_individual_script()
        main()

    elif question == 4:
        help_me()
        main()
    else:
        print red("Please enter 'Y' or 'N'")
        metasploit_nmap_question()

    # if question == True:
    #     os.system('clear')
    #     db_nmap()
    #     main()
    # else:
    #     tsocks_nmap()
    #     main()
    return metasploit_nmap_question

def select_by_category():

    category_list_str = os.system("cat /root/Documents/nmap_script_category_list")

    print yellow(category_list_str)
    opt_choice = int(raw_input(cyan("Enter a SCRIPT CATEGORY: ")))
    if opt_choice == 0:
        main()
    elif opt_choice == 1:
    	acarsd()
    elif opt_choice == 2:
    	address()
    elif opt_choice == 3:
    	afp()
    elif opt_choice == 4:
    	allseeingeye()
    elif opt_choice == 5:
    	amqp()
    elif opt_choice == 6:
    	asn()
    elif opt_choice == 7:
    	auth()
    elif opt_choice == 8:
    	backorifice()
    elif opt_choice == 9:
    	bacnet()
    elif opt_choice == 10:
    	banner()
    elif opt_choice == 11:
    	bitcoin()
    elif opt_choice == 12:
    	bittorrent()
    elif opt_choice == 13:
    	bjnp-discover()
    elif opt_choice == 14:
    	broadcast()
    elif opt_choice == 15:
    	cassandra()
    elif opt_choice == 16:
    	cccam-version()
    elif opt_choice == 17:
    	cics-enum()
    elif opt_choice == 18:
    	citrix-xml()
    elif opt_choice == 19:
    	clamav_exec()
    elif opt_choice == 20:
    	clarkcounty_nmap_smtp_enum_users()
    elif opt_choice == 21:
    	clock()
    elif opt_choice == 22:
    	coap-resources()
    elif opt_choice == 23:
    	couchdb-databases()
    elif opt_choice == 24:
    	creds-summary()
    elif opt_choice == 25:
    	cups()
    elif opt_choice == 26:
    	cvs()
    elif opt_choice == 27:
    	daap-get-library()
    elif opt_choice == 28:
    	daytime()
    elif opt_choice == 29:
    	db2-das()
    elif opt_choice == 30:
    	dhcp-discover()
    elif opt_choice == 31:
    	dict()
    elif opt_choice == 32:
    	distcc-cve2004-2687()
    elif opt_choice == 33:
    	dns-blacklist()
    elif opt_choice == 34:
    	docker-version()
    elif opt_choice == 35:
    	domcon()
    elif opt_choice == 36:
    	domino-enum-users()
    elif opt_choice == 37:
    	dpap()
    elif opt_choice == 38:
    	drda()
    elif opt_choice == 39:
    	duplicates()
    elif opt_choice == 40:
    	eap()
    elif opt_choice == 41:
    	enip()
    elif opt_choice == 42:
    	epmd()
    elif opt_choice == 43:
    	eppc-enum-processes()
    elif opt_choice == 44:
    	fcrdns()
    elif opt_choice == 45:
    	finger()
    elif opt_choice == 46:
    	fingerprint-strings()
    elif opt_choice == 47:
    	firewalk()
    elif opt_choice == 48:
    	firewall-bypass()
    elif opt_choice == 49:
    	flume-master()
    elif opt_choice == 50:
    	fox()
    elif opt_choice == 51:
    	freelancer()
    elif opt_choice == 52:
    	ftp-anon()
    elif opt_choice == 53:
    	ganglia()
    elif opt_choice == 54:
    	giop()
    elif opt_choice == 55:
    	gkrellm()
    elif opt_choice == 56:
    	gopher-ls()
    elif opt_choice == 57:
    	gpsd()
    elif opt_choice == 58:
    	hadoop-datanode()
    elif opt_choice == 59:
    	hbase-master()
    elif opt_choice == 60:
    	hddtemp()
    elif opt_choice == 61:
    	hnap()
    elif opt_choice == 62:
    	hostmap-bfk()
    elif opt_choice == 63:
    	http-adobe-coldfusion-apsa1301()
    elif opt_choice == 64:
    	iax2()
    elif opt_choice == 65:
    	icap()
    elif opt_choice == 66:
    	ike-version()
    elif opt_choice == 67:
    	imap()
    elif opt_choice == 68:
    	impress-remote-discover()
    elif opt_choice == 69:
    	informix()
    elif opt_choice == 70:
    	ip-forwarding()
    elif opt_choice == 71:
    	ip-geolocation-geoplugin()
    elif opt_choice == 72:
    	ip-https-discover()
    elif opt_choice == 73:
    	ipidseq()
    elif opt_choice == 74:
    	ipmi()
    elif opt_choice == 75:
    	ipv6-multicast-mld-list()
    elif opt_choice == 76:
    	irc-botnet-channels()
    elif opt_choice == 77:
    	iscsi()
    elif opt_choice == 78:
    	isns()
    elif opt_choice == 79:
    	jdwp_exec()
    elif opt_choice == 80:
    	knx-gateway-discover()
    elif opt_choice == 81:
    	krb5-enum-users()
    elif opt_choice == 82:
    	ldap()
    elif opt_choice == 83:
    	lexmark-config()
    elif opt_choice == 84:
    	llmnr-resolve()
    elif opt_choice == 85:
    	lltd()
    elif opt_choice == 86:
    	maxdb()
    elif opt_choice == 87:
    	mcafee-epo-agent()
    elif opt_choice == 88:
    	membase()
    elif opt_choice == 89:
    	metasploit()
    elif opt_choice == 90:
    	mikrotik-routeros()
    elif opt_choice == 91:
    	mmouse()
    elif opt_choice == 92:
    	modbus-discover()
    elif opt_choice == 93:
    	mongodb()
    elif opt_choice == 94:
    	mqtt-subscribe()
    elif opt_choice == 95:
    	mrinfo()
    elif opt_choice == 96:
    	msrpc-enum()
    elif opt_choice == 97:
    	ms-sql()
    elif opt_choice == 98:
    	mtrace()
    elif opt_choice == 99:
    	murmur-version()
    elif opt_choice == 100:
    	mysql-audit()
    elif opt_choice == 101:
    	nat-pmp()
    elif opt_choice == 102:
    	nbstat()
    elif opt_choice == 103:
    	ncp-enum-users()
    elif opt_choice == 104:
    	ncp-serverinfo()
    elif opt_choice == 105:
    	ndmp-fs()
    elif opt_choice == 106:
    	ndmp-version()
    elif opt_choice == 107:
    	nessus()
    elif opt_choice == 108:
    	netbus-auth-bypass()
    elif opt_choice == 109:
    	nexpose()
    elif opt_choice == 110:
    	nfs-ls()
    elif opt_choice == 111:
    	nje-node()
    elif opt_choice == 112:
    	nntp-ntlm()
    elif opt_choice == 113:
    	nping()
    elif opt_choice == 114:
    	nrpe-enum()
    elif opt_choice == 115:
    	ntp()
    elif opt_choice == 116:
    	omp2()
    elif opt_choice == 117:
    	omron()
    elif opt_choice == 118:
    	openlookup()
    elif opt_choice == 119:
    	openvas-otp()
    elif opt_choice == 120:
    	oracle()
    elif opt_choice == 121:
    	oracle-tns-version()
    elif opt_choice == 122:
    	ovs-agent-version()
    elif opt_choice == 123:
    	p2p-conficker()
    elif opt_choice == 124:
    	path-mtu()
    elif opt_choice == 125:
    	pcanywhere()
    elif opt_choice == 126:
    	pcworx()
    elif opt_choice == 127:
    	pgsql()
    elif opt_choice == 128:
    	pjl-ready-message()
    elif opt_choice == 129:
    	pop3()
    elif opt_choice == 130:
    	pptp-version()
    elif opt_choice == 131:
    	qconn_exec()
    elif opt_choice == 132:
    	qscan()
    elif opt_choice == 133:
    	quake1()
    elif opt_choice == 134:
    	rdp-enum-encryption()
    elif opt_choice == 135:
    	realvnc-auth-bypass()
    elif opt_choice == 136:
    	redis()
    elif opt_choice == 137:
    	resolveall()
    elif opt_choice == 138:
    	reverse-index()
    elif opt_choice == 139:
    	rexec()
    elif opt_choice == 140:
    	rfc868-time()
    elif opt_choice == 141:
    	riak-http()
    elif opt_choice == 142:
    	rlogin()
    elif opt_choice == 143:
    	rmi-dumpregistry()
    elif opt_choice == 144:
    	rpcap()
    elif opt_choice == 145:
    	rpc-grind()
    elif opt_choice == 146:
    	rsync()
    elif opt_choice == 147:
    	rtsp-methods()
    elif opt_choice == 148:
    	rusers()
    elif opt_choice == 149:
    	s7()
    elif opt_choice == 150:
    	samba-vuln-cve-2012-1182()
    elif opt_choice == 151:
    	script.db()
    elif opt_choice == 152:
    	servicetags()
    elif opt_choice == 153:
    	shodan-api()
    elif opt_choice == 154:
    	sip()
    elif opt_choice == 155:
    	skypev2-version()
    elif opt_choice == 156:
    	smb()
    elif opt_choice == 157:
    	smtp()
    elif opt_choice == 158:
    	sniffer-detect()
    elif opt_choice == 159:
    	snmp()
    elif opt_choice == 160:
    	socks-auth()
    elif opt_choice == 161:
    	ssh2-enum-algos()
    elif opt_choice == 162:
    	ssh-hostkey()
    elif opt_choice == 163:
    	ssl-ccs-injection()
    elif opt_choice == 164:
    	stun()
    elif opt_choice == 165:
    	stuxnet-detect()
    elif opt_choice == 166:
    	supermicro-ipmi-conf()
    elif opt_choice == 167:
    	svn()
    elif opt_choice == 168:
    	targets-asn()
    elif opt_choice == 169:
    	teamspeak2-version()
    elif opt_choice == 170:
    	telnet()
    elif opt_choice == 171:
    	tftp-enum()
    elif opt_choice == 172:
    	tls-nextprotoneg()
    elif opt_choice == 173:
    	tn3270-screen()
    elif opt_choice == 174:
    	tor-consensus-checker()
    elif opt_choice == 175:
    	traceroute-geolocation()
    elif opt_choice == 176:
    	tso()
    elif opt_choice == 177:
    	tso-enum()
    elif opt_choice == 178:
    	unittest()
    elif opt_choice == 179:
    	unusual-port()
    elif opt_choice == 180:
    	upnp()
    elif opt_choice == 181:
    	url-snarf()
    elif opt_choice == 182:
    	ventrilo()
    elif opt_choice == 183:
    	versant()
    elif opt_choice == 184:
    	vmauthd()
    elif opt_choice == 185:
    	vmware-version()
    elif opt_choice == 186:
    	vnc()
    elif opt_choice == 187:
    	voldemort()
    elif opt_choice == 188:
    	vtam-enum()
    elif opt_choice == 189:
    	vuze-dht()
    elif opt_choice == 190:
    	wdb-version()
    elif opt_choice == 191:
    	weblogic-t3()
    elif opt_choice == 192:
    	whois-domain()
    elif opt_choice == 193:
    	wsdd-discover()
    elif opt_choice == 194:
    	x11-access()
    elif opt_choice == 195:
    	xdmcp-discover()
    elif opt_choice == 196:
    	xmlrpc-methods()
    elif opt_choice == 197:
    	xmpp()

    else:
        print red("You have entered a invalid option")
        select_by_category()
    main()
    return

def custom_scan_metasploit(cmd_str):
    os.chdir("/root/Documents")
    run_resource_file_str = "tsocks msfconsole -r ./db_nmap_temp_file.rc"
    # This command clears out the temporary resource file used to run metasploit scans
    clear_str = """echo "" > {0}
    """.format(
        tmp_resource_file
    )
    os.system(clear_str)

    # writes two lines, the original command string, then a new line, and then a exit command
    w = open(tmp_resource_file,'a+')
    w.write(cmd_str + '\n')
    w.write("exit")
    w.close()


    os.system(run_resource_file_str)
    main()
    return

def custom_scan():
    run_resource_file_str = "tsocks msfconsole -r ./db_nmap_temp_file.rc"
    options_string = ""

    print """
    Choose how you want to scan with:

    1. Metasploit Framework ("db_nmap")
    2. Regular NMap

    Both are obscured using Tor and TSocks
    """
    nmap_type = int(raw_input(yellow("Enter a NMAP TYPE: ")))

    if nmap_type == 1:
        nmap_type = "db_nmap"
    elif nmap_type == 2:
        nmap_type = "nmap"
    else:
        print red("You need to choose a NMap type: ")
        custom_scan()

    opt_ping_noping = str(raw_input(yellow("Enter prompt here: ")).replace(',','').replace('%','').replace('$',''))

    if opt_ping_noping != "":
        	options_string = options_string + " " + opt_ping_noping # Do not forget about a optparse character like -v = Verbose or something!
    else:
        	pass
    # For NMap, that means options_string will be added between cmd_str + options_string + target_string
    # To put all the variables together


    opt_timing_mode = str(raw_input(yellow("Enter prompt here: ")).replace(',','').replace('%','').replace('$',''))

    if opt_timing_mode != "":
        	options_string = options_string + " " + opt_timing_mode # Do not forget about a optparse character like -v = Verbose or something!
    else:
        	pass
    # For NMap, that means options_string will be added between cmd_str + options_string + target_string
    # To put all the variables together


    opt_os_detect = str(raw_input(yellow("Enter prompt here: ")).replace(',','').replace('%','').replace('$',''))

    if opt_os_detect != "":
        	options_string = options_string + " " + opt_os_detect # Do not forget about a optparse character like -v = Verbose or something!
    else:
        	pass
    # For NMap, that means options_string will be added between cmd_str + options_string + target_string
    # To put all the variables together


    opt_scan_intensity = str(raw_input(yellow("Enter prompt here: ")).replace(',','').replace('%','').replace('$',''))

    if opt_scan_intensity != "":
        	options_string = options_string + " " + opt_scan_intensity # Do not forget about a optparse character like -v = Verbose or something!
    else:
        	pass
    # For NMap, that means options_string will be added between cmd_str + options_string + target_string
    # To put all the variables together


    opt_spoof_ip = str(raw_input(yellow("Enter prompt here: ")).replace(',','').replace('%','').replace('$',''))

    if opt_spoof_ip != "":
        	options_string = options_string + " " + opt_spoof_ip # Do not forget about a optparse character like -v = Verbose or something!
    else:
        	pass
    # For NMap, that means options_string will be added between cmd_str + options_string + target_string
    # To put all the variables together


    opt_network_interface = str(raw_input(yellow("Enter prompt here: ")).replace(',','').replace('%','').replace('$',''))

    if opt_network_interface != "":
        	options_string = options_string + " " + opt_network_interface # Do not forget about a optparse character like -v = Verbose or something!
    else:
        	pass
    # For NMap, that means options_string will be added between cmd_str + options_string + target_string
    # To put all the variables together


    target_ip = str(raw_input(yellow("Enter prompt here: ")).replace(',','').replace('%','').replace('$',''))

    if target_ip != "":
        pass
    else:
        print red("You need to enter a TARGET hostname, IP or range, or a URL")
        custom_scan()
    # For NMap, that means options_string will be added between cmd_str + options_string + target_string
    # To put all the variables together


    opt_packet_fragmentation = str(raw_input(yellow("Enter prompt here: ")).replace(',','').replace('%','').replace('$',''))

    if opt_packet_fragmentation != "":
        	options_string = options_string + " " + opt_packet_fragmentation # Do not forget about a optparse character like -v = Verbose or something!
    else:
        	pass
    # For NMap, that means options_string will be added between cmd_str + options_string + target_string
    # To put all the variables together

    opt_choice = int(raw_input(yellow("Enter the NUMBER corresponding to the NMap script that you would like to use: ")))
    script_chosen = dict_all_nmap_scripts[opt_choice]
    cmd_str = "tsocks {0} {1} --script={2} {3}".format(
        str(nmap_type),
        str(options_string),
        script_chosen,
        target_ip
    )

    if nmap_type == "nmap":
        os.system(cmd_str)
    if nmap_type == "db_nmap":
        custom_scan_metasploit(cmd_str)
    return

def main():
    metasploit_nmap_question()
    main()
    return
main()
