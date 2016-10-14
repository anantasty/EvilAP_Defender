import binascii
import json
import time, os, csv, threading, smtplib, glob
import signal
from subprocess import *
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from functools import partial
from scapy.all import *
from netaddr import *
import sys, getopt
from collections import defaultdict
from pyrcrack import scanning, management, replaying

COMMANDS = {
    'check_kill': ['airmon-ng', 'check', 'kill'],
    'check_mon_disabled': ['airmon-ng'],
    'wireless_down': lambda wif: ['ifconfig', wif, 'down'],
    'wireless_up': lambda wif: ['ifconfig', wif, 'up'],
    'mon_start': lambda wif: ['airmon-ng', 'start', wif],
    'iwconfig': ['iwconfig'],
    'list_mons': ['airmon-ng'],
    'kill_mon': lambda mon: ['airmon-ng', 'stop', mon],
    'dump_ssids': lambda wif: 'exec airodump-ng --output-format csv -w out.csv {} &'.format(wif),#["airodump-ng", "--output-format", "csv",  "-w", "out.csv", wif],
    'dump_pids': "ps  aux | grep '[a]irodump-ng --output-format csv' | awk -F ' ' '{print $2}'",


}

WHITELIST = {}

ATTACKS = {}

DB_NAME = 'evil_twin'

TABLES = {
    'ssids': 'ssids',
    'whitelist': 'whitelist',
    'ouis': 'ouis'
}


class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def load_config(config_file):
    with open(config_file, 'r') as conf_file:
        return json.load(conf_file)


def init_db(conf):
    db_host = conf['db_host']
    conn = r.connect(db_host, port = conf['db_port']).repl()

    r.db_list().contains(DB_NAME).do(
        lambda exists: r.branch(exists, 0, r.db_create(DB_NAME))
    ).run()
    db = r.db(DB_NAME)
    for key in TABLES.values():
        db.table_list().contains(key).do(
            lambda exists: r.branch(exists, 0, db.table_create(key))
        ).run()


def validate_mon_iface(conf):
    output = str(Popen(*COMMANDS['iwconfig'], stdout=PIPE).communicate()[0]).split('\n')
    found = False
    for row in output:
        if conf['mon_device'] in row:
            found = True
    if not found:
        print('interface {} cound not be found'.format(conf['mon_device']))
        raise Exception('interface not found')
    return conf['mon_device']


def get_moniface():
    mons, ifaces = cmd_iwconfig()

    if len(mons) > 0:
        return mons[0]
    else:
        return


def get_mons():
    lines = str(Popen(COMMANDS['list_mons'], stdout=subprocess.PIPE) .communicate() [0]).split('\n')
    mons = []
    for line in lines:
        if 'mon' in line or 'smoothie' in line:
            mons.append(line.split('\t')[0])
    return mons


def kill_mons(mons):
    print('Killing all mons from : {}'.format(mons))
    for mon in mons:
        output = call(COMMANDS['kill_mon'](mon), stdout=PIPE)


def insert_ap(pkt, aps, ouis):
    try:
        ## Done in the lfilter param
        # if Dot11Beacon not in pkt and Dot11ProbeResp not in pkt:
        #     return
        bssid = pkt[Dot11].addr3
        if bssid in aps:
            return
        p = pkt[Dot11Elt]
        cap = pkt.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}"
                          "{Dot11ProbeResp:%Dot11ProbeResp.cap%}").split('+')

        ssid, OUI = None, None
        OUIs = []

        while isinstance(p, Dot11Elt):
            if p.ID == 0:
                ssid = p.info

            if p.ID == 221:
                s = binascii.b2a_hex(p.info)
                OUI = s[:6]
                #print p.info.encode("hex")
                #oui = OUI(s[:6])
                #print oui.registration(0).org
                #print "SSID: %r [%s], OUI: %r" % (ssid, bssid, OUI)
                if OUI not in OUIs:
                    OUIs.append(OUI)

            p = p.payload

        #cursor.execute("select * from whitelist where ssid = '" + ssid + "'")
        #if cursor.rowcount > 0:
        aps[bssid] = (ssid)
        ouis.extend(OUIs)
    except Exception as e:
        print(bcolors.FAIL + bcolors.BOLD + "Unexpected error in 'insert_ap': {}\n".format(sys.exc_info()[0]) + bcolors.ENDC)
        raise(e)


def start_dump(mon_iface, **kwargs):
    print(mon_iface)
    dump = scanning.Airodump(interface=mon_iface, **kwargs)
    dump.start()
    return dump


def sniff_packets(mon_iface):
    print ('starting airodump. NOW: {}'.format(mon_iface))
    aps = {}
    ouis = []
    insert_ap_suc = partial(insert_ap, aps=aps, ouis=ouis)
    sniff(iface=mon_iface, prn=insert_ap_suc, count=100, store=False, lfilter=lambda p: (Dot11Beacon in p or Dot11ProbeResp in p))
    return aps, ouis


def cmd_iwconfig():
    mons = []
    ifaces = {}
    iwconf = Popen(COMMANDS['iwconfig'], stdout=PIPE)
    for line in iwconf.communicate()[0].split('\n'):
        if len(line) == 0: continue
        if line[0] != ' ':
            wired_search = re.search('eth[0-9]|em[0-9]|p[1-9]p[1-9]', line)
            if not wired_search:
                iface = line[:line.find(' ')]
                if 'Mode:Monitor' in line:
                    mons.append(iface)
                elif 'IEEE 802.11' in line:
                    if "ESSID:\"" in line:
                        ifaces[iface] = 1
                    else:
                        ifaces[iface] = 0
    return mons, ifaces


def prep_mon_iface(wireless_interface, channel=None):
    call(COMMANDS['check_kill'])
    mon = management.Airmon(interface=wireless_interface, channel=channel)
    mon_iface = mon.start()
    print("Airmon RES \n {}".format(mon_iface))
    return mon_iface


def delete_stale_files():
    map(os.remove, glob('out.csv*'))


def parse_airodump_csv(file):
    try:
        # Trying to solve the issue of having null bytes
        f = open(file, 'rb') # opens the csv file
        try:
            #reader = csv.reader(f)  # creates the reader object
            # Trying to solve the issue of having null bytes (utf-16)
            reader = csv.reader(x.replace('\0', '') for x in f)  # creates the reader object
            ssids = []
            for row in reader:   # iterates the rows of the file in orders
                if 'BSSID' in row:
                    continue
                if 'Station MAC' in row:
                    break
                if len(row) < 1:
                    continue
                keys = ['mac','ssid','pwr','channel','CIPHER','Enc','Auth']
                vals = [row[0].strip(), row[13].strip(), row[8].strip(), row[3].strip(), row[6].strip(), row[5].strip(), row[7].strip()]
                ssid_row = dict(zip(keys, vals))
                print(ssid_row)
                ssids.append(ssid_row)
            return ssids
        finally:
            f.close()      # closing
    except:
        print(bcolors.FAIL + bcolors.BOLD + "Unexpected error in 'ParseAirodumpCSV': {}\n".format(sys.exc_info()[0]) + bcolors.ENDC)

def get_ssids(mon_iface):
    aps, ouis = dump_ssids(mon_iface)
    ssids = []
    for file in glob('out.csv*'):
        ssids.extend(parse_airodump_csv(file))
    return ssids


def detect_evil_ap(ssids_dict):
    evil_aps = []
    for ssid in WHITELIST.keys():
        if ssid in ssids_dict:
            for ssid_detail in ssids_dict[ssid]:
                if WHITELIST[ssid] != ssid_detail:
                    evil_aps.append(ssid_detail)
    return evil_aps


def create_defaultdict(aps):
    ssids_dict = defaultdict(list)
    for bssid, ap in aps.items():
        ap['BSSID'] = bssid
        ssids_dict[ap['ESSID']].append(ap)
    return ssids_dict


def deauth(bssid, ssid, channel, wireless_interface, repeat_time=None):
    deauth_mon = prep_mon_iface(wireless_interface, channel=channel)
    deauth_dev = replaying.Aireplay(attack='deauth', interface=deauth_mon, a=bssid, e=ssid)
    deauth_dev.start()
    ATTACKS['{}_{}_{}'.format(bssid,ssid, channel)] = (deauth_mon, deauth_dev)


def defence(evil_aps, wireless_interface):
    for ap in evil_aps:
        if '{}_{}_{}'.format(ap['BSSID'], ap['ESSID'], ap['channel']) not in ATTACKS:
            print('deauthing clients from ssid: {}, bssid{}'.format(ap['BSSID'], ap['ESSID']))
            deauth(bssid=ap['BSSID'], ssid=ap['ESSID'], channel=ap['channel'], wireless_interface=wireless_interface)
        else:
            print('still attacking ssid: {}, bssid{}'.format(ap['BSSID'], ap['ESSID']))


def main(conf_file):
    conf = load_config(conf_file)
    ##init_db(conf)
    delete_stale_files()
    kill_mons(get_mons())
    wireless_interface = validate_mon_iface(conf)
    mon_iface = prep_mon_iface(wireless_interface)
    time.sleep(5)
    dump = start_dump(mon_iface)
    aps, ouis = sniff_packets(mon_iface)
    while not WHITELIST:
        ssids = dump.tree
        ssids_dict = create_defaultdict(ssids)
        print("SSIDS: {}".format(ssids_dict))
        for ssid in conf['whitelist_ssids']:
            if ssid in ssids_dict:
                WHITELIST[ssid] = ssids_dict[ssid]
        print("whitelist: {}".format(WHITELIST))
        if WHITELIST:
            break
        else:
            print('Still looking for whitelist_aps')
        time.sleep(5)
    input('press any key to start defence')
    try:
        while True:
            new_ssids = dump.tree
            new_ssids_dict = create_defaultdict(new_ssids)
            evil_aps = detect_evil_ap(new_ssids_dict)
            print('evil_aps: {}'.format(evil_aps))
            defence(evil_aps, wireless_interface)
            time.sleep(5)
    except KeyboardInterrupt:
        kill_mons(get_mons())
