import MySQLdb
import rethinkdb as r
import json
import time, os, csv, threading, smtplib
from subprocess import *
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from functools import partial
from scapy.all import *
from netaddr import *
import sys, getopt

COMMANDS = {
    'check_kill': ['airmon-ng', 'check', 'kill'],
    'check_mon_disabled': ['airmon-ng'],
    'wireless_down': lambda wif: ['ifconfig', wif, 'down'],
    'wireless_up': lambda wif: ['ifconfig', wif, 'up'],
    'mon_start': lambda wif: ['airmon-ng', 'start', wif],
    'iwconfig': ['iwconfig'],
    'list_mons': ['airmon-ng'],
    'kill_mon': lambda mon: ['airmon-ng', 'stop', mon],
    'dump_ssids': lambda wif: ["airodump-ng", "--output-format", "csv",  "-w", "out.csv", wif]

}

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
    with open(config_file, 'rb') as conf_file:
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
    output = Popen(*COMMANDS['iwconfig'], stdout=PIPE).communicate()[0].split('\n')
    found = False
    for row in output:
        if conf['mon_device'] in row:
            found = True
    if not found:
        print('interface {} cound not be found}'.format(conf['mon_device']))
        raise Exception('interface not found')
    return conf['mon_device']


def get_moniface():
    mons, ifaces = cmd_iwconfig()

    if len(mons) > 0:
        return mons[0]
    else:
        return


def get_mons():
    lines = Popen(COMMANDS['list_mons'], stdout=PIPE).communicate()[0].split('\n')
    mons = []
    for line in lines:
        if 'mon' in line:
            mons.append(line.split('\t')[0])
    return mons


def kill_mons(mons):
    print('Killing all mons from : {}'.format(mons))
    for mon in mons:
        output = call(COMMANDS['kill_mon'](mon), stdout=PIPE)


def insert_ap(pkt, aps):
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
        print('packet info: {}, packet: {},'.format(pkt.info, pkt))

        ssid, OUI = None, None
        OUIs = []

        while isinstance(p, Dot11Elt):
            if p.ID == 0:
                ssid = p.info

            if p.ID == 221:
                s = p.info.encode("hex")
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
        for item in OUIs:
            cmd = "insert into ssids_OUIs (mac, ssid, oui) values(%s,%s,%s)"
            cursor.execute(cmd, (bssid, ssid, item))

        aps[bssid] = (ssid)
        return aps
    except:
        print bcolors.FAIL + bcolors.BOLD + "Unexpected error in 'insert_ap': {}\n".format(sys.exc_info()[0]) + bcolors.ENDC


def dump_ssids(wireless_interface):
    print ('starting airodump. NOW')
    airodump = Popen(COMMANDS['dump_ssids'](wireless_interface), shell=True, stdout=PIPE)
    aps = {}
    insert_ap_sub = partial(insert_ap, aps=aps)
    sniff(iface=wireless_interface, prn=insert_ap_sub, count=100, store=False, lfilter=lambda p: (Dot11Beacon in p or Dot11ProbeResp in p))
    airodump.terminate()


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


def prep_mon_iface(wireless_interface):
    call(COMMANDS['wireless_down'](wireless_interface))
    call(COMMANDS['wireless_up'](wireless_interface))
    call(COMMANDS['check_kill'])
    airmon_out = Popen(COMMANDS['mon_start'](wireless_interface), stdout=PIPE).communicate()[0]
    print("Airmon RES \n {}".format(airmon_out))
    mon_iface = get_moniface()
    for i in range(1,20):
        if 'mon0' in get_mons():
            break
        time.sleep(10)

    if mon_iface and 'mon0' in get_mons():
        print('Monitor intreface created on {}'.format(mon_iface))
    else:
        raise Exception("Monitor intreface could not be created")


def main(conf_file):
    conf = load_config(conf_file)
    init_db(conf)
    kill_mons(get_mons())
    mon_iface = validate_mon_iface(conf)
    prep_mon_iface(mon_iface)
    dump_ssids(mon_iface)
    kill_mons(get_mons())
