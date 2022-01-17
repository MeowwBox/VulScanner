import IPy
import re


ip_re1 = r"((([0-9]+?)\.){3}([0-9]+?)(/([0-9]+))?;?)+"
ip_re2 = r"((([0-9]+?)\.){3}([0-9]+?)( )*-( )*(([0-9]+?)\.){3}([0-9]+?))"


def dec2ip(dec_ip):
    str_ip = str(bin(dec_ip))
    return ("%d.%d.%d.%d" % (
        int(str_ip[:-24], 2), int(str_ip[-24:-16], 2), int(str_ip[-16:-8], 2), int(str_ip[-8:], 2)))


def get_ips(ip, mode):
    ip_list = []
    mode = 32 - mode
    ip = IPy.IP(ip)
    ip_dec = int(ip.strDec())
    ip_base = int(ip_dec / pow(2, mode)) * pow(2, mode)
    for i in range(0, pow(2, mode)):
        dec_ip = ip_base + i
        ip_list.append(dec2ip(dec_ip))
    return ip_list

def get_all_ips(ips: str):
    all_ip_list = []
    ips_list = ips.split(",")
    print(ips_list)
    for ips in ips_list:
        if not re.match(ip_re1, ips) and not re.match(ip_re2, ips):
            return []
        if r"/" in ips:
            ip = ips.split("/")[0]
            mode = int(ips.split("/")[-1])
            ip_list = get_ips(ip, mode)
        elif "-" in ips:
            ip_list = []
            fip = int(IPy.IP(ips.split("-")[0].strip()).strDec())
            lip = int(IPy.IP(ips.split("-")[-1].strip()).strDec())
            for i in range(fip, lip+1):
                ip_list.append(dec2ip(i))
        else:
            ip_list = [ips]
        all_ip_list.extend(ip_list)
    return all_ip_list


def get_dec_ip_range(ips: str):
    if r"/" in ips:
        dec_ip = int(IPy.IP(ips.split("/")[0].strip()).strDec())
        mode = int(ips.split("/")[-1])
        f_ip = int(dec_ip / pow(2, 32-mode)) * pow(2, 32-mode)
        l_ip = f_ip+pow(2, 32-mode)-1
    # elif "-" in ips:
    else:
        f_ip = ips.split("-")[0].strip()
        l_ip = ips.split("-")[-1].strip()
    return [str(IPy.IP(f_ip)), str(IPy.IP(l_ip))]