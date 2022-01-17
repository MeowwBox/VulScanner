import os

from . import requestUtil
from . import IpUtil
import threading
import IPy
from ScanTaskModel.models import ScanTask
from AliveModel.models import AliveScan
from GroupModel.models import Group
from . import requestUtil


class Test(threading.Thread):
    def __init__(self, ip, mode):
        threading.Thread.__init__(self)
        self.mode = mode
        if mode == "http":
            self.url = f"http://{ip}"
        else:
            self.ip = ip
        self.result = False

    def run(self) -> None:
        try:
            if self.mode == "http":
                resp = requestUtil.get(self.url, timeout=0.1)
                if not resp:
                    raise Exception
                self.result = True
            else:
                self.result = "100%" not in os.popen(f"ping {self.ip} -n 1 -l 32 -w 1").read()
        except Exception as e:
            pass

    def get_result(self):
        return self.result


def get_c_ip_count(ip_range):
    count = 1
    for i in range(0, 3):
        count += ((int(ip_range[1].split(".")[i]) - int(ip_range[0].split(".")[i])) * pow(256, 2 - i))
    # ip_list = [".".join(i.split(".")[:-1]) + ".0/24" for i in (IpUtil.get_all_ips(ips))]
    # c_ip_List = []
    # for i in ip_list:
    #     if i not in c_ip_List:
    #         c_ip_List.append(i)
    # return c_ip_List
    return count


def burp(burp_list):
    flag = 0
    for i in burp_list:
        i.start()
    for i in burp_list:
        i.join()
    for i in burp_list:
        if i.get_result():
            flag += 1
    return flag


def test_alive(ips, mode="http"):
    burp_list = []
    flag = 0
    for i in IpUtil.get_all_ips(ips):
        burp_list.append(Test(i, mode))
        if len(burp_list) % 100 == 0:
            flag += burp(burp_list)
            burp_list = []
    flag += burp(burp_list)
    return flag


def alive_scan(ips, mode, gid):
    ip_range = IpUtil.get_dec_ip_range(ips)
    f_c_ip = IPy.IP(".".join(ip_range[0].split(".")[:-1]) + ".0")
    c_ip_count = get_c_ip_count(ip_range)
    mode_desc = "HTTP" if mode == "http" else "PING"
    try:
        group = Group.objects.get(id=gid)
    except:
        group = Group.objects.first()
    task = ScanTask(ip_range=ips, task_count=c_ip_count, mode="alive", description=f"{group.name} ({mode_desc})",
                    group=gid)
    task.save()
    tid = task.id
    try:
        for i in range(0, c_ip_count):
            if i > 0:
                c_ip = str(IPy.IP(int(f_c_ip.strDec()) + 256*i)) + "/24"
            else:
                c_ip = str(f_c_ip) + "/24"
            flag = test_alive(c_ip, mode)
            if flag:
                alive_scan = AliveScan(ip=c_ip, flag=flag, taskid=tid, mode=mode_desc)
                alive_scan.save()
            task.service_process += 1
            task.save(update_fields=["service_process"])
    finally:
        task.save()
    return True
