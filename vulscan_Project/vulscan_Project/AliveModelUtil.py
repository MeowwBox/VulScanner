import os

from . import requestUtil
from . import IpUtil
import threading
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





def get_c_ips(ips):
    ip_list = [".".join(i.split(".")[:-1]) + ".0/24" for i in (IpUtil.get_all_ips(ips))]
    c_ip_List = []
    for i in ip_list:
        if i not in c_ip_List:
            c_ip_List.append(i)
    return c_ip_List


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
    c_ips = get_c_ips(ips)
    mode_desc = "HTTP" if mode == "http" else "PING"
    try:
        group = Group.objects.get(id=gid)
    except:
        group = Group.objects.first()
    task = ScanTask(ip_range=ips, task_count=len(c_ips) * 256, mode="alive", description=f"{group.name} ({mode_desc})", group=gid)
    task.save()
    tid = task.id
    try:
        for i in c_ips:
            flag = test_alive(i, mode)
            if flag:
                alive_scan = AliveScan(ip=i, flag=flag, taskid=tid, mode=mode_desc)
                alive_scan.save()
            task.service_process += 256
            task.save(update_fields=["service_process"])
    finally:
        task.save()
    return True

