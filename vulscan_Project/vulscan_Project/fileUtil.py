import os
import csv

from ScanTaskModel.models import ScanTask
from ServiceScanModel.models import ServiceScan
from VulnScanModel.models import VulnScan
from IpModel.models import IpScan


def export_file(task_id, mode):
    temp_file = open(os.getcwd() + "/vulscan_Project/temp/temp_csv.csv", "wb")
    if mode == "service":
        data_list = ServiceScan.objects.filter(taskid=task_id)
        field_names = [i.name for i in ServiceScan._meta.fields]
    elif mode == "vuln":
        data_list = VulnScan.objects.filter(taskid=task_id)
        field_names = [i.name for i in VulnScan._meta.fields]
    else:
        data_list = IpScan.objects.filter(taskid=task_id)
        field_names = [i.name for i in IpScan._meta.fields]
    temp_file.write((",".join(field_names) + "\n").encode())
    for i in data_list:
        temp_file.write((",".join([str(getattr(i, j)) for j in field_names])).encode()+b"\n")
    temp_file.close()
    temp_file = open(os.getcwd() + "/vulscan_Project/temp/temp_csv.csv", "rb")
    csv_data = temp_file.read()
    return csv_data


def open_file(filename, mode="r", dir="dict"):
    return open(os.getcwd() + "/vulscan_Project/%s/%s" % (dir, filename), mode)


def get_burp_list(module):
    user_file = open_file(f"dict_{module}/dic_username_{module}.txt", "r")
    pwd_file = open_file(f"dict_{module}/dic_password_{module}.txt", "r")
    burp_list = []
    user_list = [i.strip() for i in user_file.readlines()]
    pwd_list = [i.strip() for i in pwd_file.readlines()]
    for u in user_list:
        if not u:
            continue
        for p in pwd_list:
            p = p.replace("%user%", u)
            burp_list.append((u.strip(), p.strip()))
    return burp_list
