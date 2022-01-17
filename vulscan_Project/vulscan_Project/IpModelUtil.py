import html
import re

from ScanTaskModel.models import ScanTask
from IpModel.models import IpScan
from AliveModel.models import AliveScan
from . import requestUtil, AliveModelUtil

api_url = "https://ip.bmcx.com/?dz="



def ip_scan(location):
    location = html.escape(location)
    resp = requestUtil.get(api_url + location)
    results = (re.findall(
        '<td height="25" bgcolor="#FFFFFF" style="text-align: center">(.*?)</td><td bgcolor="#FFFFFF" style="text-align: center">(.*?)</td>',
        resp.text))
    task = ScanTask(ip_range=location, task_count=len(results), mode="ip")
    task.save()
    tid = task.id
    count = 0
    try:
        for i in results:
            count += 1
            ipscan = IpScan(ip=i[0], location=i[1], taskid=tid)
            ipscan.save()
            task.service_process += 1
    finally:
        task.save()
    return True

