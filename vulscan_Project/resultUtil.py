from AliveModel.models import AliveScan
from IpModel.models import IpScan


def get_ips(query, page=0, each_num=0, mode="ip"):
    if mode == "ip":
        if page == 0:
            ip_list = IpScan.objects.extra(where=[query])
        else:
            ip_list = IpScan.objects.extra(where=[query])[(page - 1) * each_num:page * each_num]
    else:
        if page == 0:
            ip_list = AliveScan.objects.extra(where=[query])
        else:
            ip_list = AliveScan.objects.extra(where=[query])[(page - 1) * each_num:page * each_num]
    return ip_list


def get_count(task_id, page=0, each_num=0):  # 获取结果集总数
    try:
        query = "1=1"
        query += " and taskid=%s" % (task_id)
        ip_list = get_ips(query, page, each_num)
        return ip_list.count()
    except:
        return 0


def get_results(task_id, isAll=False, page=0, each_num=0, mode="ip"):  # 获取扫描结果，isAll=True获取所有结果，否则获取未显示结果
    result_list = []
    if isAll:
        query = "1=1"
    else:
        query = "isShown=False"
    query += " and taskid=%s" % (task_id)
    ip_list = get_ips(query, page, each_num, mode=mode)
    for i in ip_list:
        result_list.append(i)
        i.isShown = True
        i.save()
    return result_list