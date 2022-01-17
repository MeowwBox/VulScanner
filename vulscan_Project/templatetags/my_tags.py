from django import template
import math

register = template.Library()


@register.filter
def text2html(v1: str):
    return v1.replace("\n", "<br>").replace(" ", "&nbsp;").replace("\t", "&nbsp" * 4)


@register.filter
def contain(v1: str, v2: str):
    if v2 in v1:
        return True


@register.filter
def url(v1: str):
    if v1 == "":
        return "javascript:void(0)"


@register.filter
def get_dict(v1: dict, v2: str):
    return v1[v2]


@register.filter
def opposite(v1: bool):
    return not bool


@register.filter
def cutdown(v1: str):
    v1_list = v1.split(',')
    return ', '.join(v1_list[:5]) + " ... " + ', '.join(v1_list[-5:])


@register.filter
def get_ip_num(ip: str):
    ip_num = 1
    if "-" in ip:
        ip_range = [i.strip() for i in ip.split("-")]
        for i in range(0, 2):
            ip_n = ip_range[i].split(".")
            for j in range(0, 4):
                ip_num += (math.pow(-1, i + 1) * math.pow(256, 3 - j) * int(ip_n[j]))
    ip_num = int(ip_num)
    return ip_num
