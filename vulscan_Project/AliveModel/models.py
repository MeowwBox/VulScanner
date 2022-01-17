from django.db import models

class AliveScan(models.Model):
    taskid = models.IntegerField(default=1)
    ip = models.CharField(max_length=50)
    flag = models.IntegerField(default=0)
    mode = models.CharField(max_length=50, default="")
    group = models.IntegerField(default=0)
    isShown = models.BooleanField(default=False)