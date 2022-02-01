# Tawannnnnnnn :)
# modbus_ida - app.py
# Webapp update checker.

import os
import time
import stat
import shutil


CURRENT_DIRECTORY = os.path.dirname(os.path.abspath(__file__))

VERSION = os.path.join(CURRENT_DIRECTORY, "version.txt")
WEBAPP_FOLDER = os.path.join(CURRENT_DIRECTORY, "webapp", "")
MODBUS_IDA = os.path.join(CURRENT_DIRECTORY, "ida-modbus-reader", "")
APPFILE = os.path.join(CURRENT_DIRECTORY, "webapp", "webapp.py")
GIT_FOLDER = os.path.join(CURRENT_DIRECTORY, "ida-modbus-reader", ".git", "")
WEBAPP_TEMP = os.path.join(CURRENT_DIRECTORY, "ida-modbus-reader", "webapp", "")
REQ = os.path.join(CURRENT_DIRECTORY, "webapp" ,"req", "requirements.txt")

# pip install.
def pipUpdate():
    try:
        os.system('pip install -r ' + REQ)
    except:
        pass

# Test connection between device and github using ICMP.
def githubChecker():
    import pyping
    githubLoopChecker = True
    while githubLoopChecker == True:
        try:
            r = pyping.ping('www.github.com')
            if r.ret_code == 0:
                print("done")
                githubLoopChecker = False
            else:
                print("sth")
                pass

        except:
            print("githubChecker() failed")
            time.sleep(5)

# Check for update fucntion.
def updateChecker():
    import git
    import requests
    try:
        #response = requests.get('https://raw.githubusercontent.com/idaplatform/modbus_ida/master/version.txt')
        response = requests.get('https://raw.githubusercontent.com/erdtch/ida-modbus-reader/master/version.txt')
        # Note: data = version.txt on github | txt = version.txt on your device.
        data = response.text
        data = str(data)
        data = data[:-1]
        f = open(VERSION, "r")
        txt = f.read()
        f.close()
        txt = txt[:-1]
        if data != txt:
            # chmod 7xx
            for root, dirs, files in os.walk(GIT_FOLDER):
                for dir in dirs:
                    os.chmod(os.path.join(root, dir), stat.S_IRWXU)
                for file in files:
                    os.chmod(os.path.join(root, file), stat.S_IRWXU)
            # Remove old directories then clone repo from github.
            shutil.rmtree(MODBUS_IDA, ignore_errors=True)
            shutil.rmtree(WEBAPP_FOLDER, ignore_errors=True)
            os.mkdir(WEBAPP_FOLDER)
            git.Git(CURRENT_DIRECTORY).clone("https://github.com/erdtch/ida-modbus-reader.git")
            # Replace old version.txt with new version.txt
            os.remove(VERSION)
            shutil.move(os.path.join(MODBUS_IDA, "version.txt"), CURRENT_DIRECTORY)
            for file in os.listdir(WEBAPP_TEMP):
                shutil.move(os.path.join(WEBAPP_TEMP, file), WEBAPP_FOLDER)
    except:
        pass

if __name__ == '__main__':
    pipUpdate()
    #githubChecker()
    #updateChecker()
    os.system('python '+ APPFILE)
