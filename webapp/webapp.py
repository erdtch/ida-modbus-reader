"""
    Tawannnnnnnn :)
    modbus_ida - webapp.py
    Main Python scripts for web application & modbus TCP/IP reader from NECTEC's uRCONNECT.
"""

import os
import re
import time
import json
import random
import string
import pyping
import logging
import requests
import platform
import win_inet_pton
import mysql.connector as MySQL

from threading import Thread
from pytz import timezone, utc
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
from ConfigParser import SafeConfigParser
from pyModbusTCP.client import ModbusClient
from logging.handlers import RotatingFileHandler
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, login_required ,UserMixin, login_user, logout_user, current_user
from flask import Flask, render_template, request, redirect, url_for, flash, url_for, redirect, session

CURRENT_DIRECTORY = os.path.dirname(os.path.abspath(__file__))
APP_CONFIG = os.path.join(os.path.dirname(CURRENT_DIRECTORY), "app_config.ini")
KEY = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cert", "key.pem")
CERT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cert", "cert.pem")
LOGFILE_DIR = os.getenv("CAF_APP_LOG_DIR", "/tmp")

appconfig = SafeConfigParser()
appconfig.read(APP_CONFIG)

def setup_logging():
    """
    Setup logging for the current module and dependent libraries based on
    values available in config.
    """
    # Set a format which is simpler for console use
    formatter = logging.Formatter('[%(asctime)s] %(levelname)-8s> %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

    # Set log level based on what is defined in package_config.ini file
    loglevel = appconfig.getint("LOGGING", "log_level")
    logger.setLevel(loglevel)

    # Create a console handler only if console logging is enabled
    ce = appconfig.getboolean("LOGGING", "console")
    if ce:
        console = logging.StreamHandler()
        console.setLevel(loglevel)
        console.setFormatter(formatter)
        # Add the handler to the root logger
        logger.addHandler(console)

    def customTime(*args):
        utc_dt = utc.localize(datetime.utcnow())
        my_tz = timezone("Asia/Bangkok")
        converted = utc_dt.astimezone(my_tz)
        return converted.timetuple()

    logging.Formatter.converter = customTime

    # The default is to use a Rotating File Handler

    if platform.system() == "Windows":
        log_file_path = os.path.join(CURRENT_DIRECTORY, "modbus_app.log")
    else:
        log_file_path = os.path.join(LOGFILE_DIR, "modbus_app.log")

    # Define cap of the log file at 1 MB x 3 backups
    rfh = RotatingFileHandler(log_file_path, maxBytes=3096*3096, backupCount=3)
    rfh.setLevel(loglevel)
    rfh.setFormatter(formatter)
    logger.addHandler(rfh)

logger = logging.getLogger("modbus_ida")
setup_logging()

DB_USERNAME = appconfig.get('SQLALCHEMY_CONFIG', 'username')
DB_PASSWORD = appconfig.get('SQLALCHEMY_CONFIG', 'password')
DB_IP = appconfig.get('SQLALCHEMY_CONFIG', 'ip')
DB_PORT = appconfig.get('SQLALCHEMY_CONFIG', 'port')
DB_SCHEMA = appconfig.get('SQLALCHEMY_CONFIG', 'schema')
NEXPIE_URL = appconfig.get('NEXPIE', 'shadow_url')

# Test connection and connect to database server.
# Initialize application.
initChecker = True
while initChecker == True:
    r = pyping.ping('203.150.37.154')
    if r.ret_code == 0:
        try:
          connection = MySQL.connect(host= DB_IP,
                                     user = DB_USERNAME,
                                     passwd = DB_PASSWORD,
                                     port = DB_PORT)
          cursor = connection.cursor()
          executeCommand = "CREATE DATABASE IF NOT EXISTS " + DB_SCHEMA
          cursor.execute(executeCommand)
          connection.commit()
          connection.close()

          app = Flask(__name__)
          db = SQLAlchemy()
          db.pool_recycle = 300
          app.config['SECRET_KEY'] = appconfig.get('APP_INIT', 'secretkey')
          app.config['SQLALCHEMY_DATABASE_URI'] = "mysql://" + DB_USERNAME + ":" + DB_PASSWORD + "@" + DB_IP + ":" + DB_PORT + "/" + DB_SCHEMA
          app.config["SQLALCHEMY_POOL_SIZE"] = 20
          app.config['PERMANENT_SESSION_LIFETIME'] =  timedelta(minutes=5)
          app.config['SESSION_REFRESH_EACH_REQUEST'] = True

          db.init_app(app)

          login_manager = LoginManager()
          login_manager.login_view = 'login'
          login_manager.init_app(app)

        except Exception as e:
          logger.error("Exception occurred", exc_info=True)
        initChecker = False
    else:
        logger.info("Ping database server: Failed")

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True) # primary keys are required by SQLAlchemy
    username = db.Column(db.String(20), unique=True)
    password = db.Column(db.String(30))
    name = db.Column(db.String(100))

@app.before_request
def func():
    if not request.is_secure:
        url = request.url.replace('http://', 'https://', 1)
        code = 301
        return redirect(url, code=code)

@login_manager.user_loader
def load_user(user_id):
    # since the user_id is just the primary key of our user table, use it in the query for the user.
    return User.query.get(int(user_id))

# Establish MySQL connection to database server.
def databaseConnection():
    connection = MySQL.connect(host= DB_IP,
                           user = DB_USERNAME,
                           passwd = DB_PASSWORD,
                           port = DB_PORT,
                           db = DB_SCHEMA)
    return connection

# Load uRCONNECT default config from database server.
def urconnectSettings():
    connection = MySQL.connect(host= DB_IP,
                           user = DB_USERNAME,
                           passwd = DB_PASSWORD,
                           port = DB_PORT,
                           db = "urconnect_settings")
    return connection

# Change web application's credentials.
def changePassword(encryptedPassword, name):
    connection = databaseConnection()
    cursor = connection.cursor()
    executeCommand = "UPDATE user SET password = %s WHERE name = %s"
    cursor.execute(executeCommand, (encryptedPassword, name,))
    connection.commit()
    try:
        connection.close()
    except:
        pass

# Delete registered device from database.
def deleteConfig(ip):
    connection = databaseConnection()
    cursor = connection.cursor()
    executeCommand = "DELETE FROM config WHERE ip = %s"
    cursor.execute(executeCommand, (ip,))
    connection.commit()
    executeCommand = "DELETE FROM address_mapping WHERE ip = %s"
    cursor.execute(executeCommand, (ip,))
    connection.commit()
    executeCommand = "UPDATE config SET tablinks = %s LIMIT 1"
    cursor.execute(executeCommand, ("tablinks active",))
    connection.commit()
    try:
        connection.close()
    except:
        pass

# Check table "address_mapping" on database.
def checkAddressMapping():
    connection = databaseConnection()
    cursor = connection.cursor()
    try:
        cursor.execute("SELECT * FROM address_mapping LIMIT 1")
        result = cursor.fetchall()
        if result != []:
            return("Passed")
    except:
        cursor.execute("SHOW TABLES like 'address_mapping'")
        result = cursor.fetchall()
        if result != []:
            return("Passed")
        else:
            return("Not Passed")

    try:
        connection.close()
    except:
        pass

"""
    Create table "address_mapping" if it isn't exists.
    * id = PK, id number
    * unitid = unitid of uRCONNECT
    * module = module of uRCONNECT (1down, 2up, 2down, 3up, 3down)
    * channel = module's channel of uRCONNECT (1-8)
    * type = modbus function code (1-4)
    * name = sensor name (you can change if you need.)
    * startingAddress = starting address that script need to read from uRCONNECT.
    * quantity = amount of address that script need to read from uRCONNECT. (e.g. 00001, 2 = read from address 00001 to 00002)
    * ip = ip address is ip address, yeah I mean it.
    * displayAddress = address that you can see from uRCONNECT documents.
    * cardtype = card type (e.g. 4-20mA, digital input, relay)
    * html**** = position in html file using Jinja template.
"""
def createAddressMapping():
    connection = databaseConnection()
    cursor = connection.cursor()
    executeCommand = ("CREATE TABLE IF NOT EXISTS address_mapping (id INT NOT NULL AUTO_INCREMENT PRIMARY KEY, unitid VARCHAR(2) NOT NULL, module VARCHAR(5) NOT NULL, "
    "channel VARCHAR(1) NOT NULL, type VARCHAR(2) NOT NULL, name VARCHAR(30) NOT NULL, startingAddress VARCHAR(5) NOT NULL, "
    "quantity VARCHAR(5) NOT NULL, ip VARCHAR(15) NOT NULL, htmlmodule VARCHAR(20) NOT NULL, htmlchannel VARCHAR(20) NOT NULL, htmltype VARCHAR(20) NOT NULL, "
    "htmlname VARCHAR(20) NOT NULL, htmlstart VARCHAR(20) NOT NULL, htmlquantity VARCHAR(20) NOT NULL, htmltypeselector VARCHAR(20) NOT NULL, displayAddress VARCHAR(6) NOT NULL, cardtype VARCHAR(20) NOT NULL)")
    cursor.execute(executeCommand)
    connection.commit()
    try:
        connection.close()
    except:
        pass

# Get default power meter address from database.
def getPowermeter():
    connection = urconnectSettings()
    cursor = connection.cursor()
    executeCommand = "SELECT name, startingAddress, quantity FROM powermeter"
    cursor.execute(executeCommand)
    result = cursor.fetchall()
    try:
        connection.close()
    except:
        pass
    return result

"""
    Create table "nexpie_auth" if it isn't exists.
    * name = NEXPIE device name (it's just a name, don't mind)
    * clientid = NEXPIE device's client id
    * token = NEXPIE device's username (display as token on nexpie.io)
    * secret = NEXPIE device's password (display as secret on nexpie.io)
"""
def createNexpieAuth():
    connection = databaseConnection()
    cursor = connection.cursor()
    executeCommand = "CREATE TABLE IF NOT EXISTS nexpie_auth (id INT NOT NULL AUTO_INCREMENT PRIMARY KEY, name VARCHAR(20) NOT NULL, clientid VARCHAR(36) NOT NULL, token VARCHAR(32) NOT NULL, secret VARCHAR(32) NOT NULL)"
    cursor.execute(executeCommand)
    connection.commit()
    executeCommand = "SELECT * FROM nexpie_auth"
    cursor.execute(executeCommand)
    result = cursor.fetchall()
    if result == []:
        executeCommand = "INSERT INTO nexpie_auth (name, clientid, token, secret) VALUES (%s, %s, %s, %s)"
        cursor.execute(executeCommand, (("result", "", "", "")))
        connection.commit()
    executeCommand = "SELECT clientid, token, secret FROM nexpie_auth"
    cursor.execute(executeCommand)
    result = cursor.fetchall()
    try:
        connection.close()
    except:
        pass
    return result

"""
    Create table "user" if it isn't exists.
    If table return null then create user using username, password and name from app_config.ini
    * username = username for login to web application.
    * name = factory name.
    * password = password for login to web application.
"""
def createUser():
    connection = databaseConnection()
    cursor = connection.cursor()
    executeCommand = "CREATE TABLE IF NOT EXISTS user (id INT NOT NULL AUTO_INCREMENT PRIMARY KEY, username VARCHAR(20) NOT NULL UNIQUE, password VARCHAR(100) NOT NULL, name VARCHAR(45) NOT NULL UNIQUE)"
    cursor.execute(executeCommand)
    connection.commit()
    executeCommand = "SELECT * FROM user"
    cursor.execute(executeCommand)
    result = cursor.fetchall()
    if result == []:
        USERNAME = appconfig.get('LOGIN', 'username')
        PASSWORD = appconfig.get('LOGIN', 'password')
        NAME = appconfig.get('LOGIN', 'name')
        ENCRYPTED = generate_password_hash(PASSWORD, method='sha256')
        executeCommand = "INSERT INTO user (username, password, name) VALUES (%s, %s, %s)"
        cursor.execute(executeCommand, (USERNAME, ENCRYPTED, NAME,))
        connection.commit()
    try:
        connection.close()
    except:
        pass

"""
    Create table "config" if it isn't exists.
    * unitid = uRCONNECT's unit id.
    * ip = uRCONNECT's ip address.
    * note = **deprecated**
    * status = enable or disable
    * tablinks = tablinks active or tablinks (tablinks active will active after load config page (index.html))
    * name = uRCONNECT's name
    * html**** = position in html file using Jinja template.
"""
def getConfigData():
    connection = databaseConnection()
    cursor = connection.cursor()
    executeCommand = ("CREATE TABLE IF NOT EXISTS config (id INT NOT NULL AUTO_INCREMENT PRIMARY KEY, unitid VARCHAR(2) NOT NULL, ip VARCHAR(15) NOT NULL,"
    "note VARCHAR(15) NOT NULL, status VARCHAR(10) NOT NULL, tablinks VARCHAR(40) NOT NULL, name VARCHAR(20) NOT NULL, htmltab VARCHAR(15) NOT NULL,"
    "htmlip VARCHAR(15) NOT NULL, htmlunitid VARCHAR(20) NOT NULL, htmlcheckbox VARCHAR(15) NOT NULL, htmloldunitid VARCHAR(15) NOT NULL, htmloldip VARCHAR(15) NOT NULL, htmldevicename VARCHAR(30),  htmloldname VARCHAR(30))")
    cursor.execute(executeCommand)
    connection.commit()
    executeCommand = "SELECT * FROM config"
    cursor.execute(executeCommand)
    data = cursor.fetchall()
    try:
        connection.close()
    except:
        pass
    return data

# Get value that define tab(s) in config page.
def getTab():
    connection = databaseConnection()
    cursor = connection.cursor()
    executeCommand = "SELECT tablinks, htmltab, name FROM config WHERE note = %s"
    cursor.execute(executeCommand, ("config",))
    result = cursor.fetchall()
    return result

# Get value that define unitid in config page.
def getHtmlUnitid():
    connection = databaseConnection()
    cursor = connection.cursor()
    executeCommand = "SELECT htmlunitid FROM config WHERE note = %s"
    cursor.execute(executeCommand, ("config",))
    result = cursor.fetchall()
    return result

# Add new uRCONNECT to database.
def newDevice(ip, unitid, checkbox, devicename):
    # Note: enabled = get value from uRCONNECT, convert to json and send to NEXPIE.
    if checkbox != "enabled":
        checkbox = "disabled"
    connection = databaseConnection()
    cursor = connection.cursor()
    executeCommand = "SELECT * FROM config"
    cursor.execute(executeCommand)
    result = cursor.fetchall()
    # Note: tablinks active = show this tab after GET config page (index.html)
    if result == []:
        number = str(0)
        tablinks = "tablinks active"
    else:
        executeCommand = "SELECT id FROM config ORDER BY id DESC LIMIT 1"
        cursor.execute(executeCommand)
        result = cursor.fetchall()
        number = str(result[0][0])
        tablinks = "tablinks"
    stringunitid = "UnitID:" + str(unitid)
    htmltab = "unitid" + number
    htmlip = "ip" + number
    htmlunitid = "id_unitid" + number
    htmlcheckbox = "checkbox" + number
    htmloldunitid = "oldunitid" + number
    htmloldip = "oldip" + number
    htmldevicename = "devicename" + number
    htmloldname = "oldname" + number
    executeCommand = ("INSERT INTO config (unitid, ip, note, status, tablinks, name,"
    "htmltab, htmlip, htmlunitid, htmlcheckbox, htmloldunitid, htmloldip, htmldevicename, htmloldname) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)")
    cursor.execute(executeCommand, (unitid, ip, "config", checkbox, tablinks, devicename, htmltab, htmlip, htmlunitid, htmlcheckbox, htmloldunitid, htmloldip, htmldevicename, htmloldname))
    connection.commit()
    try:
        connection.close()
    except:
        pass
"""
    * Get last id from table "address_mapping".
    * We need latest id to generate next id for uRCONNECT address.
    * e.g. addressMappingLastrow() return 39, id for next 1down from new device is 40 ...
"""

def addressMappingLastrow():
    connection = databaseConnection()
    cursor = connection.cursor()
    executeCommand = "SELECT * FROM address_mapping"
    cursor.execute(executeCommand)
    result = cursor.fetchall()
    if result == []:
        number = 0
    else:
        executeCommand = "SELECT id FROM address_mapping ORDER BY id DESC LIMIT 1"
        cursor.execute(executeCommand)
        result = cursor.fetchall()
        number = result[0][0]
    try:
        connection.close()
    except:
        pass
    return number

# Update uRCONNECT's config (ip, unitid, device name, status enable or disable) to database
def updateConfig(ip, unitid, devicename, oldunitid, oldip, oldname, checkbox):
    if checkbox != "enabled":
        checkbox = "disabled"
    connection = databaseConnection()
    cursor = connection.cursor()
    executeCommand = "UPDATE address_mapping SET ip = %s, unitid = %s WHERE unitid = %s and ip = %s"
    cursor.execute(executeCommand, (ip, unitid, oldunitid, oldip))
    connection.commit()
    executeCommand = "UPDATE config SET ip = %s, unitid = %s, name = %s, status = %s WHERE unitid = %s and ip = %s and name = %s"
    cursor.execute(executeCommand, (ip, unitid, devicename, checkbox, oldunitid, oldip, oldname))
    connection.commit()
    executeCommand = "SELECT htmlname FROM address_mapping WHERE ip = %s" # We only need length of unitid = %s
    cursor.execute(executeCommand, (ip,))
    result = cursor.fetchall()
    return result

# Update NEXPIE credentials to database.
def updateNexpieCredentials(command,clientid,token,secret):
    connection = databaseConnection()
    cursor = connection.cursor()
    executeCommand = "UPDATE nexpie_auth SET clientid = %s, token = %s, secret = %s WHERE name = %s"
    cursor.execute(executeCommand, (clientid, token, secret, command))
    connection.commit()
    connection.close()

# Check type and correction of input before update to database.
def inputChecker(ip, unitid, devicename, oldip, oldunitid, oldname):
    if ip == "":
        return("Failed: IP address cannot be blank.")
    if unitid == "":
        return("Failed: Unit id or device name cannot be blank.")
    if devicename == "":
        return("Failed: Device name cannot be blank.")
    connection = databaseConnection()
    cursor = connection.cursor()
    executeCommand = "SELECT id FROM config WHERE ip = %s and unitid = %s and name = %s"
    cursor.execute(executeCommand, (oldip, oldunitid, oldname))
    result = cursor.fetchall()
    id = result[0][0]
    executeCommand = "SELECT ip FROM config WHERE ip = %s and id <> %s"
    cursor.execute(executeCommand, (ip, id))
    result = cursor.fetchall()
    if result != []:
        return("Failed: The IP address '" + ip + "' is already used in database.")
    executeCommand = "SELECT unitid FROM config WHERE unitid = %s and id <> %s"
    cursor.execute(executeCommand, (unitid, id))
    result = cursor.fetchall()
    if result != []:
        return("Failed: The unit id '" + unitid + "' is already used in database.")
    executeCommand = "SELECT name FROM config WHERE name = %s and id <> %s"
    cursor.execute(executeCommand, (devicename, id))
    result = cursor.fetchall()
    if result != []:
        return("Failed: The name '" + devicename + "' is already used in database.")
    return("Passed")

# Check type and correction of input before add new device to database.
def inputCheckerNewDevice(ip, unitid, devicename):
    if ip == "":
        return("Failed: IP address cannot be blank.")
    if unitid == "":
        return("Failed: Unit id or device name cannot be blank.")
    if devicename == "":
        return("Failed: Device name cannot be blank.")
    connection = databaseConnection()
    cursor = connection.cursor()
    executeCommand = "SELECT ip FROM config WHERE ip = %s"
    cursor.execute(executeCommand, (ip,))
    result = cursor.fetchall()
    if result != []:
        return("Failed: The IP address '" + ip + "' is already used in database.")
    executeCommand = "SELECT unitid FROM config WHERE unitid = %s"
    cursor.execute(executeCommand, (unitid,))
    result = cursor.fetchall()
    if result != []:
        return("Failed: The unit id '" + unitid + "' is already used in database.")
    executeCommand = "SELECT name FROM config WHERE name = %s"
    cursor.execute(executeCommand, (devicename,))
    result = cursor.fetchall()
    if result != []:
        return("Failed: The name '" + devicename + "' is already used in database.")
    return("Passed")

# Check correction of client id before update to database.
def clientidChecker(clientid):
    for i in range(0, len(clientid)):
        if i == 8 or i == 13 or i == 18 or i == 23:
            if clientid[i] != "-":
                return False
        else:
            if clientid[i] == "-":
                return False
    return True

# Check connection between application and uRCONNCET before update to database.
def checkUrconnect(ip, unitid):
    PORT_NUMBER = 502
    try:
        client = ModbusClient(auto_open=True, timeout=3, host=ip, port=PORT_NUMBER, unit_id=unitid, debug=True)
        client.host(ip)
        client.port(PORT_NUMBER)
        client.unit_id(unitid)
        client.debug()
        if not client.is_open():
            if not client.open():
                return("Failed: Can't connect to " + ip + ", unit id " + unitid)
        if client.is_open():
                return("Passed")
    except:
        return("Failed: Can't connect to " + ip + ", unit id " + unitid)

# Read type of card's address from uRCONNECT.
def readCard(ip, unitid):
    PORT_NUMBER = 502
    client = ModbusClient(auto_open=True, timeout=3, host=ip, port=PORT_NUMBER, unit_id=unitid, debug=True)
    client.host(ip)
    client.port(PORT_NUMBER)
    client.unit_id(unitid)
    client.debug()
    if not client.is_open():
        if not client.open():
            return("Failed: Can't connect to " + ip + ", unit id " + unitid)
    # if open() is ok, read register (modbus function 0x03)
    if client.is_open():
        data = client.read_holding_registers(501, 5)
        for i in range(0,len(data)):
            if data[i] not in [80, 81, 82, 83, 84, 85, 86, 87, 0]:
                data[i] = 0
        return data

# Get modbus function from database using card type.
def getModbusType(name,cardList):
    connection = MySQL.connect(host= DB_IP,
                           user = DB_USERNAME,
                           passwd = DB_PASSWORD,
                           port = DB_PORT,
                           db = "urconnect_settings")
    cursor = connection.cursor()
    typeList = []
    moduleList = ["1down", "2up", "2down", "3up", "3down"]
    resultList = []
    for i in range (0, len(cardList)):
        cursor = connection.cursor()
        executeCommand = "SELECT type, cardtype FROM cardtype WHERE value = %s" #cardType = result[0][1]
        cursor.execute(executeCommand, (cardList[i],))
        cardtypeList = cursor.fetchall()
        executeCommand = "SELECT * FROM urconnect_address WHERE type = %s AND module = %s"
        cursor.execute(executeCommand, (cardtypeList[0][0], moduleList[i],))
        result = cursor.fetchall()
        for i in range (0, len(result)):
            result[i] = result[i] + (cardtypeList[0][1],)
            resultList.append(result[i])
    try:
        connection.close()
    except:
        pass
    return resultList

"""
    GET index.html
    * Display current uRCONNECT's config.
"""
@app.route("/index")
@login_required
def index():
    # Check table "address_mapping"
    result = checkAddressMapping()
    if result == "Not Passed":
        createAddressMapping()
    connection = databaseConnection()
    data = getConfigData()
    tab = getTab()
    cursor = connection.cursor()
    executeCommand = "SELECT * FROM address_mapping"
    cursor.execute(executeCommand)
    result = cursor.fetchall()
    connection.close()
    return render_template('index.html', name=current_user.name, result=result, tab=tab, data=data)

"""
    POST index.html
    * Update uRCONNECT's config.
"""
@app.route("/index", methods=['POST'])
@login_required
def index_post():
    name = current_user.name
    htmlUnitid = getHtmlUnitid()
    for i in range (0,len(htmlUnitid)):
        temp = request.form.get(htmlUnitid[i][0])
        if temp != None:
            strUnitid = str(htmlUnitid[i][0])
            number = strUnitid.replace("id_unitid","")
            unitid = temp
            number = str(htmlUnitid[i][0]).replace("id_unitid", "")
            ipForm = "ip" + str(number)
            ip = request.form.get(ipForm)
            oldunitidForm = "oldunitid" + str(number)
            oldunitid = request.form.get(oldunitidForm)
            oldipForm = "oldip" + str(number)
            oldip = request.form.get(oldipForm)
            oldnameForm = "oldname" + str(number)
            oldname = request.form.get(oldnameForm)
            checkboxForm = "checkbox" + str(number)
            checkbox = request.form.get(checkboxForm)
            devicenameForm = "devicename" + str(number)
            devicename = request.form.get(devicenameForm)
    checked = checkUrconnect(ip, unitid)
    if checked != "Passed":
        flash(checked)
        return redirect('index')
    checked = inputChecker(ip, unitid, devicename, oldip, oldunitid, oldname)
    if checked != "Passed":
        flash(checked)
        return redirect('index')
    result = updateConfig(ip, unitid, devicename, oldunitid, oldip, oldname, checkbox)
    connection = databaseConnection()
    cursor = connection.cursor()
    for i in range(0, len(result)):
        name = request.form.get(result[i][0])
        if name == "":
            pass
        else:
            executeCommand = "UPDATE address_mapping SET name = %s WHERE htmlname = %s"
            cursor.execute(executeCommand, (name, result[i][0],))
            connection.commit()
    try:
        connection.close()
    except:
        pass
    flash("Updated Successfully")
    logger.info('User: ' + current_user.name + ' - "' + devicename + '" updated.')
    return redirect('index')

"""
    GET powermeter.html
    * Display powermeter's address that use in IDA Platform.
"""
@app.route("/powermeter")
@login_required
def powermeter():
    data = getPowermeter()
    return render_template("powermeter.html", name=current_user.name, data=data)

"""
    POST newdevice, GET index.html
    * Add new uRCONNECT to database.
"""
@app.route("/newdevice", methods=['POST'])
@login_required
def newdevice_post():
    ip = request.form.get("newip")
    unitid = request.form.get("newunitid")
    checkbox = request.form.get("newcheckbox")
    devicename = request.form.get("newdevicename")
    checked = inputCheckerNewDevice(ip, unitid, devicename)
    if checked != "Passed":
        flash(checked)
        return redirect('index')
    try:
        cardList = readCard(ip, unitid)
    except:
        cardList = "Failed: Can't connect to " + ip + ", unit id " + unitid
    if cardList == "Failed: Can't connect to " + ip + ", unit id " + unitid:
        flash(cardList)
        return redirect('index')
    newDevice(ip, unitid, checkbox, devicename)
    lastrow = addressMappingLastrow()
    resultList = getModbusType("urconnect_settings", cardList)
    channelMarker = ""
    connection = databaseConnection()
    cursor = connection.cursor()
    for i in range(0, len(resultList)): #
        strCounter = str(i + lastrow)
        name = "ch" + str(resultList[i][2]) + "_" + str(resultList[i][1])
        htmlchannel = "channel" + str(i)
        if resultList[i][2] == "1":
            channelMarker = str(strCounter)
        htmlmodule = "module" + strCounter
        htmlchannel = "channel" + strCounter
        htmltype = "type" + strCounter
        htmlname = "name" + strCounter
        htmlstart = "start" + strCounter
        htmlquantity = "quantity"  + strCounter
        htmltypeselector = "typeselector" + channelMarker
        executeCommand = ("INSERT INTO address_mapping (unitid, module, channel, type, name, startingAddress, quantity, ip, htmlmodule, "
        "htmlchannel, htmltype, htmlname, htmlstart, htmlquantity, htmltypeselector, displayAddress, cardtype) VALUES ( %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)")
        cursor.execute(executeCommand, (unitid, resultList[i][1], resultList[i][2], resultList[i][0], name, resultList[i][3], resultList[i][4], ip, htmlmodule, htmlchannel, htmltype, htmlname, htmlstart, htmlquantity, htmltypeselector, resultList[i][5], resultList[i][6]))
    connection.commit()
    try:
        connection.close()
    except:
        pass
    flash('"' + devicename + '" added successfully.')
    logger.info('User: ' + current_user.name + ' - ' + devicename + "(" + ip + ", " + unitid + ') added to database.')
    return redirect('index')

"""
    GET credentials.html
    * Display current NEXPIE credentials.
"""
@app.route("/credentials")
@login_required
def credentials():
    result = createNexpieAuth()
    return render_template('credentials.html', name=current_user.name, result=result)

"""
    POST credentials.html
    * Update NEXPIE credential to database.
"""
@app.route("/credentials", methods=['POST'])
@login_required
def credentials_post():
    name = current_user.name
    resultClientID = request.form.get("resultClientID")
    resultToken = request.form.get("resultToken")
    resultSecret = request.form.get("resultSecret")
    resultCheckbox = request.form.get("resultCheckbox")
    if resultCheckbox == "result" and len(resultClientID) == 36 and len(resultToken) == 32 and len(resultSecret) == 32:
        resultChecker = clientidChecker(resultClientID)
        if resultChecker == True:
            updateNexpieCredentials(resultCheckbox,resultClientID,resultToken,resultSecret)
            flash("Nexpie credentials updated successfully.")
            logger.info('User: ' + current_user.name + ' - Update NEXPIE credentials.')
            logger.info('User: ' + current_user.name + ' - Clientid (' + resultClientID + ') updated.')
            logger.info('User: ' + current_user.name + ' - Token (' + resultToken + ') updated.')
            logger.info('User: ' + current_user.name + ' - Secret (' + resultSecret + ') updated.')
        else:
            flash("Failed: Please recheck client id format.")
    elif len(resultClientID) != 36:
        flash("Failed: Client ID must be 36 characters.")
    elif len(resultToken) != 32:
        flash("Failed: Token must be 32 characters.")
    elif len(resultSecret) != 32:
        flash("Failed: Secret must be 32 characters.")
    return redirect('credentials')

@app.route('/')
def page():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    else:
        return redirect(url_for('login'))

"""
    GET login.html
    * Display web application login page.
"""
@app.route('/login')
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    else:
        return render_template("login.html")

"""
    POST login.html
    * Get username and password from HTML form and check matching between form and database.
"""
@app.route('/login', methods=['POST'])
def login_post():
    # Get username and password from login form.
    username = request.form.get('username')
    password = request.form.get('password')
    # Query username and password in database.
    user = User.query.filter_by(username=username).first()
    if not user or not check_password_hash(user.password, password):
        flash('Please check your login details and try again.')
        return redirect(url_for('login')) # if the user doesn't exist or password is wrong, reload the page.
    login_user(user)
    logger.info('User: ' + current_user.name + ' - Successfully logged in.')
    return redirect(url_for('index'))

"""
    POST deleteconfig, GET index.html
    * Delete uRCONNECT from database.
"""
@app.route('/deleteconfig', methods=['POST'])
@login_required
def deleteconfig_post():
    ip = request.form.get('ipaddr')
    devicename = request.form.get('current_devicename')
    deleteConfig(ip)
    flash('"' + devicename + '" deleted successfully.')
    logger.info('User: ' + current_user.name + ' - "' + str(devicename) + '" deleted successfully.')
    return redirect(url_for('index'))

"""
    GET user.html
    * Display current log and password changer page.
"""
@app.route('/user')
@login_required
def user():
    if platform.system() == "Windows":
        logpath = os.path.join(CURRENT_DIRECTORY, "modbus_app.log")
    else:
        logpath = os.path.join(LOGFILE_DIR, "modbus_app.log")
    with open(logpath, "r") as f:
        log = f.read()
    return render_template('user.html', name=current_user.name, content=log)

"""
    POST user.html
    * Update new password to database.
    * Return to login page if password changed successfully.
"""
@app.route('/user' , methods=['POST'])
@login_required
def user_post():
    currentpasswordInput = request.form.get('currentpassword')
    checkingResult = check_password_hash(current_user.password, currentpasswordInput)
    if checkingResult == True:
        password = request.form.get('password')
        repassword = request.form.get('repassword')
        if password == "" and repassword == "":
            flash("Failed: Password cannot be blank.")
        elif password == repassword:
            encryptedPassword = generate_password_hash(password, method='sha256')
            changePassword(encryptedPassword, current_user.name)
            flash("Password changed successfully.")
            logger.info('User: ' + current_user.name + ' - Successfully changed password.')
            logger.info('User: ' + current_user.name + ' - Successfully logged out.')
            logout_user()
            return redirect(url_for('login'))
        else:
            flash("Failed: Those password didn't match.")
    else:
        flash("Failed: Current password didn't match.")
    return render_template('user.html', name=current_user.name)

"""
    GET logout
    * Remove current user session from application, then redirect to login page.
"""
@app.route('/logout')
@login_required
def logout():
    name = current_user.name
    logger.info('User: ' + current_user.name + ' - Successfully logged out.')
    logout_user()
    return redirect(url_for('login'))

"""
    * Read current active uRCONNECT from database.
    * Return value that pyModbusTCP need.
"""
def readAddress():
    connection = databaseConnection()
    cursor = connection.cursor()
    executeCommand = "SELECT unitid, ip, name FROM config WHERE status = %s"
    cursor.execute(executeCommand, ("enabled",))
    urconnectList = cursor.fetchall()
    addressList = []
    for i in range(0,len(urconnectList)):
        executeCommand = ('SELECT type, name, startingAddress, quantity, cardtype, module, channel FROM address_mapping WHERE unitid = %s and ip = %s')
        UNIT_ID = int(urconnectList[i][0])
        IP_ADDRESS = str(urconnectList[i][1])
        UNITNAME = str(urconnectList[i][2])
        cursor.execute(executeCommand, (UNIT_ID, IP_ADDRESS))
        result = cursor.fetchall()
        addressList.append(result)
    try:
        connection.close()
    except:
        pass
    connection = urconnectSettings()
    cursor = connection.cursor()
    executeCommand = "SELECT name, startingAddress, quantity FROM powermeter"
    cursor.execute(executeCommand)
    powermeterList = cursor.fetchall()
    return(urconnectList, addressList, powermeterList)

"""
    * Read value from uRCONNECT
    * Read every channel from every module (up to 40 channel) then convert to json format.
"""
def modbusRead(urconnectList, addressList, powermeterList):
    payloadDict = {"data":{}}
    PORT_NUMBER = 502
    for i in range(0,len(urconnectList)):
        UNIT_ID = int(urconnectList[i][0]) #UnitID #xx
        IP_ADDRESS = str(urconnectList[i][1]) #IPaddress #xx
        UNITNAME = str(urconnectList[i][2])
        payloadDict["data"][UNITNAME] = {}
        payloadDict["data"][UNITNAME]["UnitID"] = UNIT_ID
        payloadDict["data"][UNITNAME]["IPAddress"] = IP_ADDRESS
        payloadDict["data"][UNITNAME]["Module"] = {}
        payloadDict["data"][UNITNAME]["Module"]["module_1down"] = {}
        payloadDict["data"][UNITNAME]["Module"]["module_2down"] = {}
        payloadDict["data"][UNITNAME]["Module"]["module_2up"] = {}
        payloadDict["data"][UNITNAME]["Module"]["module_3down"] = {}
        payloadDict["data"][UNITNAME]["Module"]["module_3up"] = {}
        payloadDict["data"][UNITNAME]["Module"]["powermeter"] = {}
        # Create connection to uRCONNECt.
        client = ModbusClient(auto_open=True, timeout=3, host=IP_ADDRESS, port=PORT_NUMBER, unit_id=UNIT_ID, debug=True)
        if not client.is_open():
            if not client.open():
                logger.error("unable to connect to " + IP_ADDRESS + ":" + str(PORT_NUMBER))
        # if open() is ok, read register
        if client.is_open():
            for num in range (0,len(addressList[i])):
                if addressList[i][num][1] == "" and addressList[i][num][2] == "" and addressList[i][num][3] == "":
                    startingAddress = 0
                    quantity = 1
                else:
                    startingAddress = int(addressList[i][num][2])
                    quantity = int(addressList[i][num][3])
                type = str(addressList[i][num][0])
                name = str(addressList[i][num][1]) # label

                module = "module_" + str(addressList[i][num][5]) #1down,2up...
                if type == "01":
                    data = client.read_coils(startingAddress, quantity) # Return list that contains True or False.
                elif type == "02":
                    data = client.read_discrete_inputs(startingAddress, quantity) # Return list that contains True or False.
                elif type == "04":
                    data = client.read_input_registers(startingAddress, quantity) # Return list that contains integer.
                if str(addressList[i][num][6]) == "1":
                    cardtype = str(addressList[i][num][4])
                    payloadDict["data"][UNITNAME]["Module"][module]["ModuleCardtype"] = cardtype
                payloadDict["data"][UNITNAME]["Module"][module][name] = data
                if str(addressList[i][num][6]) == "8" and str(addressList[i][num][4]) == "None":
                    payloadDict["data"][UNITNAME]["Module"][module] = {}

            payloadDict["data"][UNITNAME]["Module"]["powermeter"] = {}
            for num in range (0,len(powermeterList)):
                if powermeterList[num][0] == "" and powermeterList[num][1] == "" and powermeterList[num][2] == "":
                    startingAddress = 0
                    quantity = 1
                else:
                    startingAddress = int(powermeterList[num][1])
                    quantity = int(powermeterList[num][2])
                name = str(powermeterList[num][0]) # label
                name = name.replace(" ","") # Remove space.
                data = client.read_input_registers(startingAddress, quantity) # Return list that contains integer.
                try:
                    payloadDict["data"][UNITNAME]["Module"]["powermeter"][name] = data
                except:
                    payloadDict["data"][UNITNAME]["Module"]["powermeter"][name] = []
                    payloadDict["data"][UNITNAME]["Module"]["powermeter"][name] = data
    now = datetime.now(tz=timezone('Asia/Bangkok'))
    currentTime = now.strftime("%d/%m/%Y %H:%M:%S")
    payloadDict["data"]["currentTime"] = currentTime
    dataShadow = json.dumps(payloadDict)
    return dataShadow

"""
    * Get NEXPIE credential from database.
    * Return client id, username and password.
"""
def getNexpieCredentials():
    connection = databaseConnection()
    cursor = connection.cursor()
    executeCommand = "SELECT clientid, token, secret from nexpie_auth" #WHERE name
    cursor.execute(executeCommand)
    result = cursor.fetchall()
    connection.close()
    return result

"""
    * Send JSON data to NEXPIE using HTTPS Restful API
    * You can see result on nexpie.io
"""
def payloadPost(dataShadow, credentials):
    basicAuthCredentials = (credentials[0][0], credentials[0][1]) # clientid & token
    response = requests.post(NEXPIE_URL, data=dataShadow, auth=basicAuthCredentials, timeout=5)
    try:
        logger.info('NEXPIE RestAPI response: ' + str(response.text))
    except:
        pass

"""
    * Start modbus thread
    * Note: read enabled device from DB. => get NEXPIE credentials from DB => read value from uRCONNECT
      => convert to JSON => send to NEXPIE.
    * IMPORTANT! : After update uRCONNECT settings and/or NEXPIE credential. You need to restart application to take effect.
"""
def threadedModbus():
    logger.info("Thread: modbusReader started.")
    try:
        urconnectList, addressList, powermeterList = readAddress()
        credentials = getNexpieCredentials()
        logger.info('uRCONNECT: ' + str(urconnectList))
    except:
        pass

    while True:
        try:
            dataShadow = modbusRead(urconnectList, addressList, powermeterList)
            payloadPost(dataShadow, credentials)
            time.sleep(60)
        except:
            logger.debug("Modbus reader error - Please check your configuration.")
            time.sleep(5)

"""
    * Application init.
    * Note: create user if not exists. => ping NEXPIE & DB server => start modbusReader thread
      => start web application => :)
"""
if __name__ == '__main__':
    createUser() # Create user if table "user" have nothing.
    logger.info("Logger: Started.")
    #app.debug = True
    mqttLoopChecker = True
    while mqttLoopChecker == True:
        try:
            r = pyping.ping('mqtt.nexpie.io')
            if r.ret_code == 0:
                logger.info("Ping mqtt.nexpie.io: Success!")

                mqttLoopChecker = False
            else:
                logger.info("Ping mqtt.nexpie.io: Failed!")
        except:
            time.sleep(5)
    webappLoopChecker = True
    while webappLoopChecker == True:
        try:
            r = pyping.ping('203.150.37.154')
            if r.ret_code == 0:
                logger.info("Ping database server: Success")

                webappLoopChecker = False
            else:
                logger.info("Ping database server: Failed")
        except:
            time.sleep(5)
    thread = Thread(target=threadedModbus)
    thread.daemon = True
    thread.start()
    logger.info("WebServer: Web application started.")
    app.run(host='0.0.0.0', port=6969, ssl_context=(CERT, KEY))
