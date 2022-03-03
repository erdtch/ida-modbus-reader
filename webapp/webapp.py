"""
    Tawannnnnnnn :)
    modbus_ida - webapp.py
    Main Python scripts for web application & modbus TCP/IP reader from NECTEC's uRCONNECT.
"""

import csv
import os
import re
import sys
import glob
import time
import json
import wget
import random
import string
import struct
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
from flask_login import LoginManager, login_required, UserMixin, login_user, logout_user, current_user
from flask import Flask, render_template, request, redirect, url_for, flash, url_for, redirect, session, Response

CURRENT_DIRECTORY = os.path.dirname(os.path.abspath(__file__))
POWERMETER = os.path.join(CURRENT_DIRECTORY, "powermeter", "")
POWERMETER_LIBRARY = os.path.join(CURRENT_DIRECTORY, "powermeter")
APP_CONFIG = os.path.join(os.path.dirname(CURRENT_DIRECTORY), "app_config.ini")
CARDTYPE_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "csv", "cardtype.csv")
DATATYPE_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "csv", "datatypes.csv")
UR_ADDR_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "csv", "urconnect_address.csv")
KEY = os.path.join(os.path.dirname(
    os.path.abspath(__file__)), "cert", "key.pem")
CERT = os.path.join(os.path.dirname(os.path.abspath(
    __file__)), "cert", "cert.pem")  # Self signed
LOGFILE_DIR = os.getenv("CAF_APP_LOG_DIR", "/tmp")
sys.path.append(POWERMETER)
appconfig = SafeConfigParser()
appconfig.read(APP_CONFIG)

# Establish MySQL connection to database server.


def databaseConnection():
    connection = MySQL.connect(host=DB_IP,
                               user=DB_USERNAME,
                               passwd=DB_PASSWORD,
                               port=DB_PORT,
                               db=DB_SCHEMA)
    return connection

def urconnectConnection():
    connection = MySQL.connect(host=DB_IP,
                               user=DB_USERNAME,
                               passwd=DB_PASSWORD,
                               port=DB_PORT,
                               db=UR_SCHEMA)
    return connection

"""
    Create table "urconnect_address" if it isn't exists.
    * id = PK, id number
    * unitid = unitid of uRCONNECT
    * module = module of uRCONNECT (1down, 2up, 2down, 3up, 3down)
    * channel = module's channel of uRCONNECT (1-8)
    * type = modbus function code (FC01-FC04)
    * name = sensor name (you can change if you need.)
    * startingAddress = starting address that script need to read from uRCONNECT.
    * quantity = amount of address that script need to read from uRCONNECT. (e.g. 00001, 2 = read from address 00001 to 00002)
    * ip = ip address is ip address, yeah i mean it.
    * displayAddress = address that you can see from uRCONNECT documents.
    * cardtype = card type (e.g. 4-20mA, digital input, relay)
    * unit = unit of value (e.g. mA, V, Celcius)
    * status = read or not read that address.
"""


def createUrconnectAddress():
    connection = databaseConnection()
    cursor = connection.cursor()
    executeCommand = ("CREATE TABLE IF NOT EXISTS urconnect_address (id INT NOT NULL AUTO_INCREMENT PRIMARY KEY, unitid VARCHAR(2) NOT NULL, module VARCHAR(5) NOT NULL, "
                      "channel VARCHAR(1) NOT NULL, type VARCHAR(2) NOT NULL, name VARCHAR(30) NOT NULL, startingAddress VARCHAR(5) NOT NULL, "
                      "quantity VARCHAR(5) NOT NULL, urconnect VARCHAR(40) NOT NULL, displayAddress VARCHAR(6) NOT NULL, cardtype VARCHAR(20) NOT NULL, unit VARCHAR(20), status VARCHAR(20))")
    cursor.execute(executeCommand)
    connection.commit()
    try:
        connection.close()
    except:
        pass


"""
    Create table "powermeter" if it isn't exists.
    * id = PK, id number
    * metername = name of power meter.
    * tablinks = active status of tablinks in powermeter.html
    * urconnect = urconnect name
"""


def createPowermeter():
    connection = databaseConnection()
    cursor = connection.cursor()
    executeCommand = ("CREATE TABLE IF NOT EXISTS powermeter (id INT NOT NULL AUTO_INCREMENT PRIMARY KEY, metername VARCHAR(40) NOT NULL UNIQUE, "
                      "tablinks VARCHAR(30) NOT NULL, urconnect VARCHAR(50) NOT NULL)")
    cursor.execute(executeCommand,)
    connection.commit()
    try:
        connection.close()
    except:
        pass


"""
    Create table "powermeter_address" if it isn't exists.
    * id = PK, id number
    * name = name of address that u need to read from powermeter.
    * address = start address that u need to read from powermeter.
    * quantity = amount of address that script need to read from powermeter. (e.g. 00001, 2 = read from address 00001 to 00002)
    * datatype = data type of value that u need to convert to. (e.g. uint32 = convert 2 uint16 to uint32)
    * realaddress = REAL ADDRESS THAT MY SCRIPT USE TO READ FROM URCONNECT (ALWAYS MINUS ONE FROM address)
    * modbustype = modbus function code (FC01-FC04)
    * multiplier = just a multiplier. (converted data MULTIPLIED BY multiplier)
    * unit = unit of value (e.g. mA, V, Celcius)
"""


def createPowermeterAddress():
    connection = databaseConnection()
    cursor = connection.cursor()
    executeCommand = ("CREATE TABLE IF NOT EXISTS powermeter_address (id INT NOT NULL AUTO_INCREMENT PRIMARY KEY, name VARCHAR(40) NOT NULL, address VARCHAR(6), "
                      "quantity VARCHAR(3), datatype VARCHAR(30) NOT NULL, realaddress VARCHAR(6), metername VARCHAR(50) NOT NULL, modbustype VARCHAR(3) NOT NULL, multiplier VARCHAR(20) NOT NULL, unit VARCHAR(20))")
    cursor.execute(executeCommand,)
    connection.commit()
    try:
        connection.close()
    except:
        pass


"""
    Create table "api_endpoint" if it isn't exists.
    * id = PK, id number
    * apiname = name of api.
    * url = url of api (ex. "http://192.168.1.1")
    * port = port of api (ex. "5000")
    * path =  path of api (ex. "/data")
    * nexpie_device = NEXPIE device name from nexpie_auth table
    * lastupdate = datetime that data is update (ex. "2022-01-14 00:01:32")

"""


def createAPIsEndpoint():
    connection = databaseConnection()
    cursor = connection.cursor()
    executeCommand = ("CREATE TABLE IF NOT EXISTS api_endpoint (id INT NOT NULL AUTO_INCREMENT PRIMARY KEY, apiname VARCHAR(50) NOT NULL UNIQUE, "
                      "url TEXT NOT NULL, port VARCHAR(5) NOT NULL, path TEXT NOT NULL, nexpieauth VARCHAR(50) NOT NULL, lastupdate TIMESTAMP NULL DEFAULT NULL)")
    cursor.execute(executeCommand)
    connection.commit()
    try:
        connection.close()
    except:
        pass


"""
    Create table "nexpie_auth" if it isn't exists.
    * name = NEXPIE device name (it's just a name, don't mind)
    * clientid = NEXPIE device's client id
    * token = NEXPIE device's username (token on nexpie.io)
    * secret = NEXPIE device's password (secret on nexpie.io)
"""


def createNexpieAuth():
    connection = databaseConnection()
    cursor = connection.cursor()
    executeCommand = "CREATE TABLE IF NOT EXISTS nexpie_auth (id INT NOT NULL AUTO_INCREMENT PRIMARY KEY, name VARCHAR(50) NOT NULL, clientid VARCHAR(36) NOT NULL, token VARCHAR(32) NOT NULL, secret VARCHAR(32) NOT NULL)"
    cursor.execute(executeCommand)
    connection.commit()
    try:
        connection.close()
    except:
        pass


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
"""


def createConfig():
    connection = databaseConnection()
    cursor = connection.cursor()
    executeCommand = ("CREATE TABLE IF NOT EXISTS config (id INT NOT NULL AUTO_INCREMENT PRIMARY KEY, unitid VARCHAR(2) NOT NULL UNIQUE, ip VARCHAR(15) NOT NULL UNIQUE"
                      ",note VARCHAR(15) NOT NULL, status VARCHAR(10) NOT NULL, tablinks VARCHAR(40) NOT NULL, urconnect VARCHAR(40) NOT NULL UNIQUE, nexpieauth VARCHAR(50))")
    cursor.execute(executeCommand)
    connection.commit()
    try:
        connection.close()
    except:
        pass


"""
    Create table "cardtype" if it isn't exists.
    * value = ? 
    * cardtype = type of card of uRCONNECT
    * type = ?
"""


def createCardtype():
    connection = urconnectConnection()
    cursor = connection.cursor()
    executeCommand = ("CREATE TABLE IF NOT EXISTS cardtype ("
                    "value VARCHAR(2) NOT NULL, "
                    "cardtype VARCHAR(8) NOT NULL, "
                    "type VARCHAR(2) NOT NULL)"
                )
    cursor.execute(executeCommand)
    connection.commit()
    executeCommand = "SELECT * FROM cardtype"
    cursor.execute(executeCommand)
    result = cursor.fetchall()
    if result == []:
        csv_data = csv.reader(file(CARDTYPE_path))
        for row in csv_data:
            executeCommand = "INSERT INTO cardtype (value, cardtype, type) VALUES (%s, %s, %s)"
            cursor.execute(executeCommand, row)
            connection.commit()
    try:
        connection.close()
    except:
        pass


"""
    Create table "datatypes" if it isn't exists.
    * name = ?
    * symbol = ?
"""


def createDatatypes():
    connection = urconnectConnection()
    cursor = connection.cursor()
    executeCommand = ("CREATE TABLE IF NOT EXISTS datatypes ("
                    "id INT NOT NULL AUTO_INCREMENT PRIMARY KEY, "
                    "name VARCHAR(33) NOT NULL, "
                    "symbol VARCHAR(9) NOT NULL)"
                    )
    cursor.execute(executeCommand)
    connection.commit()
    executeCommand = "SELECT * FROM datatypes"
    cursor.execute(executeCommand)
    result = cursor.fetchall()
    if result == []:
        csv_data = csv.reader(file(DATATYPE_path))
        for row in csv_data:
            executeCommand = "INSERT INTO datatypes (name, symbol) VALUES (%s, %s)"
            cursor.execute(executeCommand, row)
            connection.commit()
    try:
        connection.close()
    except:
        pass


"""
    Create table "urconnect_address" (urconnect_settings DB) if it isn't exists.
    * type
    * module
    * channel
    * startingAddress
    * quantity
    * displayAddress
"""


def createUrconnect_data():
    connection = urconnectConnection()
    cursor = connection.cursor()
    executeCommand = ("CREATE TABLE IF NOT EXISTS urconnect_address ("
                        "type VARCHAR(2) NOT NULL, "
                        "module VARCHAR(5) NOT NULL, "
                        "channel VARCHAR(1) NOT NULL, "
                        "startingAddress VARCHAR(2) NOT NULL, "
                        "quantity VARCHAR(1) NOT NULL, "
                        "displayAddress VARCHAR(5) NOT NULL)"
                    )
    cursor.execute(executeCommand)
    connection.commit()
    executeCommand = "SELECT * FROM urconnect_address"
    cursor.execute(executeCommand)
    result = cursor.fetchall()
    if result == []:
        csv_data = csv.reader(file(UR_ADDR_path))
        for row in csv_data:
            executeCommand = "INSERT INTO urconnect_address (type, module, channel, startingAddress, quantity, displayAddress) VALUES (%s, %s, %s, %s, %s, %s)"
            cursor.execute(executeCommand, row)
            connection.commit()
    try:
        connection.close()
    except:
        pass


"""
    Setup logging for the current module and dependent libraries based on
    values available in config.
"""


def setup_logging():
    # Set a format which is simpler for console use
    formatter = logging.Formatter(
        '[%(asctime)s] %(levelname)-8s> %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

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

    # Define cap of the log file at 1 MB x 3 backups.
    rfh = RotatingFileHandler(log_file_path, maxBytes=3096*3096, backupCount=3)
    rfh.setLevel(loglevel)
    rfh.setFormatter(formatter)
    logger.addHandler(rfh)

# Write time interval to old app_config.ini if not exist. (version 1.1)


def initInterval():
    try:
        TIME_INTERVAL = int(appconfig.get('TIME_INTERVAL', 'timeInterval'))
    except:
        cfgfile = open(APP_CONFIG, "w")
        appconfig.add_section("TIME_INTERVAL")
        appconfig.set("TIME_INTERVAL", "timeInterval", "60")
        appconfig.write(cfgfile)


# Load config from app_config.ini
DB_USERNAME = appconfig.get('SQLALCHEMY_CONFIG', 'username')
DB_PASSWORD = appconfig.get('SQLALCHEMY_CONFIG', 'password')
DB_IP = appconfig.get('SQLALCHEMY_CONFIG', 'ip')
DB_PORT = appconfig.get('SQLALCHEMY_CONFIG', 'port')
DB_SCHEMA = appconfig.get('SQLALCHEMY_CONFIG', 'schema')
UR_SCHEMA = appconfig.get('SQLALCHEMY_CONFIG', 'ur_schema')
NEXPIE_URL = appconfig.get('NEXPIE', 'shadow_url')
jsondata = []

logger = logging.getLogger("modbus_ida")
setup_logging()
initInterval()  # Create time interval config (if not exist.)

# Test connection and connect to database server.
# Initialize application.
initChecker = True
while initChecker == True:
    r = pyping.ping(DB_IP)
    if r.ret_code == 0:
        try:
            connection = MySQL.connect(host=DB_IP,
                                       user=DB_USERNAME,
                                       passwd=DB_PASSWORD,
                                       port=DB_PORT)
            cursor = connection.cursor()
            executeCommand = "CREATE DATABASE IF NOT EXISTS " + DB_SCHEMA
            cursor.execute(executeCommand)
            connection.commit()
            connection.close()

            createUser()  # Create user if table "user" have nothing.
            createUrconnectAddress()
            createAPIsEndpoint()
            createNexpieAuth()
            createConfig()
            createPowermeter()
            createPowermeterAddress()
     
            connection = MySQL.connect(host=DB_IP,
                                       user=DB_USERNAME,
                                       passwd=DB_PASSWORD,
                                       port=DB_PORT)
            cursor = connection.cursor()
            executeCommand = "CREATE DATABASE IF NOT EXISTS " + UR_SCHEMA
            cursor.execute(executeCommand)
            connection.commit()
            connection.close()

            createCardtype()
            createDatatypes()
            createUrconnect_data()


            app = Flask(__name__)
            db = SQLAlchemy()
            db.pool_recycle = 300
            app.config['SECRET_KEY'] = appconfig.get('APP_INIT', 'secretkey')
            # app.config['SQLALCHEMY_DATABASE_URI'] = "mysql://" + DB_USERNAME + ":" + DB_PASSWORD + "@" + DB_IP + ":" + DB_PORT + "/" + DB_SCHEMA
            app.config['SQLALCHEMY_DATABASE_URI'] = "mysql+mysqlconnector://" + DB_USERNAME + ":" + DB_PASSWORD + "@" + DB_IP + ":" + DB_PORT + "/" + DB_SCHEMA
            app.config["SQLALCHEMY_POOL_SIZE"] = 20
            app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=15)
            app.config['SESSION_REFRESH_EACH_REQUEST'] = True
            db.init_app(app)

            login_manager = LoginManager()
            login_manager.login_view = 'login'
            login_manager.init_app(app)
            initChecker = False
        except Exception as e:
            logger.error("Exception occurred", exc_info=True)
    else:
        logger.info("Ping database server: Failed")


class User(UserMixin, db.Model):
    # primary keys are required by SQLAlchemy
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True)
    password = db.Column(db.String(30))
    name = db.Column(db.String(100))


@login_manager.user_loader
def load_user(user_id):
    # since the user_id is just the primary key of our user table, use it in the query for the user.
    return User.query.get(int(user_id))

# Load uRCONNECT default config from database server.


def urconnectSettings():
    connection = MySQL.connect(host=DB_IP,
                               user=DB_USERNAME,
                               passwd=DB_PASSWORD,
                               port=DB_PORT,
                               db="urconnect_settings")
    return connection

# Change web application's credentials.


def changePassword(encryptedPassword, name):
    connection = databaseConnection()
    cursor = connection.cursor()
    executeCommand = "UPDATE user SET password = %s WHERE name = %s"
    cursor.execute(executeCommand, (encryptedPassword, name,))
    connection.commit()
    closeConnection(connection)

# Close database connection


def closeConnection(connection):
    try:
        connection.close()
    except:
        pass

# Delete registered device from database.


def deleteConfig(urconnect):
    connection = databaseConnection()
    cursor = connection.cursor()
    executeCommand = "SELECT id FROM powermeter WHERE urconnect = %s"
    cursor.execute(executeCommand, (urconnect,))
    result = cursor.fetchall()
    # If selected urconnect not used by any powermeter, then delete urconnect config.
    if result == []:
        executeCommand = "DELETE FROM config WHERE urconnect = %s"
        cursor.execute(executeCommand, (urconnect,))
        executeCommand = "DELETE FROM urconnect_address WHERE urconnect = %s"
        cursor.execute(executeCommand, (urconnect,))
        executeCommand = "UPDATE config SET tablinks = %s LIMIT 1"
        cursor.execute(executeCommand, ("tablinks active",))
        connection.commit()
        try:
            connection.close()
        except:
            pass
        return("deleted")
    elif result != []:
        return("not delete")
    else:
        return("failed")

# Get list of power meter from database.


def getPowermeter():
    connection = databaseConnection()
    cursor = connection.cursor()
    executeCommand = "SELECT * FROM powermeter"
    cursor.execute(executeCommand)
    result = cursor.fetchall()
    closeConnection(connection)
    return(result)

# Get list of power meter address from database.


def getPowermeterAddress():
    connection = databaseConnection()
    cursor = connection.cursor()
    executeCommand = "SELECT * FROM powermeter_address"
    cursor.execute(executeCommand)
    result = cursor.fetchall()
    closeConnection(connection)
    return(result)

# Random power meter address name.


def randomAddressname():
    randomstring = random.sample(string.ascii_letters, 6)
    for i in range(0, 6):
        if i == 0:
            randomname = ""
        randomname = randomname + randomstring[i]
    return(randomname)

# Add new powermeter to database.


def newPowermeter(powermetername, urconnect):
    connection = databaseConnection()
    cursor = connection.cursor()
    executeCommand = "SELECT tablinks FROM powermeter WHERE tablinks = %s"
    cursor.execute(executeCommand, ("tablinks active",))
    result = cursor.fetchall()
    # Note: tablinks active = show this tab after GET config page (index.html)
    if result == []:
        tablinks = "tablinks active"
    else:
        tablinks = "tablinks"
    executeCommand = (
        "INSERT INTO powermeter (metername, tablinks, urconnect) VALUES (%s, %s, %s)")
    cursor.execute(executeCommand, (powermetername, tablinks, urconnect))
    # Create address for powermeter.
    for i in range(0, 15):
        randomname = randomAddressname()
        executeCommand = (
            "INSERT INTO powermeter_address (name, datatype, metername, modbustype, multiplier) VALUES (%s, %s, %s, %s, %s)")
        cursor.execute(executeCommand, (randomname,
                                        "none", powermetername, "00", "-"),)
    connection.commit()
    closeConnection(connection)
    return(result)

# Get NEXPIE credentials from database.


def getNexpieAuth():
    connection = databaseConnection()
    cursor = connection.cursor()
    executeCommand = "SELECT id, name, clientid, token, secret FROM nexpie_auth"
    cursor.execute(executeCommand)
    result = cursor.fetchall()
    closeConnection(connection)
    return(result)

# Get NEXPIE device name from database.


def getCredentialsName():
    connection = databaseConnection()
    cursor = connection.cursor()
    executeCommand = "SELECT name FROM nexpie_auth"
    cursor.execute(executeCommand)
    result = cursor.fetchall()
    closeConnection(connection)
    return result

# Get APIs from database.


def getAPIs():
    connection = databaseConnection()
    cursor = connection.cursor()
    executeCommand = "SELECT id, apiname, url, port, path, nexpieauth FROM api_endpoint"
    cursor.execute(executeCommand)
    result = cursor.fetchall()
    closeConnection(connection)
    return(result)

# Delete NEXPIE device from database.


def deleteCredentials(nexpiename):
    try:
        connection = databaseConnection()
        cursor = connection.cursor()
        executeCommand = "DELETE FROM nexpie_auth WHERE name = %s"
        cursor.execute(executeCommand, (nexpiename,))
        connection.commit()
        closeConnection(connection)
    except:
        return("failed")
    return("success")

# Delete API from database.


def deleteAPIs(apiname):
    try:
        connection = databaseConnection()
        cursor = connection.cursor()
        executeCommand = "DELETE FROM api_endpoint WHERE apiname = %s"
        cursor.execute(executeCommand, (apiname,))
        connection.commit()
        closeConnection(connection)
    except:
        return("failed")
    return("success")

# Query APIs data from apiname from database.


def getAPIsfromAPIsname(apiname):
    connection = databaseConnection()
    cursor = connection.cursor()
    executeCommand = "SELECT * FROM api_endpoint WHERE apiname = %s "
    cursor.execute(executeCommand, (apiname,))
    result = cursor.fetchone()
    return result

# Get id of NEXPIE device from database. (not clientid)


def getAPIsID():
    connection = databaseConnection()
    cursor = connection.cursor()
    executeCommand = "SELECT id FROM api_endpoint"
    cursor.execute(executeCommand)
    result = cursor.fetchall()
    closeConnection(connection)
    return result

# Get id of NEXPIE device from database. (not clientid)


def getNexpieID():
    connection = databaseConnection()
    cursor = connection.cursor()
    executeCommand = "SELECT id FROM nexpie_auth"
    cursor.execute(executeCommand)
    result = cursor.fetchall()
    closeConnection(connection)
    return result

# Get list of urconncet from database.


def getConfig():
    connection = databaseConnection()
    cursor = connection.cursor()
    executeCommand = "SELECT * FROM config"
    cursor.execute(executeCommand)
    data = cursor.fetchall()
    closeConnection(connection)
    return data

# Get value that define tab(s) in config page.


def getTab():
    connection = databaseConnection()
    cursor = connection.cursor()
    executeCommand = "SELECT tablinks, id, urconnect FROM config WHERE note = %s"
    cursor.execute(executeCommand, ("config",))
    result = cursor.fetchall()
    closeConnection(connection)
    return result

# Get value that define tab(s) in config page.


def getPowermeterTab():
    connection = databaseConnection()
    cursor = connection.cursor()
    executeCommand = "SELECT tablinks, id, metername FROM powermeter"
    cursor.execute(executeCommand,)
    result = cursor.fetchall()
    closeConnection(connection)
    return result

# Get list of urconnect name from database.


def getUrconnect():
    connection = databaseConnection()
    cursor = connection.cursor()
    executeCommand = "SELECT urconnect FROM config"
    cursor.execute(executeCommand)
    data = cursor.fetchall()
    closeConnection(connection)
    return data

# Get value that define unitid in config page.


def getConfigID():
    connection = databaseConnection()
    cursor = connection.cursor()
    executeCommand = "SELECT id FROM config WHERE note = %s"
    cursor.execute(executeCommand, ("config",))
    result = cursor.fetchall()
    closeConnection(connection)
    return result

# Add new urconnect to database.


def newDevice(ip, unitid, checkbox, devicename, nexpieauth):
    # Note: enabled = get value from urconnect, convert to json and send to NEXPIE.
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
    executeCommand = (
        "INSERT INTO config (unitid, ip, note, status, tablinks, urconnect, nexpieauth) VALUES (%s, %s, %s, %s, %s, %s, %s)")
    cursor.execute(executeCommand, (unitid, ip, "config",
                                    checkbox, tablinks, devicename, nexpieauth))
    connection.commit()
    closeConnection(connection)

# Update urconnect's config (ip, unitid, device name, nexpie device & status enable or disable) to database


def updateConfig(ip, unitid, devicename, oldunitid, oldip, oldname, checkbox, nexpieauth):
    if checkbox != "enabled":
        checkbox = "disabled"
    connection = databaseConnection()
    cursor = connection.cursor()
    devicename = devicename.replace(" ", "_")
    # 1st: Update urconnect name in "urconnect_address"
    executeCommand = "UPDATE urconnect_address SET urconnect = %s, unitid = %s WHERE unitid = %s and urconnect = %s"
    cursor.execute(executeCommand, (devicename, unitid, oldunitid, oldname,))
    connection.commit()
    # 2nd: Update ip, unitid, device name, nexpie device & status enable or disable.
    executeCommand = "UPDATE config SET ip = %s, unitid = %s, urconnect = %s, status = %s, nexpieauth = %s WHERE unitid = %s and ip = %s and urconnect = %s"
    cursor.execute(executeCommand, (ip, unitid, devicename,
                                    checkbox, nexpieauth, oldunitid, oldip, oldname,))
    connection.commit()
    # 3rd: Update name of urconnect in powereter database.
    executeCommand = "UPDATE powermeter SET urconnect = %s WHERE urconnect = %s"
    cursor.execute(executeCommand, (devicename, oldname,))
    connection.commit()
    # 4th: Get id of urconnect_address that you need to change value/data.
    # We only need length of unitid = %s
    executeCommand = "SELECT id FROM urconnect_address WHERE urconnect = %s"
    cursor.execute(executeCommand, (devicename,))
    result = cursor.fetchall()
    return(result)

# Update NEXPIE credentials to database.


def updateNexpieCredentials(id, name, clientid, token, secret):
    connection = databaseConnection()
    cursor = connection.cursor()
    executeCommand = "UPDATE nexpie_auth SET name = %s, clientid = %s, token = %s, secret = %s WHERE id = %s"
    cursor.execute(executeCommand, (name, clientid, token, secret, id))
    connection.commit()
    closeConnection(connection)

# Update APIs to database.


def updateAPIs(id, apiname, url, port, path, nexpieauth):
    connection = databaseConnection()
    cursor = connection.cursor()
    executeCommand = "UPDATE api_endpoint SET apiname = %s, url = %s, port = %s, path = %s, nexpieauth = %s WHERE id = %s"
    cursor.execute(executeCommand, (apiname, url, port, path, nexpieauth, id))
    connection.commit()
    closeConnection(connection)

# Update teimstamp to API database.


def updateTimeStampAPIs(apiname, timestamp):
    connection = databaseConnection()
    cursor = connection.cursor()
    executeCommand = "UPDATE api_endpoint SET lastupdate = %s WHERE apiname = %s"
    cursor.execute(executeCommand, (timestamp, apiname))
    connection.commit()
    closeConnection(connection)

# Add new NEXPIE device to database.


def addNexpieCredentials(name, clientid, token, secret):
    connection = databaseConnection()
    cursor = connection.cursor()
    executeCommand = (
        "INSERT INTO nexpie_auth (name, clientid, token, secret) VALUES (%s, %s, %s, %s)")
    cursor.execute(executeCommand, (name, clientid, token, secret))
    connection.commit()
    closeConnection(connection)

# Add new API to database.


def addAPI(apiname, url, port_url, path_url, nexpieauth):
    try:
        connection = databaseConnection()
        cursor = connection.cursor()
        executeCommand = (
            "INSERT INTO api_endpoint (apiname, url, port, path, nexpieauth) VALUES (%s, %s, %s, %s, %s)")
        cursor.execute(executeCommand, (apiname, url,
                                        port_url, path_url, nexpieauth))
        connection.commit()
        closeConnection(connection)
        return("Add New APIs successfully.")
    except MySQL.Error as err:
        return str(err)


"""
    * Check type and correction of input before update to database.
    * If its duplicate or error, then return error and skip update.
"""


def inputChecker(ip, unitid, devicename, oldip, oldunitid, oldname):
    if ip == "":
        return("Failed: IP address cannot be blank.")
    if unitid == "":
        return("Failed: Unit id or device name cannot be blank.")
    if devicename == "":
        return("Failed: Device name cannot be blank.")
    connection = databaseConnection()
    cursor = connection.cursor()
    executeCommand = "SELECT id FROM config WHERE ip = %s and unitid = %s and urconnect = %s"
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
    executeCommand = "SELECT urconnect FROM config WHERE urconnect = %s and id <> %s"
    cursor.execute(executeCommand, (devicename, id))
    result = cursor.fetchall()
    if result != []:
        return("Failed: The name '" + devicename + "' is already used in database.")
    closeConnection(connection)
    return("Passed")


"""
    * Check type and correction of input before update to database.
    * If its duplicate or error, then return error and skip update.
"""


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
    executeCommand = "SELECT urconnect FROM config WHERE urconnect = %s"
    cursor.execute(executeCommand, (devicename,))
    result = cursor.fetchall()
    if result != []:
        return("Failed: The name '" + devicename + "' is already used in database.")
    closeConnection(connection)
    return("Passed")


"""
    * Check type and correction of input before update to database.
    * If its duplicate or error, then return error and skip update.
"""


def inputCheckerNewAPI(apiname, url, port_url, path_url, nexpieauth):
    if len(apiname) != 0 and len(url) != 0 and len(port_url) != 0 and len(path_url) != 0:
        if not(port_url.isdigit()) and port_url != '-':
            return("Failed: Port must be 'Integer number' or '-'.")
        else:
            return "Passed"
    elif len(apiname) == 0:
        return("Failed: APIname cannot be blank.")
    elif len(url) == 0:
        return("Failed: URL cannot be blank.")
    elif len(port_url) == 0:
        return("Failed: Port cannot be blank (must be 'Integer number' or '-').")
    elif len(path_url) == 0:
        return("Failed: Path cannot be blank.")
    
def inputCheckerRequestAPI(url, port_url, path_url):
    full_url = createFullURLfromAPI(url, port_url, path_url)
    try:
        r = requests.get(full_url,timeout=5)
        r.raise_for_status()
        try:
            payload = r.json()
        #     if 'data' in payload: 
        #         if 'last_update' in payload:
        #             if check_date_format(payload['last_update']):
        #                 return "Passed"
        #             else:
        #                 return "Failed: Incorrect data format, should be 'yyyy-mm-dd HH:MM:SS'"
        #         else:
        #             return "Failed: 'last_update' is missing from payload"
                
        #     else:
        #         return "Failed: 'data' is missing from payload"
        # except:
            # return "Failed: No JSON object could be decoded"
        #     print(payload)
            if 'data' in payload:
                if check_payload_type(payload['data']):
                    if 'last_update' in payload:
                        if check_date_format(payload['last_update']):
                            return "Passed"
                        else:
                            return "Failed: Incorrect data format, should be 'yyyy-mm-dd HH:MM:SS'"
                    else:
                        return "Failed: 'last_update' is missing from payload"
                else:
                    return "Failed: Incorrect data type in Payload"
            else:
                return "Failed: 'data' is missing from payload"
        except:
            return "Failed: No JSON object could be decoded"

    except requests.exceptions.HTTPError as errh:
        return "Failed: " + str(errh)
    except requests.exceptions.ConnectionError as errc:
        return "Failed: " + str(errc)
    except requests.exceptions.Timeout as errt:
        return "Failed: " + str(errt)
    except requests.exceptions.RequestException as err:
        return "Failed: " + str(err)


# Check correction of client id before update to database.


def clientidChecker(clientid):
    for i in range(0, len(clientid)):
        if i == 8 or i == 13 or i == 18 or i == 23:
            if clientid[i] != "-":
                return(False)
        else:
            if clientid[i] == "-":
                return(False)
    return(True)

# Check connection between application and urconnect before update to database.
# This mean u cannot change urconnect data w/o connect to urconnect.


def checkUrconnect(ip, unitid):
    PORT_NUMBER = 502
    try:
        client = ModbusClient(auto_open=True, timeout=3, host=ip,
                              port=PORT_NUMBER, unit_id=unitid, debug=True)
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
    client = ModbusClient(auto_open=True, timeout=3, host=ip,
                          port=PORT_NUMBER, unit_id=unitid, debug=True)
    client.host(ip)
    client.port(PORT_NUMBER)
    client.unit_id(unitid)
    client.debug()
    if not client.is_open():
        if not client.open():
            return("Failed: Can't connect to " + ip + ", unit id " + unitid)
    # if open() is ok, read register (modbus function FC03)
    if client.is_open():
        data = client.read_holding_registers(501, 5)
        for i in range(0, len(data)):
            if data[i] not in [80, 81, 82, 83, 84, 85, 86, 87, 0]:
                data[i] = 0
        return data

# Get modbus function from database using card type.


def getModbusType(name, cardList):
    connection = MySQL.connect(host=DB_IP,
                               user=DB_USERNAME,
                               passwd=DB_PASSWORD,
                               port=DB_PORT,
                               db="urconnect_settings")
    cursor = connection.cursor()
    typeList = []
    moduleList = ["1down", "2up", "2down", "3up", "3down"]
    resultList = []
    for i in range(0, len(cardList)):
        cursor = connection.cursor()
        # cardType = result[0][1]
        executeCommand = "SELECT type, cardtype FROM cardtype WHERE value = %s"
        cursor.execute(executeCommand, (cardList[i],))
        cardtypeList = cursor.fetchall()
        executeCommand = "SELECT * FROM urconnect_address WHERE type = %s AND module = %s"
        cursor.execute(executeCommand, (cardtypeList[0][0], moduleList[i],))
        result = cursor.fetchall()
        for i in range(0, len(result)):
            result[i] = result[i] + (cardtypeList[0][1],)
            resultList.append(result[i])
    closeConnection(connection)
    return(resultList)

# Write time interval to app_config.ini


def writeInterval(interval):
    if interval == "":
        return("Failed: Interval cannot be blank.")
    try:
        tempInterval = int(interval)
    except:
        return("Failed: Interval can only be numeric character(s).")
    cfgfile = open(APP_CONFIG, "w")
    appconfig.set("TIME_INTERVAL", "timeInterval", interval)
    appconfig.write(cfgfile)
    return("Passed")


"""
    Quick note:
    * realAddress = address that use in pyModbusTCP. (ALWAYS MINUS ONE FROM URCONNECT DATASHEET)
    * intAddress = address that use in uRCONNECT document, uRCONNECT configuration software and IDA web application.

def addressChecker(name, startingAddress, filename):
    try:
        intAddress = int(startingAddress)
        realAddress = intAddress - 1

            intAddress > 0 same as realAddress >= 0
            intAddress = 1 same as register 40000 (holding register 0)

        if intAddress > 0:
            if name != "" and name != " ":
                model = getModelFromFilename(filename)
                return("Passed", str(realAddress), model[0][0])
            else:
                pass
        else:
            pass
        return("Not Passed", "0", "0")
    except:
        return("Not Passed", "0", "0")
"""

# Check nexpie device usage before delete from database.


def chkCredentialUsage(nexpiename):
    try:
        connection = databaseConnection()
        cursor = connection.cursor()
        executeCommand = "SELECT urconnect FROM config WHERE nexpieauth = %s"
        cursor.execute(executeCommand, (nexpiename,))
        result = cursor.fetchall()
        closeConnection(connection)
        if result != []:
            return("used")
        else:
            return("not used")
    except:
        return("failed")


"""
    Select quantity from datatype.
    e.g. uint32 need 2x uint16 > quantity = 2
"""


def datatypeQuantity(datatype):
    datatypeBits = datatype[-2:]
    if datatypeBits == "32":
        quantity = "2"
    elif datatypeBits == "16":
        quantity = "1"
    elif datatypeBits == "64":
        quantity = "4"
    else:
        quantity = "none"
    return(quantity)

# Check power meter address before add/change to database.


def powermeterAddressChecker(name, modbustype, startaddr, multiplier, datatype):
    # If multiplier or address isn't in number format => code in "except" will work.
    try:
        floatMultiplier = float(multiplier)
        intaddress = int(startaddr)
        if name == "" or name == " " or intaddress <= 0 or modbustype == "00":
            return("Not Passed", "0", "-")
        nameFirstchar = name[:1]
        # need to check first character of name. because NEXPIE will reject JSON data if first character of name is number.
        firstcharIsdigit = nameFirstchar.isdigit()
        if firstcharIsdigit == True:
            return("Not Passed", "0", "-")
        # realAddress = address that use in pyModbusTCP.
        realaddress = intaddress - 1
        if datatype != "none":
            quantity = datatypeQuantity(datatype)
        return("Passed", realaddress, quantity)
    except:
        return("Not Passed", "0", "-")


"""
    Add blank input in "powermeter.html"
    e.g. if u add 13 address to "powermeter_address". this function will generate blank input to 15 again.
"""


def updateBlankInput(metername):
    connection = databaseConnection()
    cursor = connection.cursor()
    executeCommand = "SELECT id FROM powermeter_address WHERE metername = %s and modbustype = %s"
    cursor.execute(executeCommand, (metername, "00",))
    result = cursor.fetchall()
    # Always keep 15 blank input per powermeter
    blankinput = int(len(result))
    if blankinput < 15:
        blankinput = 15 - blankinput
        for i in range(0, blankinput):
            randomname = randomAddressname()
            executeCommand = (
                "INSERT INTO powermeter_address (name, datatype, metername, modbustype, multiplier) VALUES (%s, %s, %s, %s, %s)")
            cursor.execute(executeCommand, (randomname,
                                            "none", metername, "00", "-"),)
    elif blankinput > 15:
        blankinput = blankinput - 15
        strBlankinput = str(blankinput)
        executeCommand = "SELECT id FROM powermeter_address WHERE modbustype = %s and metername = %s ORDER BY id DESC LIMIT " + strBlankinput
        cursor.execute(executeCommand, (id),)
        result = cursor.fetchall()
        for i in range(0, len(result)):
            id = result[i][0]
            executeCommand = ("DELETE FROM powermeter_address WHERE id = %s")
            cursor.execute(executeCommand, (id),)
    else:
        pass
    connection.commit()
    closeConnection(connection)

# Read function name. i mean it :D


def updatePowermeter(metername, urconnect, oldmetername):
    connection = databaseConnection()
    cursor = connection.cursor()
    executeCommand = "UPDATE powermeter_address SET metername = %s WHERE metername = %s"
    cursor.execute(executeCommand, (metername, oldmetername,))
    executeCommand = "UPDATE powermeter SET metername = %s, urconnect = %s WHERE metername = %s"
    cursor.execute(executeCommand, (metername, urconnect, oldmetername,))
    connection.commit()
    closeConnection(connection)

# Delete power meter from database.


def deletePowermeter(metername):
    connection = databaseConnection()
    cursor = connection.cursor()
    executeCommand = "DELETE FROM powermeter WHERE metername = %s"
    cursor.execute(executeCommand, (metername,))
    executeCommand = "DELETE FROM powermeter_address WHERE metername = %s"
    cursor.execute(executeCommand, (metername,))
    connection.commit()
    closeConnection(connection)

# Get datatypes from database.


def getDatatype():
    connection = urconnectSettings()
    cursor = connection.cursor()
    executeCommand = "SELECT name, symbol FROM datatypes"
    cursor.execute(executeCommand,)
    datatypeSelector = cursor.fetchall()
    closeConnection(connection)
    return(datatypeSelector)


"""
    GET api_v2.html
    * Display current APIs.
"""


@app.route("/apis")
@login_required
def apis():
    connection = databaseConnection()
    credentials = getCredentialsName()
    result = getAPIs()
    interval = int(appconfig.get('TIME_INTERVAL', 'timeInterval'))
    closeConnection(connection)
    return render_template('apis_v2.html', name=current_user.name, result=result, interval=interval, credentials=credentials)


"""
    POST api_v2.html
    * Update API to database.
"""
@app.route("/apis", methods=['POST'])
@login_required
def apis_post():
    apiid = getAPIsID()
    for i in range(0, len(apiid)):
        currentAPIid = str(apiid[i][0])
        checkbox = "checkbox" + currentAPIid
        currentCheckbox = request.form.get(checkbox)
        if currentCheckbox == "checked":
            currentAPIName = request.form.get("apiname" + currentAPIid)
            currentURL = request.form.get("url" + currentAPIid)
            currentPort = request.form.get("port" + currentAPIid)
            currentPath = request.form.get("path" + currentAPIid)
            currentNexpieauth = request.form.get("nexpieauth" + currentAPIid)
            updateAPIs(currentAPIid, currentAPIName, currentURL,
                       currentPort, currentPath, currentNexpieauth)
            flash("Nexpie credentials updated successfully.")
            logger.info('User: ' + current_user.name +
                        ' - Update APIs.')
            logger.info('User: ' + current_user.name +
                        ' - API Name (' + currentAPIName + ') updated.')
            logger.info('User: ' + current_user.name +
                        ' - URL (' + currentURL + ') updated.')
            logger.info('User: ' + current_user.name +
                        ' - Port (' + currentPort + ') updated.')
            logger.info('User: ' + current_user.name +
                        ' - Path (' + currentPath + ') updated.')
            logger.info('User: ' + current_user.name +
                        ' - Nexpie Auth (' + currentNexpieauth + ') updated.')
    return redirect(url_for('apis'))


@app.route("/apis/add", methods=['POST'])
@login_required
def apis_add_post():
    apiname = request.form.get("newAPIname")
    url = request.form.get("newURL")
    port_url = request.form.get("newPort")
    path_url = request.form.get("newPath")
    nexpieauth = request.form.get("newnexpieauth")

    checked = inputCheckerNewAPI(apiname, url, port_url, path_url, nexpieauth)
    if checked != "Passed":
        flash(checked)
        return redirect(url_for('apis'))
    
    request_status = inputCheckerRequestAPI(url, port_url, path_url)
    if request_status != "Passed":
        flash(request_status)
        return redirect(url_for('apis'))

    status = addAPI(apiname, url, port_url, path_url, nexpieauth)
    flash(status)

    return redirect(url_for('apis'))


@app.route("/apis/delete", methods=['POST'])
@login_required
def apis_delete_post():
    try:
        apiname = request.form['deletebutton']
        print(apiname)
        result = deleteAPIs(apiname)
        if result == "success":
            flash('"' + apiname + '" deleted successfully.')
            return redirect(url_for('apis'))
        else:
            flash("Failed: Can't delete " + apiname + '" from database.')
            return redirect(url_for('apis'))
    except:
        flash("Failed: Can't delete selected apiname from database.")
        return redirect(url_for('apis'))

@app.route("/apis/export", methods=['POST'])
@login_required
def apis_export():
    dataList = request.form.getlist('exportbutton')
    apiname = dataList[0]
    api_data = getAPIsfromAPIsname(dataList[0])
    url = str(api_data[2])
    port = str(api_data[3])
    path = str(api_data[4])
    full_url = createFullURLfromAPI(url, port, path)
    # payload from api
    payload = requests.get(full_url)
    payload_data = payload.json()
    schema_device = createSchemaDevice(payload_data['data'])
    schema_device = json.dumps(schema_device)
    return Response(schema_device, 
            mimetype='application/json',
            headers={'Content-Disposition':'attachment;filename='+apiname+'.json'})

"""
    GET index.html
    * Display current uRCONNECT's config.
"""
@app.route("/index")
@login_required
def index():
    # Check table "urconnect_address"
    connection = databaseConnection()
    data = getConfig()
    tab = getTab()
    credentials = getCredentialsName()
    cursor = connection.cursor()
    executeCommand = "SELECT * FROM urconnect_address"
    cursor.execute(executeCommand)
    result = cursor.fetchall()
    interval = int(appconfig.get('TIME_INTERVAL', 'timeInterval'))
    closeConnection(connection)
    return render_template('index.html', name=current_user.name, result=result, tab=tab, data=data, interval=interval, credentials=credentials)


"""
    POST index.html
    * Update uRCONNECT's config.
"""
@app.route("/index", methods=['POST'])
@login_required
def index_post():
    name = current_user.name
    idTuple = getConfigID()
    for i in range(0, len(idTuple)):
        """
        Get unit id from input, then compare it.
        Selected device => got unit id from input, if not => got None from input.
        """
        htmlUnitid = "id_unitid" + str(idTuple[i][0])
        unitid = request.form.get(htmlUnitid)
        if unitid != None:
            number = str(idTuple[i][0])
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
            nexpieauthForm = "nexpieauth" + str(number)
            nexpieauth = request.form.get(nexpieauthForm)
            checked = checkUrconnect(ip, unitid)
            if checked != "Passed":
                flash(checked)
                return redirect('index')
            checked = inputChecker(
                ip, unitid, devicename, oldip, oldunitid, oldname)
            if checked != "Passed":
                flash(checked)
                return redirect('index')
            interval = str(request.form.get("interval"))
            checked = writeInterval(interval)
            if checked != "Passed":
                flash(checked)
                return redirect('index')
            # Get length of channel of urconnect from ip address.
            result = updateConfig(
                ip, unitid, devicename, oldunitid, oldip, oldname, checkbox, nexpieauth)
            connection = databaseConnection()
            cursor = connection.cursor()
            for i in range(0, len(result)):
                id = result[i][0]
                nameForm = "name" + str(id)
                name = request.form.get(nameForm)
                unitForm = "unit" + str(id)
                unit = request.form.get(unitForm)
                checkboxForm = "checkbox" + str(id)
                checkbox = request.form.get(checkboxForm)
                if name == "":
                    pass
                else:
                    try:
                        if checkbox != "enabled":
                            checkbox = "disabled"
                        unit = str(unit)
                        executeCommand = "UPDATE urconnect_address SET name = %s, unit = %s, status = %s WHERE id = %s"
                        cursor.execute(
                            executeCommand, (name, unit, checkbox, id,))
                        connection.commit()
                    except:
                        pass
            closeConnection(connection)
            flash("Updated Successfully")
            logger.info('User: ' + current_user.name +
                        ' - "' + devicename + '" updated.')
            return redirect('index')


"""
    GET powermeter.html
    * Display powermeter's address that use in IDA Platform.
"""
@app.route("/powermeter")
@login_required
def powermeter():
    try:
        # uRCONNECT tab
        powermeter = getPowermeter()
        data = getConfig()
        # powermeter tab
        urconnect = getUrconnect()
        powermeterAddress = getPowermeterAddress()
        powermeterTab = getPowermeterTab()
        datatypeSelector = getDatatype()
    except:
        return render_template("powermeter.html", name=current_user.name)
    return render_template("powermeter.html", name=current_user.name, urconnect=urconnect, powermeter=powermeter,
                           powermeterTab=powermeterTab, powermeterAddress=powermeterAddress, datatypes=datatypeSelector)


@app.route("/powermeter", methods=['POST'])
@login_required
def powermeter_post():
    try:
        # First: update powermeter name & urconnect.
        name = current_user.name
        oldmetername = request.form.get("oldmetername")
        metername = request.form.get("metername")
        metername = metername.replace(" ", "_")
        urconnect = request.form.get("urconnect")
        # Second: update powermeter address.
        connection = databaseConnection()
        cursor = connection.cursor()
        executeCommand = "SELECT id FROM powermeter_address WHERE metername = %s"
        cursor.execute(executeCommand, (oldmetername,))
        result = cursor.fetchall()
        for i in range(0, len(result)):
            id = result[i][0]
            modbustypeForm = "type" + str(id)
            modbustype = request.form.get(modbustypeForm)
            # Delete command = "99" | None = "00"
            if modbustype == "99":
                executeCommand = "DELETE FROM powermeter_address WHERE id = %s"
                cursor.execute(executeCommand, (id,))
            elif modbustype != "00":
                nameForm = "name" + str(id)
                startaddrForm = "startaddr" + str(id)
                datatypeForm = "datatype" + str(id)
                multiplierForm = "multiplier" + str(id)
                unitForm = "unit" + str(id)

                name = request.form.get(nameForm)
                modbustype = request.form.get(modbustypeForm)
                startaddr = request.form.get(startaddrForm)
                datatype = request.form.get(datatypeForm)
                multiplier = request.form.get(multiplierForm)
                unit = request.form.get(unitForm)
                unit = str(unit)
                # Check if address & quantity are integer, then update database.
                checkerResult, realaddress, quantity = powermeterAddressChecker(
                    name, modbustype, startaddr, multiplier, datatype)
                if checkerResult == "Passed":
                    executeCommand = "UPDATE powermeter_address SET name = %s, modbustype = %s, address = %s , multiplier = %s, datatype = %s, realaddress = %s, quantity = %s, unit = %s WHERE id = %s"
                    cursor.execute(executeCommand, (name, modbustype, startaddr,
                                                    multiplier, datatype, realaddress, quantity, unit, id,))
                else:
                    pass
        connection.commit()
        updatePowermeter(metername, urconnect, oldmetername)
        updateBlankInput(metername)
        closeConnection(connection)

        flash("Updated Successfully")
        logger.info('User: ' + current_user.name + ' - "' +
                    metername + '" powermeter config updated.')
        return redirect(url_for('powermeter'))

    except:
        flash("Updated failed")
        return redirect(url_for('powermeter'))


@app.route("/powermeter/add", methods=['POST'])
@login_required
def powermeter_add_post():
    try:
        metername = request.form.get("powermetername")
        urconnect = request.form.get("newurconnect")
        newPowermeter(metername, urconnect)
        flash('"' + metername + '" added successfully.')
    except:
        flash('Failed: Cannot add "' + metername + '" to database.')
    return redirect(url_for('powermeter'))


@app.route("/powermeter/delete", methods=['POST'])
@login_required
def powermeter_delete_post():
    try:
        metername = request.form.get("metername")
        deletePowermeter(metername)
        flash('"' + metername + '" deleted successfully.')
        return redirect(url_for('powermeter'))
    except:
        flash('Failed: Cannot delete "' + metername + '" from database.')
    return redirect(url_for('powermeter'))


"""
    POST newdevice, GET index.html
    * Add new uRCONNECT to database.
"""
@app.route("/index/add", methods=['POST'])
@login_required
def newdevice_post():
    ip = request.form.get("newip")
    unitid = request.form.get("newunitid")
    checkbox = request.form.get("newcheckbox")
    devicename = request.form.get("newdevicename")
    nexpieauth = request.form.get("newnexpieauth")
    checked = inputCheckerNewDevice(ip, unitid, devicename)
    if checked != "Passed":
        flash(checked)
        return redirect(url_for('index'))
    try:
        cardList = readCard(ip, unitid)
    except:
        cardList = "Failed: Can't connect to " + ip + ", unit id " + unitid
    if cardList == "Failed: Can't connect to " + ip + ", unit id " + unitid:
        flash(cardList)
        return redirect(url_for('index'))
    newDevice(ip, unitid, checkbox, devicename, nexpieauth)
    resultList = getModbusType("urconnect_settings", cardList)
    connection = databaseConnection()
    cursor = connection.cursor()
    for i in range(0, len(resultList)):
        name = "ch" + str(resultList[i][2]) + "_" + str(resultList[i][1])
        executeCommand = ("INSERT INTO urconnect_address (unitid, module, channel, type, name, startingAddress, quantity, urconnect, "
                          "displayAddress, cardtype, status) VALUES ( %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)")
        cursor.execute(executeCommand, (unitid, resultList[i][1], resultList[i][2], resultList[i][0], name,
                                        resultList[i][3], resultList[i][4], devicename, resultList[i][5], resultList[i][6], "disabled"))
    connection.commit()
    closeConnection(connection)
    flash('"' + devicename + '" added successfully.')
    logger.info('User: ' + current_user.name + ' - ' + devicename +
                "(" + ip + ", " + unitid + ') added to database.')
    return redirect(url_for('index'))


"""
    GET credentials.html
    * Display current NEXPIE credentials.
"""
@app.route("/credentials")
@login_required
def credentials():
    result = getNexpieAuth()
    if result == []:
        haveData = False
        return render_template('credentials_false.html', name=current_user.name)
    else:
        haveData = True
        return render_template('credentials.html', name=current_user.name, result=result)


"""
    POST credentials.html
    * Update NEXPIE credential to database.
"""
@app.route("/credentials", methods=['POST'])
@login_required
def credentials_post():
    name = current_user.name
    nexpieid = getNexpieID()
    for i in range(0, len(nexpieid)):
        currentNexpieid = str(nexpieid[i][0])
        checkbox = "checkbox" + currentNexpieid
        currentCheckbox = request.form.get(checkbox)
        if currentCheckbox == "checked":
            currentName = request.form.get("name" + currentNexpieid)
            currentClientID = request.form.get("clientid" + currentNexpieid)
            currentToken = request.form.get("token" + currentNexpieid)
            currentSecret = request.form.get("secret" + currentNexpieid)
            if currentName != None and len(currentClientID) == 36 and len(currentToken) == 32 and len(currentSecret) == 32:
                currentChecker = clientidChecker(currentClientID)
                if currentChecker == True:
                    updateNexpieCredentials(
                        currentNexpieid, currentName, currentClientID, currentToken, currentSecret)
                    flash("Nexpie credentials updated successfully.")
                    logger.info('User: ' + current_user.name +
                                ' - Update NEXPIE credentials.')
                    logger.info('User: ' + current_user.name +
                                ' - Name (' + currentName + ') updated.')
                    logger.info('User: ' + current_user.name +
                                ' - Clientid (' + currentClientID + ') updated.')
                    logger.info('User: ' + current_user.name +
                                ' - Token (' + currentToken + ') updated.')
                    logger.info('User: ' + current_user.name +
                                ' - Secret (' + currentSecret + ') updated.')
                else:
                    flash("Failed: Please recheck client id format.")
            elif len(currentClientID) != 36:
                flash("Failed: Client ID must be 36 characters.")
            elif len(currentToken) != 32:
                flash("Failed: Token must be 32 characters.")
            elif len(currentSecret) != 32:
                flash("Failed: Secret must be 32 characters.")
    return redirect(url_for('credentials'))


@app.route("/credentials/delete", methods=['POST'])
@login_required
def credentials_delete_post():
    try:
        nexpiename = request.form['deletebutton']
        usageResult = chkCredentialUsage(nexpiename)
        # Check library usage before delete.
        # Script cannot delete library if it used in any powermeter.
        if usageResult == "used":
            flash('Failed:  "' + nexpiename +
                  '" is currently in use. Please deactivate uRCONNECT that using "' + nexpiename + '".')
            return redirect(url_for('credentials'))
        elif usageResult == "not used":
            pass
        else:
            flash('Failed: Cannot delete "' + nexpiename + '" from database.')
            return redirect(url_for('credentials'))

        # If it not used, then delete nexpie credentials.
        result = deleteCredentials(nexpiename)
        if result == "success":
            flash('"' + nexpiename + '" deleted successfully.')
            return redirect(url_for('credentials'))
        else:
            flash("Failed: Can't delete " + nexpiename + '" from database.')
            return redirect(url_for('credentials'))
    except:
        flash("Failed: Can't delete selected devicename from database.")
        return redirect('credentials')

# Add new nexpie device.
@app.route("/credentials/add", methods=['POST'])
@login_required
def credentials_add_post():
    name = current_user.name
    newDevicename = request.form.get("newDevicename")
    newClientID = request.form.get("newClientID")
    newToken = request.form.get("newToken")
    newSecret = request.form.get("newSecret")
    #newCheckbox = request.form.get("newCheckbox")
    if newDevicename != None and len(newClientID) == 36 and len(newToken) == 32 and len(newSecret) == 32:
        resultChecker = clientidChecker(newClientID)
        if resultChecker == True:
            addNexpieCredentials(
                newDevicename, newClientID, newToken, newSecret)
            flash("Nexpie credentials: " +
                  newDevicename + " added successfully.")
            logger.info('User: ' + current_user.name +
                        ' - Add new NEXPIE credentials.')
            logger.info('User: ' + current_user.name +
                        ' - Name (' + newDevicename + ') Added.')
        else:
            flash("Failed: Please recheck client id format.")
    elif newDevicename == None:
        flash("Failed: Devicename cannot be blank.")
    elif len(newClientID) != 36:
        flash("Failed: Client ID must be 36 characters.")
    elif len(newToken) != 32:
        flash("Failed: Token must be 32 characters.")
    elif len(newSecret) != 32:
        flash("Failed: Secret must be 32 characters.")
    return redirect(url_for('credentials'))


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
        # if the user doesn't exist or password is wrong, reload the page.
        return redirect(url_for('login'))
    login_user(user)
    logger.info('User: ' + current_user.name +
                ' - Successfully logged in.')
    return redirect(url_for('index'))


"""
    POST deleteconfig, GET index.html
    * Delete uRCONNECT from database.
"""
@app.route('/index/delete', methods=['POST'])
@login_required
def deleteconfig_post():
    urconnect = request.form.get('urconnect')
    result = deleteConfig(urconnect)
    if result == "deleted":
        flash('"' + urconnect + '" deleted successfully.')
    elif result == "not delete":
        flash('Failed:  "' + urconnect +
              '" is currently in use. Please deactivate powermeter that using ' + urconnect + '.')
    else:
        flash('Cannot delete "' + urconnect + '".')
    logger.info('User: ' + current_user.name + ' - "' +
                str(urconnect) + '" deleted successfully.')
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
@app.route('/user', methods=['POST'])
@login_required
def user_post():
    currentpasswordInput = request.form.get('currentpassword')
    checkingResult = check_password_hash(
        current_user.password, currentpasswordInput)
    if checkingResult == True:
        password = request.form.get('password')
        repassword = request.form.get('repassword')
        if password == "" and repassword == "":
            flash("Failed: Password cannot be blank.")
        elif password == repassword:
            encryptedPassword = generate_password_hash(
                password, method='sha256')
            changePassword(encryptedPassword, current_user.name)
            flash("Password changed successfully.")
            logger.info('User: ' + current_user.name +
                        ' - Successfully changed password.')
            logger.info('User: ' + current_user.name +
                        ' - Successfully logged out.')
            logout_user()
            return redirect(url_for('login'))
        else:
            flash("Failed: Those password didn't match.")
    else:
        flash("Failed: Current password didn't match.")
    return redirect(url_for('user'))


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
    * Start modbus thread
    * Note: read enabled device from DB. => get NEXPIE credentials from DB => read value from uRCONNECT
    * => convert to JSON => send to NEXPIE.

    ** New method >>> APIs **
    * Note read apis from DB => get NEXPIE credentials from DB => get requests from apis
    * => send to NEXPIE if last_update > last_update_old

    ! IMPORTANT! : After update uRCONNECT settings, APIs and/or NEXPIE credential. You need to restart application to take effect.
    ***************************************************************************************************************************
    ** FAG **
    * Q: Why we need to query data from database only 1 time?
    * A: Our database server hardware & internet connection isn't stable enough for multiple concurrent connections.
"""


def threadedModbus():
    logger.info("Thread: modbusReader started.")
    try:
        preparedList, meternameList = prepareAddress()
        # logger.info('uRCONNECT: ' + str(urconnectList))
        logger.info('Read enabled device from DB: Success')
    except:
        logger.debug('Read enabled device from DB: Error')

    try:
        apiList = prepareAPI()
        logger.info('Read APIs from DB: Success')
    except:
        logger.debug('Read APIs from DB: Error')

    """
        ** modbus2Nexpie **
        1. Get time interval value from app_config.ini
        2. Read data from uRCONNECT using pyModbusTCP.
        3. Append read data to JSON variable
        4. Send JSON to NEXPIE.
        5. Wait for x second(s) [x = time interval]
    """
    """
        ** PayloadAPIs2NexPie **
        1. Get time interval value from app_config.ini
        2. Read payload from APIs using requests
        3. check last_update (only send payload to NEXPIE only updated data)
        4. Send JSON to NEXPIE.
        5. Update last_update
        6. Wait for x second(s) [x = time interval]
    """
    while True:
        # try:
        #     TIME_INTERVAL = int(appconfig.get('TIME_INTERVAL', 'timeInterval'))
        #     modbus2Nexpie(preparedList, meternameList)
        #     apiList = PayloadAPIs2NexPie(apiList)
        #     time.sleep(TIME_INTERVAL)
        # except:
        #     logger.debug(
        #         "Modbus reader/APIs error - Please check your configuration, NEXPIE server status or APIs endpoint.")
        #     time.sleep(15)

        TIME_INTERVAL = int(appconfig.get('TIME_INTERVAL', 'timeInterval'))
        flag_modbus_error = False
        flag_api_error = False
        try:
            modbus2Nexpie(preparedList, meternameList)
        except:
            flag_modbus_error = True
            logger.debug(
                "Modbus reader/APIs error - Please check your configuration or NEXPIE server status.")
        try:
            apiList = PayloadAPIs2NexPie(apiList)
        except:
            flag_api_error = True
            logger.debug(
                "Modbus reader/APIs error - Please check your APIs endpoint or NEXPIE server status.")

        if flag_modbus_error or flag_api_error:
            time.sleep(15)
        else:
            time.sleep(TIME_INTERVAL)

def prepareAddress():
    connection = databaseConnection()
    cursor = connection.cursor()
    executeCommand = "SELECT nexpieauth FROM config WHERE status = %s"
    cursor.execute(executeCommand, ("enabled",))
    urconnectList = cursor.fetchall()
    tempNexpieList = []
    for i in range(0, len(urconnectList)):
        urconnectNexpiename = str(urconnectList[i][0])
        nexpieauth = getNexpieCredentials(urconnectNexpiename)
        nexpiename = nexpieauth[0][0]
        clientid = nexpieauth[0][1]
        token = nexpieauth[0][2]
        secret = nexpieauth[0][3]
        tempNexpieList.append([nexpiename, clientid, token, secret])
    nexpieList = []
    for i in range(0, len(tempNexpieList)):
        if i not in nexpieList:
            nexpieList.append(tempNexpieList[i])
    meternameList = []
    preparedList = []
    for numNexpieList in range(0, len(nexpieList)):
        nexpiename = nexpieList[numNexpieList][0]
        clientid = nexpieList[numNexpieList][1]
        token = nexpieList[numNexpieList][2]
        secret = nexpieList[numNexpieList][3]
        addressDict = {}
        addressDict["credentials"] = {}
        addressDict["credentials"]["nexpiename"] = nexpiename
        addressDict["credentials"]["clientid"] = clientid
        addressDict["credentials"]["token"] = token
        addressDict["credentials"]["secret"] = secret
        addressDict["urconnect"] = []
        connection = databaseConnection()
        cursor = connection.cursor()
        executeCommand = "SELECT unitid, ip, urconnect, nexpieauth FROM config WHERE status = %s and nexpieauth = %s"
        cursor.execute(executeCommand, ("enabled", nexpiename))
        urconnectList = cursor.fetchall()
        for i in range(0, len(urconnectList)):
            unitid = urconnectList[i][0]
            ip = urconnectList[i][1]
            urconnectname = urconnectList[i][2]
            tempdict = {"urconnectname": urconnectname,
                        "unitid": unitid, "ip": ip}
            moduleList = ["1down", "2up", "2down", "3up", "3down"]
            for n in range(0, len(moduleList)):
                executeCommand = (
                    'SELECT type, name, startingAddress, quantity, cardtype, module, channel, unit FROM urconnect_address WHERE unitid = %s and urconnect = %s and status = %s and module = %s')
                cursor.execute(
                    executeCommand, (unitid, urconnectname, "enabled", moduleList[n]))
                addressList = cursor.fetchall()
                modulename = "module_" + moduleList[n]
                tempdict[modulename] = []
                for m in range(0, len(addressList)):
                    modbustype = str(addressList[m][0])
                    addressname = str(addressList[m][1])
                    startaddr = int(addressList[m][2])
                    quantity = int(addressList[m][3])
                    #cardtype = str(addressList[m][4])
                    module = str(addressList[m][5])
                    #channel = str(addressList[m][6])
                    unit = str(addressList[m][7])
                    tempaddress = {"name": addressname, "startaddr": startaddr,
                                   "quantity": quantity, "modbustype": modbustype, "unit": unit}
                    tempdict[modulename].append(tempaddress)

            executeCommand = "SELECT metername, urconnect FROM powermeter WHERE urconnect = %s"
            cursor.execute(executeCommand, (urconnectname,))
            meterList = cursor.fetchall()
            tempmeternameList = []
            for n in range(0, len(meterList)):
                metername = str(meterList[n][0])
                tempmeternameList.append(metername)
                tempdict[metername] = []
                executeCommand = "SELECT name, quantity, datatype, realaddress, metername, modbustype, multiplier, unit FROM powermeter_address WHERE metername = %s and modbustype <> %s"
                cursor.execute(executeCommand, (metername, "00",))
                meteraddress = cursor.fetchall()
                for m in range(0, len(meteraddress)):
                    addressname = str(meteraddress[m][0])
                    quantity = int(meteraddress[m][1])
                    datatype = str(meteraddress[m][2])
                    startaddr = int(meteraddress[m][3])
                    METERNAME_POWERMETER_ADDR = str(meteraddress[m][4])
                    modbustype = str(meteraddress[m][5])
                    multiplier = float(meteraddress[m][6])
                    unit = str(meteraddress[m][7])
                    temppowermeter = {"name": addressname, "quantity": quantity, "datatype": datatype,
                                      "startaddr": startaddr, "modbustype": modbustype, "multiplier": multiplier, "unit": unit}
                    tempdict[metername].append(temppowermeter)
            meternameList.append(tempmeternameList)
            addressDict["urconnect"].append(tempdict)
        preparedList.append(addressDict)
    closeConnection(connection)
    return(preparedList, meternameList)

"""
    * Prepare api from api_endpoint DB
    * Return fullAPIsList, devicesList, lastUpdateList
"""


def createFullURLfromAPI(url, port, path):
    if port == '-':
        port = ''
    else:
        port = ':' + port
    full_url = url+port+path
    return full_url

def check_date_format(date_str):
    try:
        _ = datetime.strptime(date_str, '%Y-%m-%d %H:%M:%S')
        return True
    except:
        return False

def check_payload_type(payload_data):
    map_data_type = {'int': 'number', 'str': 'string', 'float': 'number'}
    try:
        for name in payload_data:
            value = str(payload_data[name])
            type_ = [map_data_type[map_] for map_ in map_data_type if isinstance(eval(value), eval(map_))][0]
        return True
    except:
        return False

def prepareAPI():
    connection = databaseConnection()
    cursor = connection.cursor()
    executeCommand = "SELECT * FROM api_endpoint"
    cursor.execute(executeCommand)
    apisList = cursor.fetchall()
    fullAPIsList  = []
    for api in apisList:
        apiname = str(api[1])
        url = str(api[2])
        port = str(api[3])
        path = str(api[4])
        device = str(api[5])
        lastupdate = api[6]
        nexpieauth = getNexpieCredentials(device)
        # nexpiename = nexpieauth[0][0]
        clientid = str(nexpieauth[0][1])
        token = str(nexpieauth[0][2])
        secret =str(nexpieauth[0][3])
        # if lastupdate is not None:
        #     lastupdate = datetime.strptime(lastupdate, '%Y-%m-%d %H:%M:%S')
        full_url = createFullURLfromAPI(url, port, path)
        api_dict = {
                        'apiname': apiname,
                        'url': full_url,
                        'clientid': clientid,
                        'token': token,
                        'secret': secret,
                        'lastupdate': lastupdate
        }
        fullAPIsList.append(api_dict)
    closeConnection(connection)
    return fullAPIsList

"""
    * Create Schema for device
"""

def createSchemaDevice(payload_data, ttlList=None, transformList=None):
    properties = {}
    map_data_type = {'int': 'number', 'str': 'string', 'float': 'number'}
    if ttlList is None:
        ttlList = ['7d'] * len(payload_data)
    if transformList is None:
        transformList = [''] * len(payload_data)
    print(payload_data)
    print(ttlList)
    print(transformList)
    for name, ttl, trans in zip(payload_data, ttlList, transformList):
        store = {'ttl': ttl}
        transform = {'expression': trans}
        value = str(payload_data[name])
        print(name, type(eval(value)))
        type_ = [map_data_type[map_] for map_ in map_data_type if isinstance(eval(value), eval(map_))][0]
        operation = {'store': store, 'transform': transform}
        properties.update({
                            name: {
                                    'operation': operation, 
                                    'type': type_
                                  }
                         })
    schema_device = {}
    schema_device['additionalProperties'] = False
    schema_device['properties'] = properties
    return schema_device

"""
    * Read current active uRCONNECT from database.
    * Return value that pyModbusTCP need.
"""


def readAddress():
    connection = databaseConnection()
    cursor = connection.cursor()
    executeCommand = "SELECT unitid, ip, urconnect, nexpieauth FROM config WHERE status = %s"
    cursor.execute(executeCommand, ("enabled",))
    urconnectList = cursor.fetchall()
    addressList = []
    ipList = []
    powermeterList = []
    powermeteraddressList = []
    STATUS_ENABLED = "enabled"
    for i in range(0, len(urconnectList)):
        executeCommand = (
            'SELECT type, name, startingAddress, quantity, cardtype, module, channel, unit FROM urconnect_address WHERE unitid = %s and urconnect = %s and status = %s')
        UNIT_ID = int(urconnectList[i][0])
        IP_ADDRESS = str(urconnectList[i][1])
        URCONNECT_NAME = str(urconnectList[i][2])
        cursor.execute(
            executeCommand, (UNIT_ID, URCONNECT_NAME, STATUS_ENABLED,))
        result = cursor.fetchall()
        addressList.append(result)
        ipList.append(IP_ADDRESS)
        powermeterList, powermeteraddressList = readPowermeter(
            URCONNECT_NAME, powermeterList, powermeteraddressList)
    closeConnection(connection)
    return(urconnectList, addressList, powermeterList, powermeteraddressList)


def readPowermeter(urconnect, powermeterList, powermeteraddressList):
    connection = databaseConnection()
    cursor = connection.cursor()
    executeCommand = "SELECT metername, urconnect FROM powermeter WHERE urconnect = %s"
    cursor.execute(executeCommand, (urconnect,))
    result = cursor.fetchall()
    for i in range(0, len(result)):
        # append tuple (metername, urconnect) instead of [(metername0, urconnect0), (metername1, urconnect1)]
        powermeterList.append(result[i])
        metername = str(result[i][0])
        executeCommand = "SELECT name, quantity, datatype, realaddress, metername, modbustype, multiplier, unit FROM powermeter_address WHERE metername = %s and modbustype <> %s"
        cursor.execute(executeCommand, (metername, "00",))
        meteraddress = cursor.fetchall()
        # [[(addr_0), (addr_1), ..., (addr_n)], [(addr_0), (addr_1), ..., (addr_n)]]
        powermeteraddressList.append(meteraddress)
    closeConnection(connection)
    return(powermeterList, powermeteraddressList)


"""
    * Read value from uRCONNECT
    * Read every channel from every module (up to 40 channel) then convert to json format.
"""


def modbus2Nexpie(addressList, meternameList):
    PORT_NUMBER = 502
    for nexpiename in range(0, len(addressList)):
        payloaddata = {"data": {}}
        # load urconnect data from addressList.
        nexpiedeviceName = addressList[nexpiename]['credentials']['nexpiename']
        for j in range(0, len(addressList[nexpiename]["urconnect"])):
            urconnectname = addressList[nexpiename]["urconnect"][j]["urconnectname"]
            IP_ADDRESS = addressList[nexpiename]["urconnect"][j]["ip"]
            UNIT_ID = addressList[nexpiename]["urconnect"][j]["unitid"]
            payloaddata["data"][urconnectname] = {}
            payloaddata["data"][urconnectname]['detail'] = {}
            payloaddata["data"][urconnectname]['detail']["ip"] = IP_ADDRESS
            payloaddata["data"][urconnectname]['detail']["unitid"] = UNIT_ID
            #
            for n in range(0, 5):
                moduleDict = {
                    0: "module_1down",
                    1: "module_2up",
                    2: "module_2down",
                    3: "module_3up",
                    4: "module_3down"
                }
                module = moduleDict[n]
                payloaddata["data"][urconnectname][module] = {}
                client = ModbusClient(
                    auto_open=True, timeout=3, host=IP_ADDRESS, port=PORT_NUMBER, unit_id=UNIT_ID, debug=True)
                for m in range(0, len(addressList[nexpiename]["urconnect"][j][module])):
                    modbustype = addressList[nexpiename]["urconnect"][j][module][m]['modbustype']
                    startaddr = addressList[nexpiename]["urconnect"][j][module][m]['startaddr']
                    quantity = addressList[nexpiename]["urconnect"][j][module][m]['quantity']
                    addressname = addressList[nexpiename]["urconnect"][j][module][m]['name']
                    unit = addressList[nexpiename]["urconnect"][j][module][m]['unit']
                    payloaddata["data"][urconnectname][module][addressname] = {}
                    if not client.is_open():
                        if not client.open():
                            logger.error("unable to connect to " +
                                         IP_ADDRESS + ":" + str(PORT_NUMBER))
                    if client.is_open():
                        # type = FC (e.g. type 04 == FC04: Read Input Register)
                        data = modbusReader(
                            modbustype, startaddr, quantity, client)
                        if modbustype == "04":
                            data = getFloat32swapped(data, 1)
                        payloaddata["data"][urconnectname][module][addressname]["value"] = data
                        payloaddata["data"][urconnectname][module][addressname]["unit"] = unit
            for n in range(0, len(meternameList[nexpiename])):
                metername = meternameList[nexpiename][n]
                payloaddata["data"][urconnectname][metername] = {}
                for m in range(0, len(addressList[nexpiename]["urconnect"][j][metername])):
                    addressname = addressList[nexpiename]["urconnect"][j][metername][m]['name']
                    modbustype = addressList[nexpiename]["urconnect"][j][metername][m]['modbustype']
                    datatype = addressList[nexpiename]["urconnect"][j][metername][m]['datatype']
                    startaddr = addressList[nexpiename]["urconnect"][j][metername][m]['startaddr']
                    multiplier = addressList[nexpiename]["urconnect"][j][metername][m]['multiplier']
                    quantity = addressList[nexpiename]["urconnect"][j][metername][m]['quantity']
                    unit = addressList[nexpiename]["urconnect"][j][metername][m]['unit']
                    payloaddata["data"][urconnectname][metername][addressname] = {}
                    if not client.is_open():
                        if not client.open():
                            logger.error("unable to connect to " +
                                         IP_ADDRESS + ":" + str(PORT_NUMBER))
                    if client.is_open():
                        # type = FC (e.g. type 04 == FC04: Read Input Register)
                        data = powermeterConverter(
                            IP_ADDRESS, UNIT_ID, startaddr, quantity, modbustype, datatype, multiplier, client)
                        payloaddata["data"][urconnectname][metername][addressname]["value"] = data
                        payloaddata["data"][urconnectname][metername][addressname]["unit"] = unit
        now = datetime.now(tz=timezone('Asia/Bangkok'))
        # currentTime = now.strftime("%d/%m/%Y %H:%M:%S")
        currentTime = now.strftime("%Y-%m-%d %H:%M:%S")
        payloaddata["data"]["currentTime"] = currentTime
        
        # ! Add convert json for NEXPIE
        payloaddata = convertPayloadModbus(data=payloaddata['data'])

        nexpieShadow = json.dumps(payloaddata)
        clientid = addressList[nexpiename]["credentials"]["clientid"]
        token = addressList[nexpiename]["credentials"]["token"]
        secret = addressList[nexpiename]["credentials"]["secret"]
        payloadPost(nexpieShadow, clientid, token, secret)


"""
    Convert payloaddata from modbus2Nexpie
"""

def convertPayloadModbus(data):
    payloaddata = {
        "data": {}, 
        'currentTime': data['currentTime']
    }
    module_list = ['module_1down', 'module_2up', 'module_2down', 'module_3up', 'module_3down']

    for primary_d in data.keys():
        if primary_d != 'currentTime':  
            for module in module_list:
                try:
                    for ch in data[primary_d][module].keys():
                        value = data[primary_d][module][ch]['value']
                        unit = data[primary_d][module][ch]['unit']
                        if value != False:
                            if unit != 'None':
                                ch_split = ch.split('_')
                                d_name = primary_d + '_' + ch_split[-1] + '_' + ch_split[0] + '_' + str(unit)
                                payloaddata['data'][d_name] = value
                except:
                    pass
    
    return payloaddata

def PayloadAPIs2NexPie(apisList):
    new_apisList = []
    for api_data in apisList:
        apiname = api_data['apiname']
        clientid = api_data['clientid']
        token = api_data['token']
        secret = api_data['secret']
        url = api_data['url']
        lastupdate_old = api_data['lastupdate']

        payload = requests.get(url)
        data = payload.json()
        lastupdate_now = datetime.strptime(data['last_update'], '%Y-%m-%d %H:%M:%S')
        if lastupdate_old is None:
            dataShadow = json.dumps(data)
            payloadPost(dataShadow, clientid, token, secret)
            lastupdate = lastupdate_now
        elif lastupdate_now > lastupdate_old:
            dataShadow = json.dumps(data)
            payloadPost(dataShadow, clientid, token, secret)
            lastupdate = lastupdate_now
        else:
            lastupdate = lastupdate_old

        api_dict = {
            'apiname': apiname,
            'url': url,
            'clientid': clientid,
            'token': token,
            'secret': secret,
            'lastupdate': lastupdate
        }
        new_apisList.append(api_dict)
    
    return new_apisList

def getFloat32(valueArray, multiplier):
    packedUint16 = struct.pack('>HH', valueArray[0], valueArray[1])
    convertedFloat32 = struct.unpack('>f', packedUint16)
    multipliedValue = convertedFloat32[0] * float(multiplier)
    data = float("%.3f" % multipliedValue)
    return(data)


def getFloat32swapped(valueArray, multiplier):
    packedUint16 = struct.pack('>HH', valueArray[1], valueArray[0])
    convertedFloat32 = struct.unpack('>f', packedUint16)
    multipliedValue = convertedFloat32[0] * float(multiplier)
    data = float("%.3f" % multipliedValue)
    return(data)


def getUint32(valueArray, multiplier):
    packedUint16 = struct.pack('>HH', valueArray[0], valueArray[1])
    convertedUint32 = struct.unpack('>I', packedUint16)
    multipliedValue = float(convertedUint32[0]) * float(multiplier)
    data = float("%.3f" % multipliedValue)
    return(data)


def getUint32swapped(valueArray, multiplier):
    packedUint16 = struct.pack('>HH', valueArray[1], valueArray[0])
    convertedUint32 = struct.unpack('>I', packedUint16)
    multipliedValue = float(convertedUint32[0]) * float(multiplier)
    data = float("%.3f" % multipliedValue)
    return(data)


def getUint16(valueArray, multiplier):
    value = valueArray[0]
    data = float(valueArray[0]) * float(multiplier)
    return(data)


def modbusReader(type, startaddr, quantity, client):
    if type == "01":
        # Return list that contains True or False.
        data = client.read_coils(startaddr, quantity)
        data = data[0]
    elif type == "02":
        # Return list that contains True or False.
        data = client.read_discrete_inputs(startaddr, quantity)
        data = data[0]
    elif type == "03":
        # Return uint16 list.
        data = client.read_holding_registers(startaddr, quantity)
    elif type == "04":
        # Return uint16 list.
        data = client.read_input_registers(startaddr, quantity)
    else:
        data = None
    return(data)


def powermeterConverter(IP_ADDRESS, UNIT_ID, startaddr, quantity, modbustype, datatype, multiplier, client):
    valueArray = modbusReader(modbustype, startaddr, quantity, client)
    if valueArray == None:
        return(None)
    if datatype == "uint32":
        data = getUint32(valueArray, multiplier)
    if datatype == "uint32sw":
        data = getUint32swapped(valueArray, multiplier)
    elif datatype == "float32":
        data = getFloat32(valueArray, multiplier)
    elif datatype == "float32sw":
        data = getFloat32swapped(valueArray, multiplier)
    elif datatype == "uint16":
        data = getUint16(valueArray, multiplier)
    """
    elif converter == "uint64":
        getUint64(startingAddress, IP_ADDRESS, UNIT_ID, multiplier)

    elif converter == "float64":
        getFloat64(startingAddress, IP_ADDRESS, UNIT_ID, multiplier)
    """
    return(data)


"""
    * Get NEXPIE credential from database.
    * Return client id, username and password.
"""


def getNexpieCredentials(nexpiename):
    connection = databaseConnection()
    cursor = connection.cursor()
    executeCommand = "SELECT name, clientid, token, secret FROM nexpie_auth WHERE name = %s"
    cursor.execute(executeCommand, (nexpiename,))
    result = cursor.fetchall()
    try:
        connection.close()
    except:
        pass
    return(result)


"""
    * Send JSON data to NEXPIE using HTTPS Restful API
    * You can see result on nexpie.io
"""


def payloadPost(dataShadow, nexpieDeviceid, nexpieToken, nexpieSecret):
    basicAuthCredentials = (nexpieDeviceid, nexpieToken)  # clientid & token
    response = requests.post(NEXPIE_URL, data=dataShadow,
                             auth=basicAuthCredentials, timeout=5)
    try:
        if response.ok:
            logger.info('NEXPIE RestAPI response: SUCCESS' )
    except:
        logger.debug('NEXPIE RestAPI response: ' + str(response.text))
    # try:
    #     logger.info('NEXPIE RestAPI response: ' + str(response.text))
    # except:
    #     pass


"""
    * Application init.
    * Note: create user if not exists. => ping NEXPIE & DB server => start modbusReader thread
      => start web application => :)
"""
if __name__ == '__main__':
    logger.info("Logger: Started.")
    #app.debug = True
    nexpieLoopChecker = True
    while nexpieLoopChecker == True:
        try:
            r = pyping.ping('api.nexpie.io')
            if r.ret_code == 0:
                logger.info("Ping api.nexpie.io: Success!")

                nexpieLoopChecker = False
            else:
                logger.info("Ping api.nexpie.io: Failed!")
        except:
            time.sleep(5)
    webappLoopChecker = True
    while webappLoopChecker == True:
        try:
            r = pyping.ping(DB_IP)
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

    # app.run(host='0.0.0.0', port=6969, ssl_context=(CERT, KEY))
    app.run(host='0.0.0.0', port=6969, ssl_context=(CERT, KEY), debug=True)
