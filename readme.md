# modbus_ida
<br>
<p align="center">
    <img src="/webapp/static/images/platelet.gif" width="700" height="394">
</p>

## Details
### Requirements (requirements.txt)
* Python v2.7
* Flask
* win-inet-pton
* requests
* pymodbusTCP
* flask-login
* flask-sqlalchemy
* mysql-connector-python
* pytz
* pyping
* gitpython
```sh
pip install -r requirements.txt
```
### Current structure
```
modbus_ida
├── /webapp
      ├── cert (self-signed certificate files)
      ├── req (python package requirement)
      ├── static (css, images ,javascript files)
      ├── templates (html files)
      └── webapp.py
├── app.py
├── app_config.ini
└── version.txt
```
### For Cisco IOx: Build IOx package from docker image
* [Download IOx Client from Cisco](https://software.cisco.com/download/home/286306005/type/286306762/release/1.10.0)
* Build docker image from dockerfile.
```
docker build -t modbus_ida .
```
* Save image to tar archive.
```
docker save -o rootfs.tar
```
* Build IOx package from tar archive. (IOx Client and tar archive in the same directory)
```
./ioxclient package .
```
### For other ARM 64-bit architecture.
* Add command to dockerfile
```
EXPOSE 6969
WORKDIR /modbus_ida
CMD ["python","app.py"]
```
* Build docker image from dockerfile.
```
docker build -t modbus_ida .
```
* Create docker container from docker image.
```
docker run -ti --restart=always modbus_ida
```
