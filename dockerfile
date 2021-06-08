FROM arm64v8/alpine:3.7
COPY qemu-aarch64-static /usr/bin
RUN apk add --no-cache python py-pip py-mysqldb
RUN rm -rf /var/cache/apk/*
RUN mkdir modbus_ida
COPY webapp /modbus_ida/webapp
RUN pip install -r /modbus_ida/webapp/req/requirements.txt
COPY app_config.ini /modbus_ida/app_config.ini
COPY version.txt /modbus_ida/version.txt
COPY app.py /modbus_ida/app.py
