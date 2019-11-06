FROM php:7-apache

RUN apt-get update
RUN apt-get -y install lua5.3 xinetd procps iputils-ping net-tools python

COPY xinetd.conf /etc/
COPY lua.xinetd /etc/xinetd.d/lua
COPY index.php /var/www/html

COPY ./start.sh /start.sh
RUN chmod +x /start.sh

EXPOSE 80

CMD ["/start.sh"]
