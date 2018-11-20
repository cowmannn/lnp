#!/bin/bash
#data: 2018.11.20
#AutoInstall LNP
clear
echo "#############################################################################"
echo "#                           Auto Install LNP.                              ##"
echo "#                           Press Ctrl + C to cancel                       ##"
echo "#                           Any key to continue                            ##"
echo "#############################################################################"
read -p 1
software_dir="/root/lnp/software"



########################## 安装依赖软件

if [ -s /etc/yum.conf ]; then
     cp /etc/yum.conf /etc/yum.conf.lnmp
     sed -i 's:exclude=.*:exclude=:g' /etc/yum.conf
fi

    for packages in make cmake gcc gcc-c++ gcc-g77 flex bison file libtool libtool-libs autoconf kernel-devel patch wget crontabs libjpeg libjpeg-devel libpng libpng-devel libpng10 libpng10-devel gd gd-devel libxml2 libxml2-devel zlib zlib-devel glib2 glib2-devel unzip tar bzip2 bzip2-devel libzip-devel libevent libevent-devel ncurses ncurses-devel curl curl-devel libcurl libcurl-devel e2fsprogs e2fsprogs-devel krb5 krb5-devel libidn libidn-devel openssl openssl-devel vim-minimal gettext gettext-devel ncurses-devel gmp-devel pspell-devel unzip libcap diffutils ca-certificates net-tools libc-client-devel psmisc libXpm-devel git-core c-ares-devel libicu-devel libxslt libxslt-devel xz expat-devel libaio-devel rpcgen libtirpc-devel perl;
    do yum -y install $packages; done

    if [ -s /etc/yum.conf.lnmp ]; then
        mv -f /etc/yum.conf.lnmp /etc/yum.conf
    fi


#####################################################

Make_Install()
{
    make -j `grep 'processor' /proc/cpuinfo | wc -l`
    if [ $? -ne 0 ]; then
        make
    fi
    make install
}


PHP_Make_Install()
{
    make ZEND_EXTRA_LIBS='-liconv' -j `grep 'processor' /proc/cpuinfo | wc -l`
    if [ $? -ne 0 ]; then
        make ZEND_EXTRA_LIBS='-liconv'
    fi
    make install
}



Ln_PHP_Bin()
{
    ln -sf /usr/local/php/bin/php /usr/bin/php
    ln -sf /usr/local/php/bin/phpize /usr/bin/phpize
    ln -sf /usr/local/php/bin/pear /usr/bin/pear
    ln -sf /usr/local/php/bin/pecl /usr/bin/pecl
    ln -sf /usr/local/php/sbin/php-fpm /usr/bin/php-fpm
    rm -f /usr/local/php/conf.d/*
}



Pear_Pecl_Set()
{
    pear config-set php_ini /usr/local/php/etc/php.ini
    pecl config-set php_ini /usr/local/php/etc/php.ini
}



Install_Composer()
{
    curl -sS --connect-timeout 30 -m 60 https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer
    if [ $? -eq 0 ]; then
        echo "Composer install successfully."
    else
        if [ -s /usr/local/php/bin/php ]; then
            wget --prefer-family=IPv4 --no-check-certificate -T 120 -t3 ${Download_Mirror}/web/php/composer/composer.phar -O /usr/local/bin/composer
            if [ $? -eq 0 ]; then
                echo "Composer install successfully."
            else
                echo "Composer install failed!"
            fi
            chmod +x /usr/local/bin/composer
        fi
    fi
}




############################ libiconv-1.15

cd $software_dir

#wget -c --progress=bar:force --prefer-family=IPv4 --no-check-certificate https://soft.vpser.net/web/libiconv/libiconv-1.15.tar.gz

tar zxf libiconv-1.15.tar.gz

cd $software_dir/libiconv-1.15

./configure --enable-static
Make_Install

cd $software_dir
rm -rf $software_dir/libiconv-1.15


############################ libmcrypt-2.5.8

cd $software_dir

#wget -c --progress=bar:force --prefer-family=IPv4 --no-check-certificate https://soft.vpser.net/web/libmcrypt/libmcrypt-2.5.8.tar.gz

tar zxf libmcrypt-2.5.8.tar.gz

cd $software_dir/libmcrypt-2.5.8/

./configure
Make_Install
/sbin/ldconfig
cd libltdl/
./configure --enable-ltdl-install
Make_Install
ln -sf /usr/local/lib/libmcrypt.la /usr/lib/libmcrypt.la
ln -sf /usr/local/lib/libmcrypt.so /usr/lib/libmcrypt.so
ln -sf /usr/local/lib/libmcrypt.so.4 /usr/lib/libmcrypt.so.4
ln -sf /usr/local/lib/libmcrypt.so.4.4.8 /usr/lib/libmcrypt.so.4.4.8
ldconfig

cd $software_dir
rm -rf $software_dir/libmcrypt-2.5.8/

###########################  mhash-0.9.9.9

cd $software_dir

#wget -c --progress=bar:force --prefer-family=IPv4 --no-check-certificate https://soft.vpser.net/web/mhash/mhash-0.9.9.9.tar.bz2

tar jxf mhash-0.9.9.9.tar.bz2

cd $software_dir/mhash-0.9.9.9

./configure
Make_Install

    ln -sf /usr/local/lib/libmhash.a /usr/lib/libmhash.a
    ln -sf /usr/local/lib/libmhash.la /usr/lib/libmhash.la
    ln -sf /usr/local/lib/libmhash.so /usr/lib/libmhash.so
    ln -sf /usr/local/lib/libmhash.so.2 /usr/lib/libmhash.so.2
    ln -sf /usr/local/lib/libmhash.so.2.0.1 /usr/lib/libmhash.so.2.0.1
    ldconfig

cd $software_dir
rm -rf $software_dir/mhash-0.9.9.9

############################ mcrypt-2.6.8

cd $software_dir

#wget -c --progress=bar:force --prefer-family=IPv4 --no-check-certificate https://soft.vpser.net/web/mcrypt/mcrypt-2.6.8.tar.gz

tar zxf mcrypt-2.6.8.tar.gz
cd $software_dir/mcrypt-2.6.8

./configure
Make_Install

cd $software_dir
rm -rf $software_dir/mcrypt-2.6.8


############################ freetype-2.7

cd $software_dir

#wget -c --progress=bar:force --prefer-family=IPv4 --no-check-certificate https://soft.vpser.net/lib/freetype/freetype-2.7.tar.bz2

tar jxf freetype-2.7.tar.bz2

cd $software_dir/freetype-2.7
./configure --prefix=/usr/local/freetype
Make_Install

mkdir -p /usr/lib/pkgconfig
cp /usr/local/freetype/lib/pkgconfig/freetype2.pc /usr/lib/pkgconfig/

cat > /etc/ld.so.conf.d/freetype.conf<<EOF
/usr/local/freetype/lib
EOF

ldconfig
ln -sf /usr/local/freetype/include/freetype2/* /usr/include/


############################# gperftools-2.7

cd $software_dir

#wget -c --progress=bar:force --prefer-family=IPv4 --no-check-certificate https://soft.vpser.net/lib/tcmalloc/gperftools-2.7.tar.gz

tar zxf gperftools-2.7.tar.gz

cd $software_dir/gperftools-2.7

./configure
Make_Install


############################ libunwind-1.2

cd $software_dir

#wget -c --progress=bar:force --prefer-family=IPv4 --no-check-certificate https://soft.vpser.net/lib/libunwind/libunwind-1.2.tar.gz

tar zxf libunwind-1.2.tar.gz

cd $software_dir/libunwind-1.2

./configure
Make_Install



############################ 添加用户，用户组

mkdir -p /data/www/
groupadd www
useradd -s /bin/bash -d /data/www/ -g www www

mkdir -p /data/www/.ssh

cat >> /data/www/.ssh/authorized_keys << EOF
ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAyzZgZM0EXJzo3vDExX/aof7FzB9X9GCtOdobd/Tqy6CrgFfbQEeeUJOt0gF7e3hMRvFUbIhdNAPYgVVyVW14MXdfgmFJipPxC5cVnBEhDjrYHmZ1X7DAPMs8Q00se1kC7dMW4N3FSBHRX6ubJXIv57P7UOEukQ6ib8UBlSKYQxNfffLqkDC94FBq35/hKidHhl04iem8e8dlhXG+AT9e3/7FQ5mNyR9Dv2jhDTFga6rzsTnOi+bwyAoMhRwiR9lay8K5UD7NzS+e4zrrwCM+3KC58BijE49Kapau3sE8xmdj4P6j1aYpLngjbphW27CDRZAlivNcbpsQigHVgM9ivQ==
EOF

chown www:www /data/www/ -R
chmod 600 /data/www/.ssh/authorized_keys
chmod 755 /data/www/.ssh
#chmod 600 /var/spool/cron/root
#chmod 600 /var/spool/cron/www
#chown www:www /var/spool/cron/www


############################ 编译安装php

cd $software_dir


#wget -c --progress=bar:force --prefer-family=IPv4 --no-check-certificate http://cn2.php.net/get/php-7.1.19.tar.gz/from/this/mirror

mv mirror php-7.1.19.tar.gz
tar zxf php-7.1.19.tar.gz

cat > /etc/ld.so.conf << EOF
include ld.so.conf.d/*.conf
/lib
/usr/lib
/usr/lib64
/usr/local/lib
EOF

/sbin/ldconfig


cd $software_dir/php-7.1.19

./configure --prefix=/usr/local/php --with-config-file-path=/usr/local/php/etc --with-config-file-scan-dir=/usr/local/php/conf.d --enable-fpm --with-fpm-user=www --with-fpm-group=www --enable-mysqlnd --with-mysqli=mysqlnd --with-pdo-mysql=mysqlnd --with-iconv-dir --with-freetype-dir=/usr/local/freetype --with-jpeg-dir --with-png-dir --with-zlib --with-libxml-dir=/usr --enable-xml --disable-rpath --enable-bcmath --enable-shmop --enable-sysvsem --enable-inline-optimization --with-curl --enable-mbregex --enable-mbstring --enable-intl --enable-pcntl --with-mcrypt --enable-ftp --with-gd --enable-gd-native-ttf --with-openssl --with-mhash --enable-pcntl --enable-sockets --with-xmlrpc --enable-zip --enable-soap --with-gettext --disable-fileinfo --enable-opcache --with-xsl

PHP_Make_Install
Ln_PHP_Bin

mkdir -p /usr/local/php/{etc,conf.d}
cp $software_dir/php-7.1.19/php.ini-production /usr/local/php/etc/php.ini
cp /root/lnp/redis.so /usr/local/php/lib/php/extensions/no-debug-non-zts-20160303

sed -i 's/post_max_size =.*/post_max_size = 50M/g' /usr/local/php/etc/php.ini
sed -i 's/upload_max_filesize =.*/upload_max_filesize = 50M/g' /usr/local/php/etc/php.ini
sed -i 's/;date.timezone =.*/date.timezone = PRC/g' /usr/local/php/etc/php.ini
sed -i 's/short_open_tag =.*/short_open_tag = On/g' /usr/local/php/etc/php.ini
sed -i 's/;cgi.fix_pathinfo=.*/cgi.fix_pathinfo=0/g' /usr/local/php/etc/php.ini
sed -i 's/disable_functions =.*/disable_functions = passthru,exec,system,chroot,chgrp,chown,shell_exec,proc_open,proc_get_status,popen,ini_alter,ini_restore,dl,openlog,syslog,readlink,symlink,popepassthru,stream_socket_server/g' /usr/local/php/etc/php.ini
sed -i 's/;error_log = syslog/error_log = \/data\/logs\/php\/php_error.log/g' /usr/local/php/etc/php.ini
sed -i 's/;opcache.enable=.*/opcache.enable=1/g' /usr/local/php/etc/php.ini
sed -i 's/;opcache.enable_cli=.*/opcache.enable_cli=1/g' /usr/local/php/etc/php.ini
sed -i 's/;opcache.memory_consumption=.*/opcache.memory_consumption=128/g' /usr/local/php/etc/php.ini
sed -i 's/;opcache.interned_strings_buffer=.*/opcache.interned_strings_buffer=8/g' /usr/local/php/etc/php.ini
sed -i 's/;opcache.max_accelerated_files=.*/opcache.max_accelerated_files=8000/g' /usr/local/php/etc/php.ini
sed -i 's/;opcache.validate_timestamps=.*/opcache.validate_timestamps=1/g' /usr/local/php/etc/php.ini
sed -i 's/;opcache.revalidate_freq=.*/opcache.revalidate_freq=0/g' /usr/local/php/etc/php.ini
sed -i 's/;opcache.fast_shutdown=.*/opcache.fast_shutdown=1/g' /usr/local/php/etc/php.ini
sed -i 's/;opcache.file_cache=.*/opcache.file_cache=\/tmp/g' /usr/local/php/etc/php.ini
sed -i '1780i zend_extension=opcache.so' /usr/local/php/etc/php.ini
sed -i '927i extension=redis.so' /usr/local/php/etc/php.ini


Pear_Pecl_Set
Install_Composer

cat >/usr/local/php/etc/php-fpm.conf<<EOF
[global]
pid = /usr/local/php/var/run/php-fpm.pid
error_log = /data/logs/php/php-fpm.log
log_level = notice

[www]
listen = /tmp/php-cgi.sock
listen.backlog = -1
listen.allowed_clients = 127.0.0.1
listen.owner = www
listen.group = www
listen.mode = 0666
user = www
group = www
pm = dynamic
pm.max_children = 10
pm.start_servers = 2
pm.min_spare_servers = 1
pm.max_spare_servers = 6
request_terminate_timeout = 100
request_slowlog_timeout = 10
slowlog = /data/logs/php/php_slow.log
EOF

cp /root/lnp/init.d.php-fpm.in /etc/init.d/php-fpm
chmod +x /etc/init.d/php-fpm



############################ openssl

cd $software_dir

#wget -c --progress=bar:force --prefer-family=IPv4 --no-check-certificate https://www.openssl.org/source/openssl-1.0.2p.tar.gz

tar zxf openssl-1.0.2p.tar.gz

cd $software_dir/openssl-1.0.2p

./config -fPIC --prefix=/usr/local/openssl --openssldir=/usr/local/openssl
make depend
Make_Install



############################ 编译nginx

cd $software_dir

#wget -c --progress=bar:force --prefer-family=IPv4 --no-check-certificate http://nginx.org/download/nginx-1.14.0.tar.gz

tar zxf nginx-1.14.0.tar.gz

cd $software_dir/nginx-1.14.0

./configure --user=www --group=www --prefix=/usr/local/nginx --with-http_stub_status_module --with-http_ssl_module --with-http_v2_module --with-http_gzip_static_module --with-http_sub_module --with-stream --with-stream_ssl_module --with-openssl=/root/lnp/software/openssl-1.0.2p

Make_Install


#######################################


rm -f /usr/local/nginx/conf/nginx.conf

mkdir -p /data/www/test.com
mkdir -p /data/www/nginx/vhost/
cat > /data/www/test.com/index.php << EOF
<?php 
phpinfo(); 
?>

EOF

mkdir -p /data/logs/nginx
mkdir -p /data/logs/php
chmod 755 /data/logs
chown -R www:www /data/logs

chmod +w /data/www/test.com
ln -s /data/www/nginx/vhost/ /usr/local/nginx/conf/

cd /root/lnp
cp p.php /data/www/test.com/
cp test.com.conf /usr/local/nginx/conf/vhost
cp nginx.conf /usr/local/nginx/conf/nginx.conf
cp init.d.nginx /etc/init.d/nginx
cp -ra rewrite /usr/local/nginx/conf/
cp pathinfo.conf /usr/local/nginx/conf/pathinfo.conf
cp enable-php.conf /usr/local/nginx/conf/enable-php.conf
cp enable-php-pathinfo.conf /usr/local/nginx/conf/enable-php-pathinfo.conf
cp enable-ssl-example.conf /usr/local/nginx/conf/enable-ssl-example.conf
cp magento2-example.conf /usr/local/nginx/conf/magento2-example.conf

chown -R www:www /data/www/test.com


###########################################


chmod +x /etc/init.d/nginx
chkconfig --add nginx
chkconfig nginx on

/sbin/iptables -I INPUT 1 -i lo -j ACCEPT
/sbin/iptables -I INPUT 2 -m state --state ESTABLISHED,RELATED -j ACCEPT
/sbin/iptables -I INPUT 3 -p tcp --dport 22 -j ACCEPT
/sbin/iptables -I INPUT 4 -p tcp --dport 80 -j ACCEPT
/sbin/iptables -I INPUT 5 -p tcp --dport 443 -j ACCEPT
/sbin/iptables -I INPUT 6 -p tcp --dport 3306 -j DROP
/sbin/iptables -I INPUT 7 -p icmp -m icmp --icmp-type 8 -j ACCEPT
service iptables save

systemctl stop firewalld
systemctl disable firewalld


###########################################

#set ulimit 65535
echo " * soft nofile 65535  ">> /etc/security/limits.conf
echo " * hard nofile 65535  ">> /etc/security/limits.conf
echo "session  required  pam_limits.so">> /etc/pam.d/login


##########################################

#selinux
setenforce 0
sed -i 's/SELINUX=.*/SELINUX=disabled/' /etc/selinux/config

##########################################

#ssh

#sed -i 's/#AuthorizedKeysFile/AuthorizedKeysFile/g' /etc/ssh/sshd_config
sed -i 's/PasswordAuthentication yes/PasswordAuthentication no/g' /etc/ssh/sshd_config
sed -i 's/#Port 22/Port 37671/g' /etc/ssh/sshd_config
sed -i 's/#UseDNS yes/UseDNS no/g' /etc/ssh/sshd_config

systemctl restart sshd

##########################################

/etc/init.d/nginx restart
/etc/init.d/php-fpm restart
chkconfig nginx on
chkconfig php-fpm on


#########################################


