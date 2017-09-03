---
title: '[心得] 高併發伺服器設定'
date: 2016-02-23 18:08
catalog: true
header-img: "/img/header_img/article-bg.png"
tags: [backend]
---
當初在設定的時候有碰到一些問題，跟上網找一些解法
這篇純粹當作筆記，紀錄一下

vi /etc/sysctl.conf
加上
net.netfilter.ip_conntrack_max=65535
net.netfilter.nf_conntrack_max=65535

如果設置沒開，可以這樣打開
1. modprobe ip_conntrack
2. lsmod |grep conn 
4. sysctl -p
http://serverfault.com/questions/326687/what-is-the-correct-way-to-load-modules-for-iptables-on-centos-6

/var/log/messages
可以看到很多訊息

http://www.ahlinux.com/start/base/21338.html
http://www.ttlsa.com/yun_wei_an_li/tcp_-time-wait-bucket-table-overflow-solution/

寫入/etc/sysctl.conf使之永久生效
net.ipv4.tcp_max_tw_buckets = 20000

SHOW INNODB STATUS;
看db log

/etc/my.cnf
innodb_lock_wait_timeout 等待鎖時間
innodb_thread_concurrency

/etc/init.d/mysqld restart