---
title: 'postgresql 管理'
date: 2015-06-29 14:36
catalog: true
header-img: "/img/header_img/article-bg.png"
tags: [backend,database]
---
在postgresql裝好以後，先來設定一下使用者

首先先用postgres
`su - postgres`

再來建立使用者
`createuser`

可用`\du`看到使用者名單
可用`ALTER USER Postgres WITH PASSWORD '<newpassword>';`建立密碼

然後來建db
`psql`
`CREATE DATABASE db_name;`
`\l`

建db前可參考[這篇](https://gist.github.com/ffmike/877447)把模板改成自己想要的編碼

後來我在自己電腦連server連不上，發現是設定的一些問題
可參考 [這篇](http://stackoverflow.com/questions/2942485/psql-fatal-ident-authentication-failed-for-user-postgres)
設定檔在 `/var/lib/pgsql/data/pg_hba.conf`
把`ident`換成`password`
改完以後記得 `service postgresql restart`
然後就可以利用你剛建好的帳號跟密碼登進去遠端的db了

`ALTER DATABASE db_name OWNER TO huli;` 可更改某db的owner


[How To Install and Use PostgreSQL on a CentOS VPS](https://www.digitalocean.com/community/tutorials/how-to-install-and-use-postgresql-on-a-centos-vps)
[How To Use Roles and Manage Grant Permissions in PostgreSQL on a VPS](https://www.digitalocean.com/community/tutorials/how-to-use-roles-and-manage-grant-permissions-in-postgresql-on-a-vps--2)
[在 RHEL/CENTOS 6 Debian Linux 上使用 PostgreSQL資料庫](http://blog.jangmt.com/2011/04/rhelcentos-postgresql.html)
[Copying PostgreSQL database to another server](http://stackoverflow.com/questions/1237725/copying-postgresql-database-to-another-server)
http://www.revsys.com/writings/postgresql/errors.html

