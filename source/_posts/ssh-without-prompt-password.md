---
title: 'ssh without prompt password'
date: 2015-06-29 12:37
catalog: true
header-img: "/img/header_img/article-bg.png"
tags: [tool]
---
用ssh或是rsync的時候都會問你密碼，上網稍微搜尋了一下解法
我的電腦環境是mac，如果是linux的話可省略第一步

1. brew install ssh-copy-id
2. ssh-keygen (一直按enter即可)
3. ssh-copy-id -i ~/.ssh/id_rsa.pub 127.0.0.1

127.0.0.1就是你remote的server位置
這樣子就可以讓你的電腦在ssh或是rsync的時候不用輸入密碼了

