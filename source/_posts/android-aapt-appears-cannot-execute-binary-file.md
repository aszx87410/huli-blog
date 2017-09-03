---
title: '[Android] aapt出現 cannot execute binary file'
date: 2015-06-12 17:30
catalog: true
header-img: "/img/header_img/article-bg.png"
tags: [Android]
---
在自己本機上(Mac)都沒問題，在CentOS上面就出事，出現cannot execute binary file的錯誤提示
google以後發現跟64bit與32bit有關
解決方法就是裝一些library
因為有些裝了之後還會報錯，所以就google解法之後再裝別的
```
yum -y install zlib.i686
yum -y install libstdc++
yum -y install libstdc++.i686
yum -y install glibc.i686
```