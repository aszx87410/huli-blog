---
title: 'URL 加號（+）與空白的問題'
date: 2015-12-03 12:40
catalog: true
header-img: "/img/header_img/article-bg.png"
tags: [other]
---
最近碰到一個問題，原本的字串是`A+B`好了，從client端傳到對方的server
但是對方的server傳給我這邊以後，就變成`A B`，導致字串變得不一樣

查了以後發現是Url encode, decode的問題
有些url encode會把` `encode成`+`
例如說你去google搜尋`foo bar`，網址會是`https://www.google.com.tw/webhp?q=foo+bar`

所以問題發生是這樣的
1. client 傳 `A+B` 給 server
2. server 收到之後做 urldecode，把`+`解釋為` `，變成`A B`

在php裡面，urldecode就是會做這樣的事，但是rawurldecode不會
總之，在實作上還是盡量避免`+`這種特殊符號比較好，就不用考慮這麼多問題了

參考資料
1. [php URL decode get '+' from URL](http://stackoverflow.com/questions/5495920/php-url-decode-get-from-url)
2. [When to encode space to plus (+) or %20?](http://stackoverflow.com/questions/2678551/when-to-encode-space-to-plus-or-20)
3. [In a URL, should spaces be encoded using %20 or +?](http://stackoverflow.com/questions/1211229/in-a-url-should-spaces-be-encoded-using-20-or)