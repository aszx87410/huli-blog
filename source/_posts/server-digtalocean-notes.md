---
title: '[Server] DigtalOcean 筆記'
date: 2015-07-10 16:59
catalog: true
header-img: "/img/header_img/article-bg.png"
tags: [backend,server]
---
之前一直在猶豫要買DigtalOcean還是linode或是AWS的免費一年方案
最後決定先買DigtalOcean試試水溫，先用最便宜的5美元方案看看
基本上購買流程跟開主機的流程都很簡單，輸入資料然後滑鼠點一點就開好了
就可以ssh上去到你的主機了

連到主機以後速度有點慢，但是尚可接受啦
我自己是寫nodejs，所以參考[How To Set Up a Node.js Application for Production on Ubuntu 14.04](https://www.digitalocean.com/community/tutorials/how-to-set-up-a-node-js-application-for-production-on-ubuntu-14-04)這篇

node已經在選主機的時候就挑一台裝好的了，所以只要裝pm2跟nginx，做一下設定即可
因為可能會在一台主機上跑很多個網站，例如説blog跟個人網頁或是一些side project
有幾種方法啦，我比較懶所以我隨便選一種有成功我就繼續用了
`/etc/nginx/conf.d`底下開一個`.conf`結尾的檔案，裡面寫著
```
server {
    listen 80;

    server_name huli.tw;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
    }
}
```

這樣子我把`huli.tw`這個domain指到這台主機以後，就會自動導到8080 port
就可以在一台主機下面跑很多web project

接著筆記一下怎麼把domain指到這個ip
我domain是在godaddy買的，進去設定頁裡面然後新增A record，填入主機的ip即可
或是新增nameserver record，填入DO給的那幾組 `ns1.digitalocean.com.`之類的
設定還滿方便的，等個十分鐘左右就生效了

