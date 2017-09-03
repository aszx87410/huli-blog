---
title: 'Google map API - 從經緯度判斷在哪個城市'
date: 2014-06-14 16:21
catalog: true
header-img: "/img/header_img/article-bg.png"
tags: [javascript]
---
最近想要做個跟天氣有關的app當做練習
第一個迎面而來的問題就是：我要怎麼知道使用者現在在哪裡呢？
我知道可以用GPS獲得經緯度，那我要怎麼從經緯度得到使用者位於哪個縣市呢？

沒錯，解答就跟標題一樣，就是google map
很多跟地理有關的應用都要借助google map的幫助才能夠達成
在網路上花了點時間找資料以後總算找到了[解法](http://fecbob.pixnet.net/blog/post/38313949-android-gps%E5%AE%9A%E4%BD%8D%EF%BC%8C%E5%8F%96%E5%BE%97%E5%9F%8E%E5%B8%82%E5%90%8D%E7%A8%B1)

接著我自己去google map的官方docs翻資料
使用到的是[Google Geocoding API](https://developers.google.com/maps/documentation/geocoding/)
使用方式超級簡單，就是把經緯度給它就好
例如說 **http://maps.google.com/maps/api/geocode/json?latlng=23.920823,120.652914&language=zh-TW&sensor=true**

就會回傳一大串的資訊，而裡面只有一個是我們要的
```
{
  "long_name" : "南投縣",
  "short_name" : "南投縣",
  "types" : [ "administrative_area_level_2", "political" ]
},
```
types是`administrative_area_level_2`的就是我們想要的所在縣市的資料了
