---
title: 部落格搬家心得：從 Logdown 到 Hexo
catalog: true
date: 2017-09-03 21:34:38
subtitle: 早知道就早點搬...
header-img: "/img/header_img/article-bg.png"
tags: [story]
---

# 前言

終於搬完啦！

花了一整天的時間在搞搬家的東西，其實真的挺麻煩的，而且中途碰到滿多小問題，所以特地寫這篇來紀錄一下心得。

# 為什麼搬家？

你知我知獨眼龍也知，Logdown 基本上已經是一個停滯的產品了，從很久以前就不再更新了，看樣子應該也不會再更新了。

我真的滿喜歡 Logdown 的，因為我覺得使用起來很方便很順手，完全打到我，到既然是個停止維護的產品，繼續在那邊就會有一些風險，例如說哪天 blog 突然掛掉連不上或者是文章全部不見之類的。

所以囉，就趁著最近有空趕快把部落格整個搬出來，避免之後發生什麼災難就來不及了。

不過其實我也是滿不想搬的...畢竟搬家真的超麻煩，而且這次又換一個全新的 Domain，往長遠來看是好的啦，但也代表要放棄之前累積的那些流量就是了。

# 第一個挑戰：匯出文章

Logdown 後台有一個功能可以匯出所有 blog 的文章然後寄到你信箱，但我按了幾次他只有出現：「在 5 分鐘之後會把文章寄到你信箱」的通知，之後就什麼都沒收到了。

所以我推測要嘛就是壞了，要嘛就是我文章太多檔案大小超過所以 GG。但不論是哪一種，都注定我用不到這個功能了。

身為一個工程師，我馬上想到是不是該寫個爬蟲之類的，研究了一下 Logdown 的結構之後放棄了，因為他所有 API 傳回的資料都是 HTML...我不想自己 parse 啊...

正當絕望之際，突然發現後台有個「下載 Markdown 格式」的功能，可以下載單篇文章，試過這個功能正常之後，立刻想到一個解法：

> 只要有所有下載文章連結，就可以寫 script 全部載下來了

## 第一步：取得網址

到 logdown 後台（http://logdown.com/account/posts ），然後一直往下捲動直到沒有文章為止。

打開 Chrome devtool 執行下面程式碼，然後把結果按右鍵保存起來
``` js
var a = Array.prototype.map.call(document.querySelectorAll('a'), item => item.getAttribute('href')).filter(item => item.indexOf('/raw') >= 0);for(var k of a) {console.log('"'+k+'"')}
```

沒意外的話，console 應該會出現像下面這種結果：

``` js
....
VM192:1 "/account/posts/294284-javascript-redux-middleware-details-tutorial/raw"
VM192:1 "/account/posts/294037-javascript-redux-basic-tutorial/raw"
VM192:1 "/account/posts/293940-javascript-redux-model-real-world-browserhistory-not-found/raw"
```

自己把前面那個惱人的字串取代掉之後，你就得到所有文章的網址了。

## 第二步：下載

可是取得網址之後，這麼多網址要怎麼下載呢？

很簡單，我們自己寫個 bash script 就搞定了！核心程式碼就是用 wget 把文章抓下來，這邊的 session key 自己去 chrome 裡面看 cookie 的值就好：

``` bash
wget --heade="Cookie:_logdown_session=xxxx;" http://logdown.com/account/posts/2223627-review-the-classical-sort-algorithm-with-javascript/raw -O review-the-classical-sort-algorithm-with-javascript.md
```

完整 script：

``` bash
declare -a arr=(
"/account/posts/2223627-review-the-classical-sort-algorithm-with-javascript/raw"
"/account/posts/2223612-dom-event-capture-and-propagation/raw"
"/account/posts/2223601-http-cache/raw"
"/account/posts/2223581-ajax-and-cors/raw"
)

for i in "${arr[@]}"
do
  url="http://logdown.com"${i}
  name=`echo $url | sed "s/.*posts\/[0-9]*[-]//g" | sed "s/\/raw//g"`
  wget --heade="Cookie:_logdown_session=xxx;" $url -O $name".md"
done
```

把 arr 下面那些換成剛剛從 chrome 得來的網址並且把 session 換成自己的就搞定了，就把所有文章都下載了！

當個工程師真好

# 第二個挑戰：修文章格式

從 logdown 下載下來的還需要加一些 meta tag 才能在 hexo 上面正常跑，而且我也想順便修一下 tag，這部分我完全是手動修...修了兩百篇左右，因為要加 tag 這也不能自動加。（硬要寫也是可以啦，但我懶得弄）

還有一個地方是我有文章用到 hexo 禁止的語法，就是兩個大括號那個，hexo 就直接報錯，然後也沒跟我講哪一篇，我只好自己用二分搜尋法，不斷拿掉文章看問題到底出在哪邊。

# 第三個挑戰：table of content 壞掉

現在大概右邊看到那個就是 TOC，Table Of Content，是個我滿喜歡的功能，但不知道為什麼這功能壞掉了，在我自己去 trace hexo 的 code 之後，發現是一個滿奇怪的問題，就是 cheerio 抓不到 span 的 id，所以連結全部變成 undefined。

身為工程師，這種小問題當然是可以自己修，於是我就修了兩個小地方：

``` js
// 原本的
var $ = cheerio.load(str);

// 改過的，加上 decodeEntities 處理中文
// https://cnodejs.org/topic/54bdd639514ea9146862ac37
var $ = cheerio.load(str, {decodeEntities: false});

// 原本的，會抓不到 id
var id = $(this).attr('id');

// 自己加上下面這一段用 Regexp 抓出來
if (!id) {
  var temp = $(this).html().match(/id="(.*)">/);
  if (temp && temp[1]) {
    id = temp[1];
  }
}
```

當一個工程師真好

# 結論

這次用的模板是：[hexo-theme-beantech](https://github.com/YenYuHsuan/hexo-theme-beantech)，是我覺得很不錯的一個版型，不過我也有自己修一些小地方就是了。

經歷過這次搬家之後，覺得 Hexo（部落格系統）+ Github Page（Hosting）+ Cloudflare（https）根本是工程師寫部落的最佳實踐，全部免費的方案然後所有必要的東西一次擁有，真棒真棒。

話說之後還可以改成配合 CI 做自動 deploy，那個就等之後再研究吧！
