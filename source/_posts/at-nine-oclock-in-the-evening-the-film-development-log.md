---
title: '「今晚九點電影」開發日誌'
date: 2014-04-19 13:27
catalog: true
header-img: "/img/header_img/article-bg.png"
tags: [story]
---
一樣是以前的文章，轉過來保存一下

「今晚九點電影」，一個想法來自於ptt Movie版的Android App
每到假日，ptt電影版總會有人po文，而文章的標題就叫做「今晚九點電影」
內容就是禮拜六日晚上九點（以及前後兩檔），在電視上會播映的電影
像是HBO、Star Movies或是本土的衛視電影台之類的
當初在開發這個程式的時候有順便寫了一下開發日誌，現在把它整理過後貼來這裡，一共有9天。
<!-- more -->



# [電影] 開發日誌 Day 1
新的project XDD
目標是七天以內完成!!!
有在逛ptt movie版的人應該都知道說
假日的時候都會有一篇文叫做 今晚九點電影
內容就是各個電影台今晚九點的電影在播什麼
我想寫的app基本上就是這樣
然後今天一時心血來潮研究了一下GAE
發現比想像中簡單許多
於是app只負責接收資料
運算就交給GAE
這應該也算是雲端吧XDD
今天進度感覺滿快的
電影的清單快要好了
感覺app就一個list就夠了

# [電影] 開發日誌 Day 2

目前弄出來的
[http://pttmovienine.appspot.com/pttmovienine](http://pttmovienine.appspot.com/pttmovienine)
GAE超棒欸
讓我一緣我的網頁夢
本來有自動抓IMDB的功能
但是不知道為什麼IMDB超慢
會跑到timeout
這部份以後可以再做改進
現在只要每點一次Link就會抓一次資料
我想設定成只要有抓過就可以從資料庫裡撈
沒抓過就存
這樣可以讓運算量變很少 也比較快
如果可以的話 imdb也可以這樣
抓好的先存起來 沒抓好的等下次再抓
不過imdb之後再說啦 先把資料庫搞定吧
還要再研究一下XD
補充一下
今天有碰到一個問題是有個頁面需要有referer才給你連
在get那邊的code加上
`conn.setRequestProperty(“Referer", url);`
就可以了XD

# [電影] 開發日誌 Day 3
今天把國片的部份也加進去了
一共有10個頻道
抓取的結果也十分正常
然後研究一下datastore的部份
還沒寫出來 不過明天應該就可以弄出來了
打算弄成

1.去抓存在資料庫裡的date這個key的值
1-1.如果是null 就抓資料 然後把資料寫進movie_data 把date更新成今天日期
1-2.如果是今天日期 就讀movie_data 然後print出來
1-3.如果不是今天日期 就跟1-1做一樣的動作

這樣應該可以加快頁面存取的速度
雖然說本來也沒多慢啦
不過可以把server的運算量變少(雖然本來就提供很多XD
有一個地方要注意 那就是我不知道upload到GAE上面之後
上面的時間是不是顯示台灣的時區 所以這明天還要再作測試
這邊弄完以後 就可以開始co android的部份了
要有一個list 然後還要去查一下要怎麼設定文字的顏色

# [電影] 開發日誌 Day 4
把資料庫存取的方法搞定了
note一下存取方法

``` java
DatastoreService ds = DatastoreServiceFactory.getDatastoreService();
 Query q = new Query("movie");
 q.addSort("date");
 PreparedQuery pq = ds.prepare(q);
 Entity movie = null;
 for(Entity mov:pq.asIterable()){
   movie = mov;
 }
```

利用一個叫做Entity的東西來存取
ds就是類似資料管理員之類的東西
首先先建立一個Query 查詢資料庫裡名為"movie"的這個實體
然後要查詢的property是"date"
弄完之後你的movie就會是查詢到的那個entity
如果資料庫裡沒有的話 就會是null
接著再根據拿到的時間跟現在的時間做判斷
邏輯很簡單 就不再贅述了

要儲存資料就是 `movie.setProperty(“date", strdate);`
要拿取就把上面的set改成get 第二個參數拿掉

還有一個要注意的點是 用string來存的話他只給你存< 500字元
要用Text這個類別
所以load的地方是這樣寫的

``` java
textstr = (Text) movie.getProperty(“str");
resp.getWriter().println(textstr.getValue());
```

用getValue來拿 用toString的話只會return 前70個char
存東西就是這樣

``` java
textstr = new Text(outstr);
movie.setProperty(“str", textstr);
ds.put(movie);
```

outstr是String 之前拿來存輸出的結果的
現在直接把它當參數傳入 就可以轉成Text
噢對還有一個地方要note
就是抓取時間的地方

``` java
SimpleDateFormat sdFormat = new SimpleDateFormat(“MM/dd");
Date date = new Date();
TimeZone tt = TimeZone.getTimeZone(“Asia/Shanghai");
sdFormat.setTimeZone(tt);
String strdate = sdFormat.format(date);
```

重點是可以設定時區
要記得調成亞洲的時區(GMT+8)
今天有點晚了 明天開始來co android的部份

# [電影] 開發日誌 Day 5
今天大致上研究了一下如何自訂list
但是還沒實做出來
首先就是要先準備一個xml檔 是你list的item的layout
例如說

[textview] [button]

這樣每一行就會有個文字跟按鈕
然後要自己寫個class繼承BaseAdapter
今天找的幾個網頁當中
比較方便的是先幫自己要放的資料寫一個class
例如說我的要放電影資料 時間
就可以

``` java
public class movie{
String name;
String date;
}
```

然後再用一個List<movie>去存每行的資料
總之上一篇NOTE裡面的連結仔細看一看之後滿好懂得
而且很有彈性
不過我剛剛突然想到會不會用ExpandableListView會比較好…
明天再來研究看看

# [電影] 開發日誌 Day 6

作者外出取材
本日休刊一次
事情是這樣子的
昨天我同學丟給我一個web game的連結
跟我說不是很好玩 但是就是會一直玩
我今天下午沒事手賤開始玩
一天就這樣耗掉了…
我錯了Q__Q

# [電影] 開發日誌 Day 7

自訂List的部份搞定了
screenshot明天再附
目前就剩下幾個部份而已了

1.從網路頁面抓資料回來
2.把資料弄進list
3.判斷本日是否已經抓過?(T:從手機資料庫拿回來 F:去抓 然後存進DB)
4.關於..的按鈕
希望在這禮拜六之前能搞定

#[電影] 開發日誌 Day 8

第一版應該算是完成了
話說昨天有件事情我忘記寫
昨天我大概花了快一個小時畫icon…
程式名稱叫做今晚九點電影
不知道是不是原本就有這個涵義所以才要把強檔放在九點
tonight -> night- > nine
所以我project的name就取叫movietonine XD
一開始icon就純文字 然後用數字9

後來想到應該要加一些電影的元素 於是google了些圖片

變這樣
![](http://hulinote.files.wordpress.com/2013/02/movie.png?w=300&h=300)
後來覺得還是怪怪的
經過一陣子的努力 + 突然發現有個字型的9很酷
完成版就這樣
![](http://hulinote.files.wordpress.com/2013/02/movie4.png?w=300&h=300)
先來一張模擬器上的截圖
![](http://hulinote.files.wordpress.com/2013/02/2012-11-28_224815.png?w=300&h=278)
實機上
![](http://hulinote.files.wordpress.com/2013/02/shot_000007.png?w=202&h=359)
今天就是把昨天文章中提到的部份一口氣做完
有SharedPreferences這個class可以輕鬆達成資料的IO
不過好像只能存特定類型的東西(int float string…
自訂的好像就不能存
明天再想想看有沒有什麼功能忘記做的

# [電影] 開發日誌 Day 9 最終章

今天沒進度囉
因為我暫時想不到什麼要加的
剛剛寄信給ptt_movie版的作者問他是否有意願在文章底下幫我宣傳一下
還沒回信
不過以後應該是會更新啦

到時候就變成更新筆記了XD
自動抓IMDB功能一開始是有的
後來不知道為什麼速度超級慢 慢到會error
所以暫時關掉
除了IMDB以外 List點進去會有電影介紹這個我也滿想做的
但是資料量會增加很多…
有人反映再說吧XD

電影開發日誌就到這邊結束啦
下面講一下我的開發心得好了
從日誌中可以看出前4天是在co GAE的部份，後四天是Android
其實一開始的想法是直接從Android抓取電影訊息，但是經過考慮之後覺得GAE實在是方便許多
1. 當我抓取電影的部份寫爛的時候，假如是寫死在Android裡，我就必須發布更新，但是如果是用GAE，我只要改GAE的code就行了，馬上把bug修掉，使用者也無須更新Android程式，這點真的十分重要，因為我真的寫爛了XDD，幸好是透過GAE去抓資料，所以我程式現在還沒更新過XD 
2. 速度跟效率。GAE假如已經把資料儲存好，那顯然是快很多

所以啦，後端的部份用GAE去撈資料再吐給Android我真的覺得超棒的！
而且GAE現在也可以用java寫，可以直接把Android上面抓取資訊的code移到GAE上面去，做一點小幅修改就可以跑。不過日後有機會我還是會想用python寫啦，練功XD