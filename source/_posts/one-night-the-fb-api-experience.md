---
title: '一個晚上的FB API心得'
date: 2014-09-10 09:49
catalog: true
header-img: "/img/header_img/article-bg.png"
tags: [backend]
---
前幾天同學丟給我一個[連結]( http://apps-redri.eu/app/index.php?ref=100000241324896)
可以測前十名跟你傳最多訊息的（只是這網站時好時壞，而且會幫你po文所以我不太喜歡）
我自己的結果是滿準的啦，但是有些同學就說不準
一直很想接觸FB的api但是一直懶得入門
這次剛好趁著這個機會查了一下資料

我利用 `facebook api message count` 這組關鍵字找到了一個stackoverflow的連結[Get count CHAT message](http://stackoverflow.com/questions/9894889/get-count-chat-message)
底下的回答直接給出FQL的query：

>SELECT viewer_id,recipients,message_count FROM thread WHERE folder_id = 0 ORDER BY message_count DESC

實際拿這個query去Facebook的[測試頁面](https://developers.facebook.com/tools/explorer)，就可以直接看到結果
而把這個結果拿去跟那個網站的結果比對一下就可以大概知道差在哪邊了
首先就是Facebook頁面出現的，網站的結果並沒有出現，所以這個網站的測試結果顯然是有缺失的
第二就是這個query所能抓的資料只有50筆左右，但我的收件箱有300多筆紀錄，所以這個query並不完整
而我東找西找找不到怎麼用這個query抓所有資料回來，於是這邊就無法繼續往前進

那要怎麼辦呢？於是我決定先去翻Facebook的docs
左翻又翻找到一個[inbox的api](https://developers.facebook.com/docs/graph-api/reference/v2.1/user/inbox)
可以檢視一個user的收件箱，而在Facebook裡面每一個對話串都是一個thread，在inbox傳回的資料裡面就有這個thread id
所以接下來要做的事情很明顯了，就是先把所有的thread id抓下來
抓下來以後就是針對每筆thread去統計數量，還記得剛剛上面的query嗎？改一下就可以用了

>SELECT recipients,message_count FROM thread WHERE folder_id = 0 and thread_id=1111111...

就可以查到這筆對話紀錄的訊息總數是多少了
接著最後一個步驟就是看看所謂的收件人(recipients)到底是誰
而這也很簡單，就直接把那串id拿來查詢就好，像是這樣
[http://graph.facebook.com/1157251270](http://graph.facebook.com/1157251270)
（我也不知道他是誰，這只是在網路上找到的範例）

流程全部都決定好了，而且在Facebook的測試頁面上面也的確可以用這些方法得到資料，接下來就是實際動手做了
而沒想到，這才是痛苦的開始.....

我一開始先採用Facebook開放給php的SDK，因為我主機跟我電腦的php版本都是5.2或5.3，所以sdk只能用3.2版的(最新是4版)
接著開始實作第一個流程：抓取所有thread-id
這個部分進行得滿順利的，沒有花很多時間就搞定了
第二個步驟是用FQL抓收件人還有訊息總數
但是FQL已經是被Facebook拋棄的東西，新版的都不再支援
於是我用php怎麼試也沒辦法試出來，就一直出錯一直出錯，翻遍了官方的說明跟google一堆stackoverflow的解答都沒用
我有查到Graph API 2.0還可以使用FQL，但是php SDK　3.2版無法指定版本（或是可能可以但我不知道）
到了這裡，只好捨棄php，改用javascript的SDK開發

換成js以後先把剛剛的php抓thread id的code轉過來，測試一下能否順利抓到
確認可以抓到以後接著就是把version指定成2.0，讓我可以用FQL
結果....就算版本設成2.0還是一直出錯
經過一連串的google以後發現如果是現在新申請的應用程式，就不能使用舊版的（2.1以前）的Graph API
這...難道我跟Facebook的初次接觸就這樣徹底失敗嗎......

幸好露出了一線曙光
在一年兩年我因為無聊沒事，剛好想學一下寫Facebook的應用程式，所以有隨便註冊了一個（之後就再也沒碰過）
所以我就把App ID換成那個，就可以用FQLf取得訊息了
沒事到處亂戳亂註冊還是有好處的，感謝一兩年前的我

接下來繼續寫code
就每一個thread id都送出一個query查詢
結果發送到大約第200個query的時候出錯了!!!
跟我說已經達到query的上限，所以沒有辦法再送query出去
這邊我也是一直查資料一直google看有沒有解決方法
最後找到一個說明是一個query可以包含很多個query
例如說 `{'q1':'select ...','q2':'select...'}`
我想說這樣子應該可以解決reach limit的問題，發一個request出去裡面包含50個query
沒想到最後還是fail，碰到一樣的錯誤訊息，看來這招是沒有用的，因為query數還是一樣，只是request減少而已
最後是憑著以前寫SQL query的經驗靈機一動想到`IN`這個東西
就把query改成
>SELECT recipients,message_count FROM thread WHERE folder_id = 0 and thread_id IN(1,2,3,4,5,6,...)

嘗試一次把所有的thread id塞進去發現回傳的資料也只有十筆
於是我就改成每十筆一個query
query的數量就立刻減少十倍，達成Facebook所限制的標準以下

最後再用ajax去抓上面講過的那個網址 `http://graph.facebook.com/1157251270`的資料
把這個id的name抓回來，就可以知道id跟姓名的對應關係了
接著記得把自己的id排除，就可以生成最後的結果

心得：
1. 因為ajax跟Facebook API都是非同步的，記得等資料傳回來再做事情
2. 為什麼Facebook要把FQL這麼方便的東西停用
3. Google萬歲! stackoverflow萬歲!


最後附上不一定能跑的測試網頁(會有彈出視窗要你登入，被瀏覽器擋掉的話記得解除)
只有電腦可以用，手機進這個網頁不會有任何東西在跑
不知道太多人用的話server會不會掛掉或是被Facebook擋掉（又說我發太多query之類的）
滿草率的一個網頁，連title跟SEO還有og-tag都沒設XD

http://huli.tw/fb/message_rank.php
上面那個灰框框是debug訊息，看到他有在動就代表程式在跑
沒在動代表壞掉了（或是正在抓名字）XDD

source code : https://github.com/aszx87410/fb_get_message_count


