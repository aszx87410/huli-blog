---
title: 'Mailgun簡介'
date: 2014-07-21 16:31
catalog: true
header-img: "/img/header_img/article-bg.png"
tags: [backend,mailgun]
---
上一篇心得筆記有稍微提到一點但點到為止
這篇來比較詳細一下的介紹mailgun好了

#mailgun是做什麼的？
[mailgun](http://www.mailgun.com/)首頁看過一遍之後應該就能完全理解了
mailgun就是來幫你解決"發信"這個很多公司都會有的需求
以往發信通常會有兩種管道，一個是利用現成的信件服務，例如說gmail
另外一個就是自己架郵件伺服器
但是前者比較容易被擋信或是被丟到垃圾信箱之類的，後者則是比較花費力氣
於是mailgun就跳出來幫大家解決這個問題

#How?

##善於給開發者使用的介面
身為網頁後端工程師，對API的串接應該不陌生才對
可能串過facebook、google、paypal...等等的api
而mailgun就提供了基於RESTful架構的api，容易理解以及使用
如果剛好是rails的工程師，因為rails本身就是這種架構，所以我覺得使用mailgun最容易上手
若是對api串接沒那麼熟，mailgun也貼心提供多種語言（ruby、python、php、java、C#）的library
安裝以後只要看著官方的document就可以輕鬆上手
而且mailgun的document我真的覺得寫的不錯

##追蹤信件
一旦開始使用mailgun發信
後台就可以看到信件的log，mailgun預設了幾個event
像是

1. accepted(mailgun接受了你的信)
2. delivered(mailgun成功發送到收件者信箱)
3. opend(收件者打開了信件)
4. clicked(收件者點開了信件裡的連結)
5. dropped(信件因為某種原因所以寄不到)

所以你可以知道哪封信有沒有寄達，或是使用者有沒有打開
除此之外還可以啟用更多的追蹤資訊，例如說收件者用的os、browser、收件軟體之類的

##更多服務
例如說你有一個自己的domain，比如說huli.tw好了
單純用mailgun寄信，信件中會寫說 `寄件者：service@huli.tw 經由 mailgun.com`
那如果我不想讓使用者看到`經由mailgun.com`，就要自己去設定domain
mailgun也提供了完整的教學，基本上就是dns設定調一下之後就ok了

而寄件的時候除了信件內容，還可以夾帶自己訂的參數，方便後續追蹤
例如說mailgun可以提供`tag`的功能，每封信都可以tag最多三個標籤
像是我可以分成`會員註冊`、`密碼查詢`...之類的
或是你可以自己傳個`category`的參數進去

以上就是對mailgun大致上的介紹，以下提供更多的實作細節

要完成這樣的一個跟mailgun串接的system需要兩個部分
1. 發信
2. 接收事件

發信的部份很簡單，把標題內容寄件者收件者準備好以後，丟一個request給mailgun就好了
``` php
function send_simple_message() {
  $ch = curl_init();
  curl_setopt($ch, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
  curl_setopt($ch, CURLOPT_USERPWD, 'api:key-example');
  curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
  curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'POST');
  curl_setopt($ch, CURLOPT_URL, 
              'https://api.mailgun.net/v2/samples.mailgun.org/messages');
  curl_setopt($ch, CURLOPT_POSTFIELDS, 
                array('from' => 'huli_blog <service@huli.tw>',
                      'to' => 'huli <aszx87410@gmail.com>',
                      'subject' => '你好',
                      'v:mail-number' => '123',
                      'html' => '<h1>安安你好，這是內文，可以用html喔<h1>'));
  $result = curl_exec($ch);
  curl_close($ch);
  return $result;
}
echo send_simple_message();
```
這是網路上找到的php範例code，出處在上篇文章有附
基本上要改的地方就只有`api:key-example`，把`key-example`換成自己的api-key即可
第二個是`https://api.mailgun.net/v2/samples.mailgun.org/messages`裡的`samples.mailgun.org`
要換成自己的domain，如果沒有的話mailgun有預設的，通常長得像`sandbox(一串英文數字).mail.org`
只要執行這段code以後，就可以發信了

其中`v:mail-number`就是之前說的可以傳入自訂參數，例如說我的網站如果有幫每封郵件都編號，就可以在這邊傳入
之後接受event的時候就可以把這個資訊取出來

接收事件的地方，就是可以在mailgun後台裡面給他一個網址
mailgun就會在相對應的事件發生時（例如說opened），送request到這個網址來
而mailgun會傳過來的參數，在[官方documents](http://documentation.mailgun.com/api-webhooks.html)上面都有
如果是php的話，用`$_POST`就可以接到參數了
然後再進行解析，做更進一步的動作（例如說更新資料庫之類的）

##總結
像是有些網站可能要發會員註冊信、驗證信之類的
就可以考慮使用mailgun來當做發信系統
或是要自己架也可以，不過懶得架的很適合串mailgun
一個月1萬封信以下都是free的，付費方案可以參考[這裡](http://www.mailgun.com/pricing)
mailgun客服的回應速度也滿快的，我覺得不錯
除了mailgun，也有其他公司在做跟郵件有關的事
要特別注意的是，要針對自己的需求選擇相對應的服務
假如你的需求是發電子報，我就覺得[電子豹](https://www.newsleopard.com/)可能比較適合
