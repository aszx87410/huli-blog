---
title: 'Mailgun心得筆記'
date: 2014-07-20 21:48
catalog: true
header-img: "/img/header_img/article-bg.png"
tags: [mailgun]
---
http://www.mailgun.com/

有時候可能會需要用到寄信的功能，但是用php內建的mail或是用gmail的smtp有時候會寄丟
所以聽說到mailgun這個還不錯的網站，研究了兩三天之後終於接上了

mailgun官方的documents寫的已經滿詳細的了，而且很多語言都有提供現成的library可以套
如果不想套library的話，用curl也是可以
用法可以參考[這篇](http://blog.mailgun.com/post/the-php-sdk-the-first-of-many-official-mailgun-sdks/)

``` ruby
function send_simple_message() {
  $ch = curl_init();
  curl_setopt($ch, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
  curl_setopt($ch, CURLOPT_USERPWD, 'api:key-example');
  curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
  curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'POST');
  curl_setopt($ch, CURLOPT_URL, 
              'https://api.mailgun.net/v2/samples.mailgun.org/messages');
  curl_setopt($ch, CURLOPT_POSTFIELDS, 
                array('from' => 'Dwight Schrute <dwight@example.com>',
                      'to' => 'Michael Scott <michael@example.com>',
                      'subject' => 'The Printer Caught Fire',
                      'text' => 'We have a problem.'));
  $result = curl_exec($ch);
  curl_close($ch);
  return $result;
}
echo send_simple_message();
```

原本在自己電腦上可以跑，但是放到server上以後發現跑不出來
debug以後發現有兩個問題
第一個跟https有關
要加上
``` ruby
curl_setopt($ch,CURLOPT_SSL_VERIFYHOST,0);
curl_setopt($ch,CURLOPT_SSL_VERIFYPEER,0);
```
之後就可以正常運行
可參考[這篇](http://taichunmin.pixnet.net/blog/post/35782941-%5Bphp%5Dcurl%E4%BD%BF%E7%94%A8https%E9%81%87%E5%88%B0ssl-certificate-problem)

[這篇有詳細說明](http://www.plurk.com/p/e797gs)
>由於 CURLOPT_SSL_VERIFYPEER 的預設值為 TRUE 是要驗證伺服器憑證的，所以當拜訪 https 網站時，若未做任何 SSL 相關設定，會出現以下錯誤。
Error Number: 60
Error Message: SSL certificate problem, verify that the CA cert is OK. Details:
error:14090086:SSL routines:SSL3_GET_SERVER_CERTIFICATE:certificate verify failed
如果只是要拜訪 https 網站，但不會來回傳遞敏感信息，可以把 CURLOPT_SSL_VERIFYPEER 設定為 FALSE，代表可以盲目接受任何伺服器憑證。
而當 CURLOPT_SSL_VERIFYPEER 為 FALSE 時，其他諸如 CURLOPT_SSL_VERIFYHOST, CURLOPT_CAINFO, CURLOPT_CAPATH 等設定，都不具任何意義。
但如果需要來回傳遞敏感信息時，就要正確啟用此同行核查機制，而 CURL 預設的相關 SSL 設定，也都是採用比較嚴格的作法。
預設 CURLOPT_SSL_VERIFYPEER 為 TRUE 代表要比對驗證伺服器憑證，與 CURL 程式本身所使用的 crt 憑證是否相符合。
預設 CURLOPT_SSL_VERIFYHOST 為 2 代表除了要檢查 SSL 憑證內的 common name 是否存在外，也驗證是否符合伺服器的主機名稱。
而當 CURLOPT_SSL_VERIFYPEER 為 TRUE 時，須搭配 CURLOPT_CAINFO 或 CURLOPT_CAPATH 設定。
但這兩個設定預設值為空，可擇一使用，一般會使用 CURLOPT_CAINFO 直接指定 crt 檔的絕對路徑，例如 Facebook PHP SDK 內附的 fb_ca_chain_bundle.crt 就是為了這個目的。
而這個 ca bundle crt 憑證檔，則可以利用瀏覽器來拜訪該 https 網站時，來匯出該站台的 crt 憑證。詳細可參考底下這篇文章的介紹。

[Using cURL in PHP to access HTTPS SSL/TLS protected sites ](http://unitstep.net/blog/2009/05/05/using-curl-in-php-to-access-https-ssltls-protected-sites/)

第二個問題是
mailgun允許你傳自訂參數進去，用json格式即可
我在php裡面用 `json_encode(...)`
然後拿回資料的時候用 `json_decode(...)`
發現在decode的時候出現錯誤，原因是因為傳回來的資料`"`會變成`\"`
造成php裡面的json_decode沒辦法解析
解決方法是傳過去的時候先`urlencode`，接收的時候先`urldecode`

``` ruby
//設定寄件內容
curl_setopt($ch, CURLOPT_POSTFIELDS, 
	array(
		'from' => $from,
		'to' => $to,
		'subject' => $subject,
		//urlencode無敵重要
		"v:custom_variables" => urlencode(json_encode($custom_variables)),
		'html' => $body
	));
```

記錄完問題以後來介紹一下mailgun好了
申請帳號以後一個月寄1萬封信以內都是免費的
後台會有log可以看（只保留兩天）
驗證自己的domain(設定dns)以後可以用這個domain來寄信
寄信的方法有兩種，一種走http，mailgun提供RESTful的api可以用
另外一種就走smtp
官方推薦用http

除了基本的寄信以外，還提供event的callback
例如說當某封信寄達或是開啟以後，mailgun就會post資料到你提供的url
有很多event可以偵測，例如說`OPENED`、`DELIVERED`、`CLICKED`
mailgun的文件裡有寫到，偵測user有沒有打開信的方法就是在裡面插一張透明png圖片
所以user如果有先擋圖片的話就沒辦法偵測到

結論：
mailgun寄信方便、偵測事件也方便（可以選擇自己去get或是mailgun來post資料，懶人選後者就好了超方便）
用一陣子之後再看看是不是真的很難掉信
