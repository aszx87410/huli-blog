---
title: 正規表達式沒寫好會怎樣？淺談 ReDoS：利用 regexp 的攻擊
catalog: true
date: 2023-06-12 14:10:44
tags: [Security]
categories: [Security]
photos: /img/redos-regular-expression-denial-of-service/cover.png
---

Regular expression，中文又翻作「正規表達式」或是「正規表示式」等等（以下簡稱 regexp），主要是用來做字串的配對，寫好一個模式之後，就可以拿來配對到符合規則的文字。

無論是電話號碼、Email 或是身分證字號等等，都可以運用 regexp 來完成初步的格式驗證，確保字串的格式與特定規則相符合。

Regexp 雖然方便，但沒寫好的話有可能導致一些輸入的驗證被繞過，演變成資安問題；而除了這個之外，還有另外一種也會造成問題，就是這篇要來講的 ReDoS，全名為：Regular expression Denial-of-Service，因為正規表達式所引起的阻斷服務攻擊。

<!-- more -->

在講 ReDoS 之前，先來提一下什麼是 DoS。

舉例來說，假設假設某個網站框架對於 HTTP 請求的解析沒有做好，只要碰到特殊字元就會壞掉，造成伺服器重啟，而這時攻擊者就可以不斷送出這種會讓網站壞掉的請求，造成伺服器一直重啟，這就是一種 DoS。

如果要分更細的話，還可以分成攻擊的是哪一層，例如說是網路層還是應用層等等，這篇講的都是針對應用層的攻擊。

大家平常在網路新聞看到的攻擊，比較多應該是屬於 DDoS，前面多了一個 D，意思是 distributed，分散式的，而且都是針對網路層的攻擊居多。前面我們舉的 DoS 例子可以看出基本上都是網站本身有問題，例如說沒有考慮到特殊狀況等等，才會讓攻擊者可以利用，而 DDoS 比較像是：「不管你有沒有問題，我找一堆人把你塞爆」

以現實生活來舉例，你開了一間小吃店，賣一些常見的東西像是乾麵啦，燙青菜啦等等，因為每次要看客人的菜單點了什麼很花時間，又覺得用手機點餐很沒有人情味，因此訂製了一個「讀菜單機器人」，來幫你看客人的點菜單。

這時候我故意在點菜單上面鬼畫符，但有些地方看似正常，讓菜單看起來很吃力，機器人的辨識功能沒有做好，沒辦法解讀，於是就停擺了，這就叫做 DoS，以一己之力耗盡資源。

我找一百個人去你那邊，每個人都畫一堆空白菜單丟給機器人，讓機器人應接不暇，沒辦法處理其他客人的菜單，這就叫做 DDoS。

簡單來說呢，DoS 通常是「以少量的資源就能造成服務中斷」，而 DDoS 則是「用比超級多的資源直接把你服務打掛」。

好，讓我們講回 DoS，從前面的例子可以看出來，當你的程式本身就有一些問題的時候，是最容易出事的。符合了這個前提，就很容易以一人之力，用簡單的方式把你的服務弄掛。

而 ReDoS 就是靠著沒寫好的 regular expression 來達成這件事。

## 話不多說，直接舉例

直接看範例最快：

``` js
console.time('test');
/(a|a?)+$/.test('a'.repeat(25) +'b');
console.timeEnd('test');
// test: 2128.498046875 ms
```

一個 26 個字的字串，需要 2 秒鐘才能配對完畢。順帶一提，這個 regexp 所需要的時間是以倍數計算的，再多一個字需要 4 秒，然後 8 秒，16 秒，以此類推。

那為什麼這個 regexp 需要這麼久的時間呢？

這跟 regexp 引擎的實作以及原理有關，細節我也還沒研究清楚就不誤導大眾了，但簡單來說就是 regexp 引擎必須要遍歷所有的可能性以後才能發現字串不符合，所以花了這麼久的時間。

總而言之，如果 regexp 沒寫好，會造成使用的時候消耗大量時間。

## 實際案例

你可能會想說，regexp 有這麼容易寫壞嗎？

還真的有，一大堆的 library 都出現過 ReDoS 的漏洞，還有人整理出一個詳細的列表：[Awesome ReDoS Security](https://github.com/engn33r/awesome-redos-security)

舉例來說，CKEditor 以前有一個偵測是否是圖片網址的 regexp，傳入精心構造的字串後需要 6 秒才會執行完畢：

``` js
// from: https://github.com/ckeditor/ckeditor5/commit/e36175e86b7f5ca597b39df6e47112b91ab4e0a0
const IMAGE_URL_REGEXP = new RegExp( String( /^(http(s)?:\/\/)?[\w-]+(\.[\w-]+)+[\w._~:/?#[\]@!$&'()*+,;=%-]+/.source +
    /\.(jpg|jpeg|png|gif|ico|webp|JPG|JPEG|PNG|GIF|ICO|WEBP)\??[\w._~:/#[\]@!$&'()*+,;=%-]*$/.source ) );

console.time('test');
IMAGE_URL_REGEXP.test('a.' + 'a'.repeat(100000))
console.timeLog('test')
// test: 6231.137939453125 ms
```

雖然說字串長度有 10 萬，但如果改成沒問題的版本，不到 1 毫秒就能跑出結果：

``` js
// from: https://github.com/ckeditor/ckeditor5/commit/e36175e86b7f5ca597b39df6e47112b91ab4e0a0
const IMAGE_URL_REGEXP = new RegExp( String( /^(http(s)?:\/\/)?[\w-]+\.[\w._~:/?#[\]@!$&'()*+,;=%-]+/.source +
    /\.(jpg|jpeg|png|gif|ico|webp|JPG|JPEG|PNG|GIF|ICO|WEBP)(\?[\w._~:/#[\]@!$&'()*+,;=%-]*)?$/.source ) );

console.time('test');
IMAGE_URL_REGEXP.test('a.' + 'a'.repeat(100000))
console.timeLog('test')
// test: 0.570068359375 ms
```

以 JavaScript 來說，這些配對的程式碼都是跑在 main thread，如果是網頁的話會直接畫面凍結，直接卡死，如果是以 Node.js 來執行的伺服器也會卡住，無法處理其他請求。

## 該怎麼知道有沒有 ReDoS 的風險？

有一些現成的工具可以幫忙，我自己最常用的是這個：https://devina.io/redos-checker

只要把 regexp 丟進去，就可以跟你說有沒有問題，有的話還會附上測試的字串，讓你可以自己再測試一遍。

![devina redos checker](/img/redos-regular-expression-denial-of-service/p1.png)

不過有時候會有 false positive 就是了，它覺得有但是沒有，或也有可能真的有，但是它給的攻擊字串跑不出來。因此還是建議測完以後自己拿它給的 payload 再試一次，確認一下。

## ReDoS 在攻擊上的應用

前面講的都是「regexp 已經寫好，而使用者可以控制輸入」，這時候只要找到有問題的 regexp 產生攻擊字串即可。

而有另外一種狀況是：「使用者可以控制 regexp」。舉例來說，假設有個網站提供搜尋使用者的功能，你可以傳入一個 regexp，伺服器就會回傳是否有符合此 regexp 的 username 存在。

伺服器的實作大概如下（隨意寫的，意思有到就好）：

``` js
app.get('/search', (req, res) => {
    const q = req.query.q
    return users
        .filter(user => new RegExp(q).test(user.username))
})
```

這個危險的功能除了可以讓攻擊者把所有的 username 都拿到手以外，也會有 ReDoS 的風險在。

舉例來說，當 `/((([^m]|[^m]?)+)+)+$/` 這個 regexp 碰到 `"username"` 時，需要花費將近 4 秒才能跑完：

``` js
console.time('test');
/((([^m]|[^m]?)+)+)+$/.test('username')
console.timeEnd('test');
// test: 3728.89990234375 ms
```

只要繼續按照相同的模式把 regexp 延伸下去，就可以讓這整段程式碼執行超過 30 秒或是更久，癱瘓整個 server。

在打 CTF 時還有另一種常見的狀況是一樣可以傳入 regexp，但是伺服器不會跟你講有沒有成功，你只能根據時間差來判斷，這時候靠 ReDoS 就很有用了：

``` js
console.time('CTF{a');
console.log(/CTF{[a](((((.*)*)*)*)*)!/.test('CTF{this_is_flag}'))
console.timeEnd('CTF{a');
// CTF{a: 0.071ms

console.time('CTF{t');
console.log(/CTF{[t](((((.*)*)*)*)*)!/.test('CTF{this_is_flag}'))
console.timeEnd('CTF{t');
// CTF{t: 24.577s
```

透過傳入精心構造的 regexp，就可以利用時間差得知第一個字元是什麼。

最後簡單提一下防禦方式，最根本的解決方法就是不要寫出有缺陷的 regexp，先去學習哪一些 pattern 應該盡量少用，就能掌握到大概的方向。除此之外，似乎也有人做了一些自動化的工具幫忙掃 code 裡面出現的 regexp，這也是一種在出事前先預防的方法。

## 為了防止 ReDoS 而出現的另一種問題

底下這段 PHP 的程式碼會檢查輸入是否為 PHP 的格式，如果不是的話才進行後續操作，你有辦法繞過正規表達式嗎？

``` php
<?php
function is_php($data){  
    return preg_match('/<\?.*[(`;?>].*/is', $data);  
}

if(!is_php($input)) {
    // fwrite($f, $input); ...
}
```

答案是有辦法，但繞過的並不是正規表達式本身，而是利用了 PHP 的一個機制。

PHP 為了防止 ReDoS 的發生，設有回朔次數的上限，如果超過了上限，就會回傳 `false`，而非原本預期的 0 或是 1。雖然 PHP 的[文件](https://www.php.net/manual/en/function.preg-match.php#refsect1-function.preg-match-returnvalues)裡面有就有提到這點，但老實說會乖乖去看文件的還是少數，因此我相信有不少開發者都不知道這個行為。

因此，只需要構造出一個與 ReDoS 類似的結構觸發上限，就會讓 `preg_match` 回傳 `false`，進而繞過檢查。

上面的範例來自於 phith0n 在 2018 年發表的文章：[PHP利用PCRE回溯次数限制绕过某些安全限制](https://www.leavesongs.com/PENETRATION/use-pcre-backtrack-limit-to-bypass-restrict.html)，而 2019 年的 Facebook CTF 中也有一題是相同的原理，可以參考 balsn 的 [writeup](https://balsn.tw/ctf_writeup/20190603-facebookctf/#rceservice)。

甚至於這個漏洞在 2023 年也出現在現實世界中：[MyBB Admin Panel RCE CVE-2023-41362](https://blog.sorcery.ie/posts/mybb_acp_rce/)。

## 總結

我自己覺得 ReDoS 是一個滿有趣的攻擊方式，以前沒想過靠著 regexp 還可以做出這種效果。

以前第一次知道這個攻擊，似乎是還在當開發者的時候，偶爾會看到使用到的 library 有這個漏洞，不過當初沒有很在意就是了。後來在資安裡面再度碰到這東西，才覺得好像挺有趣的。

這篇比較像是我的個人筆記，只是想趁著記憶猶新的時候把一些 payload 記下來，以後比較好找。

最後附上一些參考資料以及延伸閱讀，有興趣深入了解的讀者們可以看一下：

1. [HackTricks - Regular expression Denial of Service - ReDoS](https://book.hacktricks.xyz/pentesting-web/regular-expression-denial-of-service-redos)
2. [OWASP: Regular expression Denial of Service - ReDoS](https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS)
3. [snyk: ReDoS](https://learn.snyk.io/lessons/redos/javascript/)

