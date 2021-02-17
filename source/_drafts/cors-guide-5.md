---
title: CORS 完全手冊（五）：跨來源的安全性問題
catalog: true
date: 2020-08-24 23:07:47
tags: [Ajax,JavaScript,Front-end,CORS]
categories:
  - Front-end
---

## 前言

在前面幾篇裡面，我們知道 CORS protocol 基本上就是為了安全性所產生的協定，而除了 CORS 以外，其實還有一系列跟跨來源有關的東西，例如說：

1. CORB（Cross-Origin Read Blocking）
2. CORP（Cross-Origin Resource Policy）
3. COEP（Cross-Origin-Embedder-Policy）
4. COOP（Cross-Origin-Opener-Policy）

是不是光是看到這一系列很類似的名詞就已經頭昏眼花了？對，我也是。在整理這些資料的過程中，發現跨來源相關的安全性問題比我想像中水還來的深，不過花點時間整理之後發現還是有脈絡可循，因此這篇會以我覺得應該比較好理解的脈絡，去理解為什麼會有這些東西出現。

除了上面這些 COXX 的各種東西，還有其他我想提的跨來源相關安全性問題，也會在這篇一併提到。

在繼續下去之後先提醒一下大家，這篇在講的是「跨來源的安全性問題」，而不單單只是「CORS 的安全性問題」。CORS protocol 所保護的東西跟內容在之前都介紹過了，這篇要談的其實已經有點偏離大標題「CORS」完全手冊，因為這跟 CORS 協定關係不大，而是把層次再往上拉高，談談「跨來源」這件事情。

所以在看底下的東西的時候，不要把它跟 CORS 搞混了。除了待會要講的第一個東西，其他的跟 CORS 關係都不大。

<!-- more -->

## CORS misconfiguration

如果你還記得的話，前面我有提到過如果你的跨來源請求想要帶 cookie，那 `Access-Control-Allow-Origin` 就不能是 `*`，而是必須指定單一的 origin，否則瀏覽器就不會給過。

但現實的狀況是，我們不可能只有一個 origin。我們可能有許多的 origin，例如說 `buy.example.com`、`social.example.com`、`note.example.com`，都需要去存取 `api.example.com`，這時候我們就沒辦法寫死 response header 裡的 origin，而是必須動態調整。

先講一種最糟糕的寫法，就是這樣：

``` js
app.use((req, res, next) => {
  res.headers['Access-Control-Allow-Credentials'] = 'true'
  res.headers['Access-Control-Allow-Origin'] = req.headers['Origin']
})
```

為了方便起見，所以直接反射 request header 裡面的 origin。這樣做的話，其實就代表任何一個 origin 的能夠通過 CORS 檢查。

這樣做會有什麼問題呢？

問題可大了。

假設我今天做一個釣魚網站，網址是 `http://fake-example.com`，並且試圖讓使用者去點擊這個網站，而釣魚網站裡面寫了一段 script：

``` js
// 用 api 去拿使用者資料，並且帶上 cookie
fetch('http://api.example.com/me', {
  credentials: 'include'
})
  .then(res => res.text())
  .then(res => {
    // 成功拿到使用者資料，我可以傳送到我自己的 server
    console.log(res)

    // 把使用者導回真正的網站
    window.location = 'http://example.com'
  })
```

我用 fetch 去打 `http://api.example.com/me` 拿資料，並且帶上 cookie。接著因為 server 不管怎樣都會回覆正確的 header，所以 CORS 檢查就通過了，我就拿到資料了。

因此這個攻擊只要使用者點了釣魚網站並且在 `example.com` 是登入狀態，就會中招。至於影響範圍要看網站的 api，最基本的就是只拿得到使用者資料，比較嚴重一點的可能可以拿到 user token（如果有這個 api）。

這個攻擊有幾件事情要注意：

1. 這不是 XSS，因為我沒有在 `example.com` 執行程式碼，我是在我自己的釣魚網站 `http://fake-example.com` 上執行
2. 這有點像是 CSRF，但是網站通常對於 GET 的 API 並不會加上 CSRF token 的防護，所以可以過關
3. 如果有設定 SameSite cookie，攻擊就會失效，因為 cookie 會帶不上去

因此這個攻擊要成立有幾個前提：

1. CORS header 給到不該給的 origin
2. 網站採用 cookie 進行身份驗證，而且沒有設定 SameSite
3. 使用者要主動點擊釣魚網站並且是登入狀態

針對第一點，可能沒有人會像我上面那樣子寫，直接反射 request header 的 origin。比較有可能的做法是這樣：

``` js
app.use((req, res, next) => {
  res.headers['Access-Control-Allow-Credentials'] = 'true'
  const origin = req.headers['Origin']

  // 偵測是不是 example.com 結尾
  if (/example\.com$/.test(origin)) {
    res.headers['Access-Control-Allow-Origin'] = origin
  }
})
```

如此一來，底下的 origin 都可以過關：

1. example.com
2. buy.example.com
3. social.example.com

可是這樣寫是有問題的，因為這樣也可以過關：

1. fakeexample.com

像是這類型的漏洞是經由錯誤的 CORS 設置引起，所以稱為 CORS misconfiguration。

而解決方法就是不要用 RegExp 去判斷，而是事先準備好一個清單，有在清單中出現的才通過，否則都是失敗，如此一來就可以保證不會有判斷上的漏洞，然後也記得把 cookie 加上 SameSite 屬性。

``` js
const allowOrigins = [
  'example.com',
  'buy.example.com',
  'social.example.com'
]
app.use((req, res, next) => {
  res.headers['Access-Control-Allow-Credentials'] = 'true'
  const origin = req.headers['Origin']

  if (allowOrigins.includes(origin)) {
    res.headers['Access-Control-Allow-Origin'] = origin
  }
})
```

想知道更多的話可以參考：

1. [3 Ways to Exploit Misconfigured Cross-Origin Resource Sharing (CORS)](https://we45.com/blog/3-ways-to-exploit-misconfigured-cross-origin-resource-sharing-cors/)
2. [JetBrains IDE Remote Code Execution and Local File Disclosure](http://blog.saynotolinux.com/blog/2016/08/15/jetbrains-ide-remote-code-execution-and-local-file-disclosure-vulnerability-analysis/)
3. [AppSec EU 2017 Exploiting CORS Misconfigurations For Bitcoins And Bounties by James Kettle](https://www.youtube.com/watch?v=wgkj4ZgxI4c&ab_channel=OWASP)

## 繞過 Same-origin Policy？

除了 CORS 以外，Same-origin policy 其實出現在瀏覽器的各個地方，例如說 `window.open` 以及 `iframe`。當你使用 `window.open` 打開一個網頁的時候，回傳值會是那個新的網頁的 window（更精確來說是 WindowProxy 啦，可以參考 [MDN: Window.open()](https://developer.mozilla.org/en-US/docs/Web/API/Window/open)），但只有在 same origin 的狀況下才能存取。

假設我現在在 `a.example.com` 好了，然後寫了這一段 script：

``` js
var win = window.open('http://b.example.com')
// 等新的頁面載入完成
setTimeout(() => {
  console.log(win)
}, 2000)
```

用 `window.open` 去開啟 `b.example.com`，等頁面載入完成之後去存取 `b.example.com` 的 window。

執行之後會看到 console 有一段錯誤：

![](/img/cors/frame-block.png)

因為 `a.example.com` 跟 `b.example.com` 是 cross origin，所以沒辦法存取到 window。這個規範其實也十分合理，因為如果能存取到 window 的話其實可以做滿多事情的，所以限制在 same origin 底下才能拿到 window。

但是呢，如果這兩個網站是在同一個 subdomain 底下，而且你對兩個網站都有控制權，是可以透過更改 `document.domain` 來讓他們的 origin 相同的！

在 `a.example.com`，這樣子做：

``` js
// 新增這個，把 domain 設為 example.com
document.domain = 'example.com'

var win = window.open('http://b.example.com')
// 等新的頁面載入完成
setTimeout(() => {
  console.log(win.secret) // 12345
}, 2000)
```

在 `b.example.com` 裡面也需要做一樣的事情：

``` js
document.domain = 'example.com'
window.secret = 12345
```

然後你就會神奇地發現，你現在可以拿到 `b.example.com` 的 window 了！

更詳細的介紹可以參考 MDN：[Document.domain](https://developer.mozilla.org/en-US/docs/Web/API/Document/domain)，會這樣可能是有什麼歷史因素，但未來因為安全性的問題有可能會被拔掉就是了。

## 進入正題：其他各種 COXX 是什麼？

前面這兩個其實都只是小菜而已，並不是這一篇著重的主題。這一篇最想跟大家分享的其實是：

1. CORB（Cross-Origin Read Blocking）
2. CORP（Cross-Origin Resource Policy）
3. COEP（Cross-Origin-Embedder-Policy）
4. COOP（Cross-Origin-Opener-Policy）

這幾個東西。

開頭我有提過了，這幾個東西沒有好好講的話很容易搞混，所以我會用我自己覺得可能比較好懂的方式來講解，接下來就開始吧。

## 嚴重的安全漏洞：meltdown 與 spectre

在 2018 年 1 月 3 號，Google 的 Project Zeror 對外發布了一篇名為：[Reading privileged memory with a side-channel](https://googleprojectzero.blogspot.com/2018/01/reading-privileged-memory-with-side.html) 的文章，裡面講述了三種針對 CPU data cache 的攻擊：

1. Variant 1: bounds check bypass (CVE-2017-5753)
2. Variant 2: branch target injection (CVE-2017-5715)
3. Variant 3: rogue data cache load (CVE-2017-5754)

而前兩種又被稱為 Spectre，第三種被稱為是 Meltdown。如果你有印象的話，在當時這可是一件大事，因為問題是出在 CPU，而且並不是個容易修復的問題。

而這個漏洞的公佈我覺得對於瀏覽器的運作機制有滿大的影響（或至少加速了瀏覽器演進的過程），尤其是 spectre 可以拿來攻擊瀏覽器，而這當然也影響了這系列的主題：跨來源資源存取。

因此，稍微理解一下 spectre 在幹嘛我覺得是很有必要的。如果想要完全理解這個攻擊，需要有滿多的背景知識，但這不是這一篇主要想講的東西，因此底下我會以非常簡化的模型來解釋 spectre，想要完全理解的話可以參考上面的連結。

## 超級簡化版的 spectre 攻擊解釋

再次強調，這是為了方便理解所簡化過的版本，跟原始的攻擊有一定出入，但核心概念應該是類似的。

假設現在有一段程式碼（C 語言）長這樣子：

``` c
uint8_t arr1[16] = {1, 2, 3}; 
uint8_t arr2[256]; 
unsigned int array1_size = 16;

void run(size_t x) {
  if(x < array1_size) {
	  uint8_t y = array2[array1[x]];
  }
}

size_t x = 1;
run(x);
```

我宣告了兩個陣列，型態是 uint8_t，所以每個陣列的元素大小都會是 1 個 byte（8 bit）。而 arr1 的長度是 16，arr2 的長度是 256。

接下來我有一個 function 叫做 run，會吃一個數字 x，然後判斷 x 是不是比 array1_size 小，是的話我就先把 `array1[x]` 的值取出來，然後作為索引去存取 `array2`，再把拿到的值給 y。

以上面的例子來說，`run(1)` 的話，就會執行：

``` C
uint8_t y = array2[array1[1]];
```

而 `array1[1]` 的值是 2，所以就是 `y = array2[2]`。

這段程式碼看起來沒什麼問題，而且我有做了陣列長度的判斷，所以不會有超出陣列索引（Out-of-Bounds，簡稱 OOB）的狀況發生，只有在 x 比 array1_size 小的時候才會繼續往下執行。 

不過這只是你看起來而已。

在 CPU 執行程式碼的時候，有一個機制叫做 branch prediction。為了增進程式碼執行的效率，所以 CPU 在執行的時候如果碰到 if 條件，會先預測結果是 true 還是 false，如果預測的結果是 true，就會先幫你執行 if 裡面的程式碼，把結果先算出來。

剛剛講的都只是「預測」，等到實際的 if 條件執行完之後，如果跟預測的結果相同，那就皆大歡喜，如果不同的話，就會把剛剛算完的結果丟掉，這個機制稱為：預測執行（speculatively execute）

因為 CPU 會把結果丟掉，所以我們也拿不到預測執行的結果，除非 CPU 有留下一些線索。

而這就是 spectre 攻擊成立的主因，因為還真的有留下線索。

一樣是為了增進執行的效率，在預測執行的時候會把一些結果放到 CPU cache 裡面，增進之後讀取資料的效率。

假設現在有 ABC 三個東西，一個在 CPU cache 裡面，其他兩個都不在，我們要怎麼知道到底是哪一個在？

答案是，透過存取這三個東西的時間！因為在 CPU cache 裡面的東西讀取一定比較快，所以如果讀取 A 花了 10ms，B 花了 10ms，C 只花了 1ms，我們就知道 C 一定是在 CPU cache 裡面。這種透過其他線索來得知資訊的攻擊方法，叫做 side-channel attack，從其他管道來得知資訊。

上面的方法我們透過時間來判斷，所以又叫做 timing-attack。

結合上述知識之後，我們再回來看之前那段程式碼：

``` c
uint8_t arr1[16] = {1, 2, 3}; 
uint8_t arr2[256]; 
unsigned int array1_size = 16;

void run(size_t x) {
  if(x < array1_size) {
	  uint8_t y = array2[array1[x]];
  }
}

size_t x = 1;
run(x);
```

假設現在我跑很多次 `run(10)`，CPU 根據 branch prediction 的機制，合理推測我下一次也會滿足 if 條件，執行到裡面的程式碼。就在這時候我突然把 x 設成 100，跑了一個 `run(100)`。

這時候 if 裡面的程式碼會被預測執行：

``` C
uint8_t y = array2[array1[100]];
```

假設 array1[100] 的值是 38 好了，那就是 `y = array2[38]`，所以 `array2[38]` 會被放到 CPU cache 裡面，增進之後載入的效率。

接著實際執行到 if condition 發現條件不符合，所以把剛剛拿到的結果丟掉，什麼事都沒發生，function 執行完畢。

然後我們根據剛剛上面講的 timing attack，去讀取 array2 的每一個元素，並且計算時間，會發現 `array2[38]` 的讀取時間最短。

這時候我們就知道了一件事：

> array1[100] 的內容是 38

你可能會問說：「那你知道這能幹嘛？」，能做的事情可多了。array1 的長度只有 16，所以我讀取到的值並不是 array1 本身的東西，而是其他部分的記憶體，是我不應該存取到的地方。而我只要一直複製這個模式，就能把其他地方的資料全都讀出來。

這個攻擊如果放在瀏覽器上面，我就能讀取同一個 process 的其他資料，換句話說，如果同一個 process 裡面有其他網站的內容，我就能讀取到那個網站的內容！

這就是 spectre 攻擊，透過 CPU 的一些機制來進行 side-channal attack，進而讀取到本來不該讀到的資料，造成安全性問題。

所以用一句白話文解釋，在瀏覽器上面，spectre 可以讓你有機會讀取到其他網站的資料。

有關 spectre 的解釋就到這裡了，上面簡化了很多細節，而那些細節我其實也沒有完全理解，想知道更多的話可以參考：

1. [Reading privileged memory with a side-channel](https://googleprojectzero.blogspot.com/2018/01/reading-privileged-memory-with-side.html)
2. [解读 Meltdown & Spectre CPU 漏洞](https://zhuanlan.zhihu.com/p/32757727)
3. [浅谈处理器级Spectre Attack及Poc分析](https://yangrz.github.io/blog/2018/01/09/cpu/)
4. [[閒聊] Spectre & Meltdown漏洞概論(翻譯)](https://www.ptt.cc/bbs/NetSecurity/M.1515146856.A.750.html)
5. [Spectre漏洞示例代码注释](https://github.com/hdzitao/spectre-attack-zh)
6. [Google update: Meltdown/Spectre](https://developers.google.com/web/updates/2018/02/meltdown-spectre)
7. [Mitigating Spectre with Site Isolation in Chrome](https://security.googleblog.com/2018/07/mitigating-spectre-with-site-isolation.html)

而那些 COXX 的東西，目的都是差不多的，都是要防止一個網站能夠讀取到其他網站的資料。只要不讓惡意網站跟目標網站處在同一個 process，這類型的攻擊就失效了。

從這個角度出發，我們來看看各種相關機制。

## CORB（Cross-Origin Read Blocking）

Google 於 spectre 攻擊公開的一個月後，也就是 2018 年 2 月，在部落格上面發了一篇文章講述 Chrome 做了哪些事情來防堵這類型的攻擊：[Meltdown/Spectre](https://developers.google.com/web/updates/2018/02/meltdown-spectre)。

文章中的 Cross-Site Document Blocking 就是 CORB 的前身。根據 [Chrome Platform Status](https://www.chromestatus.com/feature/5629709824032768)，在 Chrome for desktop release 67 的時候正式預設啟用，那時候大概是 2018 年 5 月，也差不多那個時候，被 merge 進去 fetch 的 spec，成為規格的一部分（[CORB: blocking of nosniff and 206 responses](https://github.com/whatwg/fetch/pull/686)）。

前面有提到過 spectre 能夠讀取到同一個 process 底下的資料，所以防禦的其中一個方式就是不要讓其他網站的資料出現在同一個 process 底下。

一個網站有許多方式可以把跨來源的資源設法弄進來，例如說 `fetch` 或是 `xhr`，但這兩種已經被 CORS 給控管住了，而且拿到的 response 應該是存在 network 相關的 process 而不是網站本身的 process，所以就算用 spectre 也讀不到。

但是呢，用 `<img>` 或是 `<script>` 這些標籤也可以輕易地把其他網站的資源載入。例如說：`<img src="https://bank.com/secret.json">`，假設 `secret.json` 是個機密的資料，我們就可以把這個機密的資料給「載入」。

你可能會好奇說：「這樣做有什麼用？那又不是一張圖片，而且我用 JS 也讀取不到」。沒錯，這不是一張圖片，但以 Chrome 的運作機制來說，Chrome 在下載之前不知道它不是圖片（有可能副檔名是 .json 但其實是圖片對吧），因此會先下載，下載之後把結果丟進 render process，這時候才會知道這不是一張圖片，然後引發載入錯誤。

看起來沒什麼問題，但別忘了 spectre 開啟了一扇新的窗，那就是「只要在同一個 process 的資料我都有機會讀取到」。因此光是「把結果丟進 render process」這件事情都不行，因為透過 spectre 攻擊，攻擊者還是拿得到存在記憶體裡面的資料。

因此 CORB 這個機制的目的就是：

> 如果你想讀的資料類型根本不合理，那我根本不需要把它放到 render process，結果我直接丟掉就好！

延續上面的例子，那個 json 檔的 MIME type 如果是 application/json，代表它絕對不會是一張圖片，因此也不可能放到 img 標籤裡面，這就是我所說的「讀的資料類型不合理」。



