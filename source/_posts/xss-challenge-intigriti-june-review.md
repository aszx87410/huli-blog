---
title: Intigriti 六月份 XSS 挑戰檢討
catalog: true
date: 2021-07-03 09:32:52
tags: [Security, Front-end]
categories:
  - Security
---

## 前言

六月份的挑戰沒解出來，這篇透過兩篇公開的 writeup 來學習一下其他人的做法，順便檢討一下自己哪邊可以再加強。

<!-- more -->

## 程式碼分析與思考過程

六月份挑戰：https://challenge-0621.intigriti.io/

![](/img/others/xss-june.png)

程式碼：

``` js
const unsafeCharacters = ["&", "`", "\"", "{", "}", "(", ")", "[", "]", "=", ",", "+"];
function sanitize(str) {
  str += "";
  for (let char of unsafeCharacters) {
    str = str.replaceAll(char, `&#x${char.codePointAt().toString(0x10)};`);
  }
  return str;
}
function showMessage(title = "", message = "", button = { text: "Close", action: "this.parentElement.parentElement.parentElement.remove();", }) {
  let elem = (new Range).createContextualFragment(`
    <div class="alert">
      <div class="alert-inner">
        <div class="page-bar">
          <h3>${sanitize(title)}</h3>
          <button onclick="${sanitize(button.action)}">${sanitize(button.text)}</button>
        </div>
        <div class="page-content">
          ${sanitize(message)}
        </div>
      </div>
    </div>
  `);
  document.body.append(elem);
}
let inputFields = {
  passwordLength: document.getElementById("password-length"),
  allowNumbers: document.getElementById("allow-numbers"),
  allowSymbols: document.getElementById("allow-symbols"),
}
let generating = false;
async function generate() {
  if (generating) {
    return;
  }
  requestAnimationFrame(_ => (generating = false));
  generating = true;
  let passwordLength = inputFields.passwordLength.value;
  let json = `{ "passwordLength": ${passwordLength}, "seed": ${crypto.getRandomValues(new Uint32Array(1))[0]}, "allowNumbers": ${inputFields.allowNumbers.checked}, "allowSymbols": ${inputFields.allowSymbols.checked} }`;
  if (!(passwordLength = passwordLength.match(/^\d+$/gm))) {
    return showMessage("Error", "Password Length must be a number.");
  }
  passwordLength = Number(passwordLength[0]);
  let wasm = await WebAssembly.instantiateStreaming(fetch("program.wasm"), { env: { log_str: idx => {
    let str = "";
    while (u8[idx] != 0) {
      str += String.fromCodePoint(u8[idx]);
      ++idx;
    }
    console.log(str);
  }, log_int: console.log, }});
  let u8 = new Uint8Array(wasm.instance.exports.memory.buffer);
  let options = wasm.instance.exports.malloc(json.length + 1);
  let password = wasm.instance.exports.malloc(Number(passwordLength) + 1);
  for (let idx = 0; idx < json.length; ++idx) {
    u8[options + idx] = json.codePointAt(idx) % 0xff;
  }
  u8[options + json.length] = 0;
  wasm.instance.exports.generate_password(options, password);
  let output_password = "";
  for (let idx = 0; idx < passwordLength; ++idx) {
    output_password += String.fromCodePoint(u8[password + idx]);
  }
  showMessage("Password Generated", "Your password is: " + output_password, { text: "OK", action: "generateAnother();", });
}
function generateAnother() {
  let params = new URLSearchParams;
  params.set("passwordLength", inputFields.passwordLength.value);
  params.set("allowNumbers", inputFields.allowNumbers.checked);
  params.set("allowSymbols", inputFields.allowSymbols.checked);
  params.set("timestamp", Number(new Date));
  location.search = params;
}
let settings = new URLSearchParams(location.search);
inputFields.passwordLength.value = settings.get("passwordLength") ?? 8;
inputFields.allowNumbers.checked = settings.get("allowNumbers") !== "false";
inputFields.allowSymbols.checked = settings.get("allowSymbols") !== "false";
```

基本上就是從 query string 拿一些參數，丟到 wasm 裡面去產生密碼，當初在解這題的時候有發現幾個地方需要繞過。

第一個是 `if (!(passwordLength = passwordLength.match(/^\d+$/gm))) {`，限定密碼長度只能是數字。

當初看到這邊時有注意到 `m` 那個 flag 沒必要，是配對換行的，所以 `123\nabc`一樣可以通過。但後來卡住的點是那個 value 是從 input 拿出來的，而 input 會把 `\n` 過濾掉，所以沒辦法用 `\n`。

那時候就在這邊整個卡死。

第二個需要做事情的點就是 wasm 那一段了，那段我有試著把它 decompile 出來不過看不懂在幹嘛。

我那時直覺猜測的解法是透過 passwordLength 去改造傳進去的 JSON，然後把 seed 固定在某個數字，就會產生出某個可行的 payload（後來發現根本不是這樣）

不過因為我也不知道 wasm 在幹嘛，所以當時就繼續往下看，產生出的密碼會經過過濾，這些字元都不能用：

```
["&", "`", "\"", "{", "}", "(", ")", "[", "]", "=", ",", "+"]
```

沒有過濾掉 `<>` 所以可以新增標籤，可是反引號跟 () 全都被過濾掉，被過濾到的字元太多了，我沒想到可以繞過的方法。

當初解題的思路大概就是這樣，有找到三個需要做事的地方，但因為三個地方都沒繞過，所以就沒解出來。

接下來來看一下別人的 writeup，中途順便做個自我檢討。

## terjanq

連結：[How to solve an XSS challenge from Intigriti in under 60 minutes](https://terjanq.medium.com/how-to-solve-a-challenge-from-intigrity-in-under-60-minutes-6843ba9b9552)

這篇除了分享解法之外還分享了他是怎麼思考的，在一小時內就把這題解開，真的猛。

他的解法是掃過一遍 code 之後發現 wasm 那邊一定有問題，就先開始測試那邊怎麼打下來。測試的方法就是複製一份 code 然後自己去改 JSON payload 去測 wasm。

這個方法其實大家都知道，但我自己可以檢討的方向就是當時太懶...我一直預設說這一題就是要 reverse wasm，所以就連試都沒去試，預設立場然後立場又不對，就卡死了。

之後可以積極嘗試不同方法，不要被困在既有的想法裡面。

再來他簡單掃了一下 wasm，發現沒什麼隱藏的東西，開始問自己說有什麼漏洞是只有 wasm 會有而 JS 沒有的，答案是 buffer overflow。

接著他就開始去試，發現密碼長度很長的時候，payload 會反映出原本的密碼。解到這邊之後他確定這一段可行，開始看其他部分。

regexp 繞過那邊，他直接根據經驗給出了可以繞過的字元 /u2028 跟 /u2029

這邊其實有下對關鍵字也查得到：[Line terminators](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Lexical_grammar#line_terminators)，我當初犯的錯誤是太早放棄，一直想說：「我知道可能有其它字元也可以換行，但我不知道是什麼啊」，阿是不會去 google 逆啦

這邊繞過之後開始繞過最後的限制，也就是一大堆限制字元的那邊。這邊的手法很炫，那就是 `-` 並沒有被限制，所以可以使用很多次的 `unsafeCharacters.length--` 去把陣列縮短，這樣限制字元就變少了！

不過這樣的話，就變成要觸發整個流程兩次，第一次把限制字元縮短，第二次才能把真正的 payload 放到畫面上。可是一旦 alert 出現之後，按下關閉就會重整網頁，沒辦法觸發兩次。

最後給出的解法是：`document.body.lastElementChild.outerHTML--`，把剛剛新增進去的 alert 整個破壞掉變成 NaN，就不會重整了。

完整程式碼：

```
1000\u2029<script>unsafeCharacters.length--;unsafeCharacters.length--;unsafeCharacters.length--;unsafeCharacters.length--;unsafeCharacters.length--;unsafeCharacters.length--;unsafeCharacters.length--;document.body.lastElementChild.outerHTML--;</script><script>alert()</script>
```

需要點擊 generate 兩次才能觸發。

最後總結一下學到的東西：

1. 分段落去嘗試，遇到不懂的東西就先亂試東西看看，搞不好就壞掉找出問題了
2. 不要預設立場，解法可能跟你想的方向完全不同
3. google 很好用
4. 如果沒辦法繞過限制，就把限制破壞掉

## FHantke

連結：[Intigriti — XSS Challenge 0621](https://infosecwriteups.com/intigriti-xss-challenge-0621-cf76c28840c1)

關於 regexp 的繞過，他直接寫了段簡單的程式 fuzzing 一下：

``` js
for (i=0;i<10000; i++) {
  let passwordLength = document.getElementById("password-length");
  passwordLength.value = "2" + String.fromCharCode(i) + "4";  
  var p = passwordLength.value.match(/^\d+$/gm);
  if (p) console.log(i + " => " + p);
}
```

對欸，為什麼我沒有想到可以這樣找，寫一段 code 幫你去猜怎樣可以繞過就好，這招很棒一定要學起來。

接著他一樣去試說怎樣的 payload 可以把 wasm 弄爆，發現 passwordLength 傳很大的，然後 allowedNumbers 傳個字串，就會反映在產生的密碼上面。

最後他用的技巧是：`<svg><script>alert(1)</script></svg>`，雖然說一樣會變成：`<svg><script>alert&#40;1&#41;</script></svg>`，但因為是包在 svg 裡面，所以會用 svg 的 parser 來解析，解析的規則不同，原文裡有附上 DOM 的圖。

這招也好棒，我記得好像以前有在哪邊看過。

不過最後的 payload 只在 Firefox 上面有用而已，不太確定為什麼，原文也沒寫到，我暫時也懶得查XD

話說寫完之後才發現這篇 writeup: [Intigriti's 0621 XSS challenge - by Physuru (@cffaedfe)](https://github.com/svennergr/writeups/blob/master/inti/0621/README.md)，裡面一樣用了很多 fuzzing 來找出合法的 payload，這篇也滿值得參考的。

## 總結

學到幾招很好用的：

1. 用 `<svg><script></script></svg>` 繞過一些字元被 encode 的限制
2. 用 `arr.length--` 破壞陣列
3. 用 fuzzing 去找出合法的字元是什麼，簡單暴力又有效
4. 有些東西不要先深入去看實作，先去試 payload，傳入不同組合跟極端的參數看看


