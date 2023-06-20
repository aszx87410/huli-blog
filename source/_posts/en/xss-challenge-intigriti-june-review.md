---
title: Intigriti June XSS Challenge Review
catalog: true
date: 2021-07-03 09:32:52
tags: [Security, Front-end]
categories:
  - Security
photos: /img/xss-challenge-intigriti-june-review/cover-en.png
---

## Introduction

I couldn't solve the challenge for June, so I'm going to learn from other people's writeups and review where I can improve.

<!-- more -->

## Code Analysis and Thought Process

June Challenge: https://challenge-0621.intigriti.io/

![](/img/others/xss-june.png)

Code:

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

Basically, some parameters are taken from the query string and passed to wasm to generate a password. When I was solving this problem, I found a few places that needed to be bypassed.

The first one is `if (!(passwordLength = passwordLength.match(/^\d+$/gm))) {`, which limits the password length to only numbers.

When I saw this, I noticed that the `m` flag was unnecessary because it matches with line breaks, so `123\nabc` can also pass. But later, I got stuck because the value was taken from the input, and the input filters out `\n`, so I couldn't use `\n`.

I got stuck here.

The second point where something needs to be done is the wasm part. I tried to decompile it, but I couldn't understand what it was doing.

My initial guess was to use passwordLength to modify the JSON passed in, and then fix the seed to a certain number, which would generate a feasible payload (later I found out that it wasn't like that).

But because I didn't know what wasm was doing, I continued to look down. The generated password will be filtered, and these characters cannot be used:

```
["&", "`", "\"", "{", "}", "(", ")", "[", "]", "=", ",", "+"]
```

`<>` is not filtered, so tags can be added, but backticks and () are all filtered out, and too many characters are filtered out, so I didn't think of a way to bypass it.

That was the train of thought when I was solving the problem. I found three places where something needed to be done, but because none of them were bypassed, I couldn't solve it.

Next, let's take a look at someone else's writeup and do a self-review in the process.

## terjanq

Link: [How to solve an XSS challenge from Intigriti in under 60 minutes](https://terjanq.medium.com/how-to-solve-a-challenge-from-intigrity-in-under-60-minutes-6843ba9b9552)

In addition to sharing the solution, this article also shares how he thought about it and solved it in under an hour, which is really impressive.

His solution was to scan the code and find that there must be a problem with wasm, so he started testing how to bring it down. The testing method is to copy the code and test wasm by modifying the JSON payload.

Everyone knows this method, but the direction I can review myself is that I was too lazy at the time... I always assumed that this problem was about reversing wasm, so I didn't even try it. I had a preset position and the position was wrong, so I got stuck.

Afterwards, I can actively try different methods and not be trapped in existing ideas.

Then he briefly scanned wasm and found nothing hidden, and started asking himself what vulnerabilities only wasm has and not JS, and the answer was buffer overflow.

Then he started testing and found that when the password length was very long, the payload would reflect the original password. After solving this part, he was sure that this part was feasible and started looking at other parts.

For the part where regexp needs to be bypassed, he directly gave the characters that can be bypassed based on experience, which are /u2028 and /u2029.

The keywords can actually be found here: [Line terminators](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Lexical_grammar#line_terminators). The mistake I made at the time was giving up too early and kept thinking, "I know there may be other characters that can be line breaks, but I don't know what they are." I didn't google it.

After bypassing this part, he started to bypass the last restriction, which is a bunch of restricted characters. The technique used here is very cool, which is that `-` is not restricted, so you can use `unsafeCharacters.length--` many times to shorten the array, so there are fewer restricted characters!

However, in this way, the entire process needs to be triggered twice, the first time to shorten the restricted characters, and the second time to put the real payload on the screen. But once the alert appears, clicking close will refresh the webpage, and it is impossible to trigger it twice.

The final solution given is: `document.body.lastElementChild.outerHTML--`, which destroys the newly added alert and turns it into NaN, preventing it from refreshing.

Complete code:

```
1000\u2029<script>unsafeCharacters.length--;unsafeCharacters.length--;unsafeCharacters.length--;unsafeCharacters.length--;unsafeCharacters.length--;unsafeCharacters.length--;unsafeCharacters.length--;document.body.lastElementChild.outerHTML--;</script><script>alert()</script>
```

You need to click generate twice to trigger it.

In summary, here are the things learned:

1. Try to break it down into paragraphs and try random things when you encounter something you don't understand. You might break it and find the problem.
2. Don't assume anything. The solution may be completely different from what you think.
3. Google is very useful.
4. If you can't bypass the restriction, break it.

## FHantke

Link: [Intigriti — XSS Challenge 0621](https://infosecwriteups.com/intigriti-xss-challenge-0621-cf76c28840c1)

Regarding the bypass of regexp, he wrote a simple program to fuzz it:

``` js
for (i=0;i<10000; i++) {
  let passwordLength = document.getElementById("password-length");
  passwordLength.value = "2" + String.fromCharCode(i) + "4";  
  var p = passwordLength.value.match(/^\d+$/gm);
  if (p) console.log(i + " => " + p);
}
```

Yes, why didn't I think of this? Just write a code to help you guess how to bypass it. This trick is great and must be learned.

Then he tried to find a payload that could break wasm. He found that if he passed a large passwordLength and a string to allowedNumbers, it would be reflected in the generated password.

Finally, he used the trick: `<svg><script>alert(1)</script></svg>`. Although it will still become: `<svg><script>alert&#40;1&#41;</script></svg>`, because it is wrapped in svg, the svg parser will be used to parse it, and the parsing rules are different. The original text has a DOM diagram attached.

This trick is also great. I remember seeing it somewhere before.

However, the final payload only works on Firefox, and I'm not sure why. The original text didn't mention it, and I'm too lazy to check it out for now XD

By the way, after writing it, I found this writeup: [Intigriti's 0621 XSS challenge - by Physuru (@cffaedfe)](https://github.com/svennergr/writeups/blob/master/inti/0621/README.md), which also uses a lot of fuzzing to find valid payloads. This article is also worth referring to.

## Summary

Learned some useful tricks:

1. Use `<svg><script></script></svg>` to bypass some character encoding restrictions.
2. Use `arr.length--` to destroy arrays.
3. Use fuzzing to find out what valid characters are. It's simple, violent, and effective.
4. Don't dive into the implementation first. Try different combinations of payloads and extreme parameters.
