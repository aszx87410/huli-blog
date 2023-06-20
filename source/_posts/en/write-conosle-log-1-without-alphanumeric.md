---
title: How to write console.log(1) without using letters and numbers in JavaScript?
catalog: true
date: 2020-12-01 20:54:18
tags:
- JavaScript
categories:
- JavaScript
photos: /img/write-conosle-log-1-without-alphanumeric/cover-en.png
---

## Introduction

Recently, my colleagues at work took a course on information security. As I was already interested in information security, I discussed it with my colleagues, which led me to research related topics for the past two weeks. These were things I had heard of before but had not studied seriously, such as LFI (Local File Inclusion), REC (Remote code execution), SSRF (Server-Side Request Forgery), and various magical filters in PHP. I also reviewed SQL Injection and XSS, which I was already relatively familiar with.

In CTF challenges, situations often arise where you need to bypass various restrictions, which is an opportunity to test your understanding of specific protocols or programming languages. You have to think about how to find at least one way to successfully bypass those restrictions under existing limitations.

Originally, I didn't know what to write about this week. I wanted to write about the things mentioned above, but I hadn't figured out how to organize them yet. The follow-up series of "I Don't know React" was not yet organized, so I thought it would be fun to do a little challenge related to "bypassing restrictions" with everyone. That is:

> In JavaScript, can you successfully execute console.log(1) without using letters and numbers?

In other words, no English letters (a-zA-Z) or numbers (0-9) can appear in the code. Everything else (various symbols) is allowed. After executing the code, console.log(1) will be executed, and 1 will be printed in the console.

If you have thought of any interesting services or libraries that can do this before, don't mention them yet. Before that, you can think about it yourself and see if you can write it out, and then check other people's solutions.

If you can write it all by yourself from scratch, it means that you should be quite familiar with the JS programming language and various automatic type conversions.

Below, I will provide some of my own thoughts and the process of solving this problem. There are spoilers, so don't scroll down if you haven't solved it yet.


== Spoiler Alert ==  
== Spoiler Alert ==  
== Spoiler Alert ==  
== Spoiler Alert ==  
== Spoiler Alert ==  

<!-- more -->

== Spoiler Alert ==  
== Spoiler Alert ==  
== Spoiler Alert ==  
== Spoiler Alert ==  
== Spoiler Alert ==  
== Spoiler Alert ==  
== Spoiler Alert ==  
== Spoiler Alert ==  

## Analysis of key points for solving the problem

To successfully execute `console.log(1)` as required by the problem, several things must be done, such as:

1. Find out how to execute the code
2. How to get numbers without using letters and numbers
3. How to get letters without using letters and numbers

If these three points are all solved, the requirements of the problem should be met.

Let's first think about the first point: "How to execute the code?"

Directly using `console.log` is impossible because even if you use a string to concatenate console, you cannot execute the function with a string like [PHP](https://www.php.net/manual/en/functions.variable-functions.php).

What about eval? You can put a string in eval, so you can execute any code! But the problem is that we can't use eval because we can't type English letters.

What other methods are there? You can also use the function constructor: `new Function("console.log(1)")` to execute, but the problem is that we can't use the keyword "new," so at first glance, it doesn't work. However, you don't need "new" either. You can create a function that can execute specific code with `Function("console.log(1)")`.

So the next question is: How can we get the function constructor? If we can get it, we have a chance.

In JS, you can use `.constructor` to get the constructor of something, such as `"".constructor`, which will get: `ƒ String() { [native code] }`. If you have a function today, you can get the function constructor, like this: `(()=>{}).constructor`, and because we can expect that this problem will concatenate various things with strings, we can't use `.constructor` directly, so we should change it to: `(()=>{})['constructor']`.

What if ES6 is not supported? What if you can't support arrow functions? Is there a way to get a function?

Yes, and it's easy, it's all built-in functions, such as `[]['fill']['constructor']`, which is actually `[].fill.constructor`, or `""['slice']['constructor']`, which can also get the function constructor. So this is not a difficult task, even without arrow functions.

Initially, we expected the code to be like this: `Function('console.log(1)')()`. If we rewrite it using the method mentioned above, we will replace `Function` with `(()=>{})['constructor']`, which becomes `(()=>{})['constructor']('console.log(1)')()`. 

Once we have this code, the problem of executing the function is solved. So, we have solved the first problem.

Next, let's think about how to generate numbers. The key here is JS coercion. If you have read some articles on JS type conversion, you may remember that `{}+[]` can give the number 0. Using the `!` operator, we can get false, for example, `![]` or `!{}` both give false. Then, adding two false values gives 0: `![]+![]`. Similarly, `![]` is false, so adding a not operator before it gives `!![]`, which is true. Therefore, `![] + !![]` is equal to false + true, which is 0 + 1, resulting in 1.

There is also a shorter method. Using `+[]`, we can get 0 through automatic type conversion. So, `+!![]` gives 1. Once we have 1, we can generate all numbers by adding 1 repeatedly. Alternatively, we can use bitwise operators `<<` and `>>` or multiplication. For example, to generate 8, we can use `1 << 3` or `2 << 2`. To generate 2, we can use `(+!![])+(+!![])`. Therefore, `(+!![])+(+!![]) << (+!![])+(+!![])` gives 8, which requires only four 1s, instead of adding 8 times.

However, we can ignore the length for now and focus on whether we can generate 1. Once we have 1, we have won.

Finally, we need to figure out how to generate strings, or in other words, how to generate each character in `(()=>{})['constructor']('console.log(1)')()`. The key is coercion, just like with numbers. As mentioned earlier, `![]` gives false, and adding a string to it, `![] + ''`, gives `"false"`. This way, we can get the characters a, e, f, l, and s. For example, `(![] + '')[1]` is a. To make it easier to remember, let's write a small program:

``` js
const mapping = {
  a: "(![] + '')[1]",
  e: "(![] + '')[4]",
  f: "(![] + '')[0]",
  l: "(![] + '')[2]",
  s: "(![] + '')[3]",
}
```

Once we have false, getting true is not difficult. `!![] + ''` gives `true`. So, we can modify our code to:

``` js
const mapping = {
  a: "(![] + '')[1]",
  e: "(![] + '')[4]",
  f: "(![] + '')[0]",
  l: "(![] + '')[2]",
  r: "(!![] + '')[1]",
  s: "(![] + '')[3]",
  t: "(!![] + '')[0]",
  u: "(!![] + '')[2]",
}
```

Next, we can use coercion again. Using `''+{}` gives `"[object Object]"` (or you can use the magical `[]+{}`). Our table can be updated as follows:

``` js
const mapping = {
  a: "(![] + '')[1]",
  b: "(''+{})[2]",
  c: "(''+{})[5]",
  e: "(![] + '')[4]",
  f: "(![] + '')[0]",
  j: "(''+{})[3]",
  l: "(![] + '')[2]",
  o: "(''+{})[1]",
  r: "(!![] + '')[1]",
  s: "(![] + '')[3]",
  t: "(!![] + '')[0]",
  u: "(!![] + '')[2]",
}
```

What happens when we get a non-existent property from an array or object? We get undefined. Adding a string to undefined gives us the string "undefined", for example, `[][{}]+''` gives `undefined`. After getting undefined, our conversion table becomes more complete:

``` js
const mapping = {
  a: "(![] + '')[1]",
  b: "(''+{})[2]",
  c: "(''+{})[5]",
  d: "([][{}]+'')[2]",
  e: "(![] + '')[4]",
  f: "(![] + '')[0]",
  i: "([][{}]+'')[5]",
  j: "(''+{})[3]",
  l: "(![] + '')[2]",
  n: "([][{}]+'')[1]",
  o: "(''+{})[1]",
  r: "(!![] + '')[1]",
  s: "(![] + '')[3]",
  t: "(!![] + '')[0]",
  u: "(!![] + '')[2]",
}
```

Looking at the conversion table and our target string, `(()=>{})['constructor']('console["log"](1)')()`, we can see that generating `constructor` and `console` is not a problem, but we are missing the `g` in log. This character is not in our conversion table.

Therefore, we must get the `g` from somewhere to generate the string we want. Alternatively, we can use another method to get the character.

I thought of two methods initially. The first method is to use base conversion. When we use `toString` to convert a number to a string, we can specify the radix parameter, which represents the base to which the number is converted. For example, `(10).toString(16)` gives a because the decimal number 10 is equivalent to the hexadecimal number a. There are 26 English letters and 10 numbers, so we can use `(10).toString(36)` to get a and `(16).toString(36)` to get g. However, the problem is that `toString` itself has a `g`, which we don't have right now, so this method won't work.

The other method I thought of is to use base64. JS has two built-in functions: `btoa` and `atob`. `btoa` encodes a string into base64, for example, `btoa('abc')` gives YWJj, and `atob('YWJj')` decodes it to abc.

We just need to find a way to have a "g" in the result after base64 encoding. This can be achieved by running the code `btoa(2)[1]`, which returns the string "Mg==", and taking the second character, which is "g". However, we need to execute this code using the function constructor, like this: `(()=>{})['constructor']('return btoa(2)[1]')()`. 

To achieve this, we can use a mapping of characters to their corresponding code, and a function to transform the code into a string. We can also write a function to remove all characters from a string, leaving only the numbers. 

Finally, we can combine all of our efforts to produce the desired output: `console.log(1)` with all letters and numbers removed. However, since `btoa` is a Web API and not available in Node.js, we need to find another way to generate the "g" character. We can use the string constructor and add a string to it to get its contents, like this: `''['constructor'] + ''`, which returns the string "function String() { [native code] }". We can then get the "g" character by using `(''['constructor'] + '')[7+7]`.

So far, we have used 1800 characters to successfully create a program that only contains the following 12 characters: `[`, `]`, `(`, `)`, `{`, `}`, `"`, `'`, `+`, `!`, `=`, `>`, and can execute `console.log(1)`.

And because we can now get these few characters, we can use the previously mentioned method of base conversion to get any lowercase character, like this:

``` js
mapping['S'] = transform(`return (''['constructor'] + '')[9]`)
mapping['g'] = transform(`return (''['constructor'] + '')[7+7]`)
console.log(transform('return (35).toString(36)')) // z
```

So how do we get any uppercase character, or even any character? I have thought of a few ways.

If you want to get any character, you can use `String.fromCharCode`, or write it in another form: `""['constructor']['fromCharCode']`, to get any character. But before that, we need to figure out how to get the uppercase C.

In addition to this approach, there is another one that relies on encoding, such as `'\u0043'`, which is actually the uppercase C. So I thought I could use this method to piece it together, but it didn't work when I tried it. For example, `console.log("\u0043")` will print C correctly, but `console.log(("\u00" + "43"))` will give you an error. It seems that encoding cannot be pieced together in this way (which makes sense when you think about it).

## Conclusion

In fact, I have written a post before: [Making JavaScript Hard to Read: jsfuck and aaencode](https://blog.techbridge.cc/2016/07/16/javascript-jsfuck-and-aaencode/), which talks about the same thing, but I only organized it a little bit before. This time, I tried it myself and it feels different.

The conversion function that was finally written is not complete and cannot execute any code. I didn't finish it because the [jsfuck](https://github.com/aemkei/jsfuck) library has already written it very clearly, with a detailed description of its conversion process in the README, and it only uses 6 characters, which is really impressive.

In its [code](https://github.com/aemkei/jsfuck/blob/master/jsfuck.js), you can also see how its conversion is done. The uppercase C part uses a function called `italics` on the String, which can generate `<i></i>`. After generating it, call escape to escape it, and you will get `%3Ci%3E%3C/i%3E`, and then you have the uppercase C.

Some people may think that they write their code well on a regular basis, so why bother doing this? But the point of doing this is not the final result, but to train a few things, such as:

1. Familiarity with programming languages. We used many type conversions and built-in methods to piece things together, some of which you may have never heard of.
2. Problem-solving and the ability to narrow down the scope. From how to execute a string as a function, to piecing together numbers and strings, step by step narrowing down the problem, solving the sub-problems, and then solving the original problem.

Anyway, the above is my thought process for solving this problem. If you have any interesting solutions, please leave a comment and let me know (such as other ways to get the uppercase letter C). Thank you!
