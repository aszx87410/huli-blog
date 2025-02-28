---
title: Understanding the Execution Environment (Runtime) in JavaScript
catalog: true
date: 2022-02-09 21:10:50
tags: [Front-end, JavaScript]
categories: [JavaScript]
photos: /img/javascript-runtime/cover-en.png
---

I believe that in order to understand the JavaScript programming language, it is important to understand the concept of the "execution environment" or "runtime". Many people are not aware of this concept, which can lead to differences in understanding of JavaScript or other technologies. Therefore, in this article, let's talk about the execution environment.

Note: In addition to "runtime", "execution environment" is also used to refer to the same concept, but these two terms are completely different. To avoid confusion, we will use the term "runtime" throughout this article.

Also, "runtime" has many meanings, but in this context, it refers to the runtime environment.

<!-- more -->

## The Function That Exists and Doesn't Exist

Our protagonist, Xiao Ming, received a requirement at work to encode a string in base64.

In JavaScript, how do we convert a string to base64 encoding? There is a function called [btoa](https://developer.mozilla.org/en-US/docs/Web/API/btoa) that can do this. You can open the Chrome devtool console and enter the following code:

``` js
console.log(btoa('hello')) // aGVsbG8=
```

To convert a string from base64, simply change the function name to `atob`:

``` js
console.log(atob('aGVsbG8=')) // hello
```

Some people may be curious, like me, why the functions are named `atob` and `btoa`. I initially misunderstood that the "b" in `atob` stood for "base64", so it was converting something to base64. But in fact, it is the opposite. `atob` converts a string from base64.

According to the answer to [Why were Javascript `atob()` and `btoa()` named like that?](https://stackoverflow.com/questions/33854103/why-were-javascript-atob-and-btoa-named-like-that), "a" stands for ASCII and "b" stands for binary, not Base64. Therefore, `atob` means converting ASCII data (i.e., strings) to binary, which is to convert a base64-encoded string back to its original form.

Although in JavaScript, both `atob` and `btoa` accept strings as parameters and there is no binary involved, the explanation above makes sense if you broaden your perspective beyond JavaScript.

For example, base64 can convert any binary data to a string, which is its most valuable feature. For example, you may have used data URI, which is a way to encode images as base64 strings.

Therefore, `btoa` stands for binary to ASCII, which means encoding anything using base64. The output will be a base64-encoded string. `atob`, on the other hand, means ASCII to binary, which is to convert a base64-encoded string back to its original form.

Okay, after talking so much about base64, let's get back to the point.

Xiao Ming found out that he needed to use `atob` and `btoa` to complete the task and successfully implemented the feature on the webpage. Two months later, his supervisor asked him to implement the same feature on a server running Node.js.

Xiao Ming thought, "What's so difficult about this?" and used `btoa` as before. However, this time, a different result appeared, and an error was thrown:

> Uncaught ReferenceError: btoa is not defined

Xiao Ming was puzzled. Why could he use the same function before but not now? Does this function exist and not exist in JavaScript at the same time?

This happens because Xiao Ming did not have the concept of runtime in mind.

## What is Runtime?

JavaScript is a programming language, so things like `var`, `if else`, `for`, or `function` are all part of JavaScript. But in addition to the language itself, JavaScript needs a place to run, and this place is called the execution environment or runtime. For example, the most commonly used runtime is the "browser".

So your JavaScript code runs on the browser runtime, which provides some things for you to use, such as the DOM (document), `console.log`, `setTimeout`, `XMLHttpRequest`, or `fetch`. These are not actually part of JavaScript (or more precisely, ECMAScript).

These are provided by the browser, so we can only use them when running JavaScript on the browser. The `atob` and `btoa` used by Xiao Ming at the beginning are also not part of the ECMAScript specification, but are provided by the browser for JavaScript. This is why we suddenly can't use them when using Node.js, because Node.js runtime does not provide these two functions.

As shown in the figure below, the left is the Node.js runtime, the middle is the things of JS itself, and the right is the browser runtime, each with its own things:

![](/img/javascript-runtime/p1.png)

Therefore, you may have had a similar experience of not being able to execute the same code in Node.js. Now you know that this is because Node.js does not provide these things, such as `document` or `atob`, and you cannot use them directly in Node.js (if you can, it means you are using other libraries or polyfills).

Conversely, when you run a JavaScript program using Node.js, you can use `process` or `fs`, but you cannot do this on the browser. Different runtimes provide different things, and you need to be very clear about which runtime you are in.

## How to distinguish whether a feature is provided by the runtime or built into JS?

By following a principle, you can have a probability of about 80% to distinguish correctly, that is: "Is this feature related to the runtime itself?"

For example, the DOM and BOM APIs are closely related to the browser. When using the Node.js runtime, we don't have a document because there is no such thing as a page, and we don't have localStorage because that is something only the browser has. Therefore, things like `document` and `localStorage` are provided by the browser, not things of the JavaScript language itself.

Or like `process`, which can read a lot of information about threads, the browser cannot allow you to do this, so obviously it cannot be used on the browser, it is something exclusive to the `Node.js` runtime.

The other 20% are some exceptions that appear to be unrelated to the runtime, but are actually related. For example, `btoa` just converts to Base64, what does it have to do with the runtime? But coincidentally, it is provided by the runtime.

And `console` is also provided by the runtime, and there is a feature to note, that is, sometimes different runtimes will provide the same things. For example, `console` and `setTimeout` are available in both the browser and Node.js, but they are not part of JavaScript, but are provided by the runtime.

But although they look the same, the internal implementation is completely different, and the way they behave may also be different. For example, the `console.log` in the browser will output to the console of the devtool, while Node.js will output to your terminal.

`setTimeout` and `setInterval` are also like this, although they are available in both the browser and Node.js, the implementation behind them is completely different.

If you want to confirm whether an API is provided by the runtime, there is a simple and correct way, which is to look at the ECMAScript specification or MDN. For example, for `atob`, in the Specifications section of [MDN](https://developer.mozilla.org/en-US/docs/Web/API/atob#specifications), you can see that its source is the HTML Standard, not ECMAScript, which means it is not part of ECMAScript:

![](/img/javascript-runtime/p2.png)

In short, if you cannot find it in the ECMAScript specification, it means it is provided by the runtime.

On MDN, these are not provided natively by ECMAScript, but are provided by the browser's API, called Web API: https://developer.mozilla.org/en-US/docs/Web/API

Below are some APIs that are often misunderstood as part of JavaScript, but are actually provided by the runtime:

1. console
2. fetch
3. performance
4. URL
5. setTimeout
6. setInterval

## Learning JavaScript from Different Runtimes

When many people learn JavaScript, the first thing they encounter is the browser, and they may leave the impression that "JavaScript can only run on the browser."

In addition to the browser, JavaScript also has another runtime called [Node.js](https://nodejs.org/en/). The introduction on the official website is:

> Node.js® is a JavaScript runtime built on Chrome's V8 JavaScript engine.

Through the Node.js runtime, our JavaScript code can run independently of the browser. I highly recommend everyone to take a look at Node.js and use the APIs it provides, such as `process` or `fs`, to write some small toys.

When you are familiar with different runtimes, you will find that the runtime is not only providing more APIs, but also a limiter.

When your runtime is a browser, the functions you can perform will naturally be subject to browser restrictions. For example, you cannot "actively read" files on your computer because the browser does not allow you to do so for security reasons. You also cannot restart the computer because the browser does not allow you to do so. When performing network-related operations, you will also be subject to the restrictions of the same-origin policy and [CORS](https://blog.huli.tw/2021/02/19/cors-guide-1/), which are unique to the browser environment.

Once you switch to a different runtime, all these restrictions will be lifted. When using Node.js to execute code, you can read files, restart the computer, and there are no restrictions on the same-origin policy and CORS. You can do whatever you want, send requests to anyone you want, and the response will not be intercepted.

The reason why I recommend everyone to learn Node.js is to make everyone aware of who is imposing the restrictions when executing code. Is it the limitations of JavaScript itself or the limitations imposed by the runtime?

After realizing this, your understanding of JavaScript will be more comprehensive.

## Conclusion

When you use JavaScript, some APIs are built into the language itself, such as `JSON.parse` or `Promise`, and you can find their descriptions in the ECMAScript specification.

Some APIs are provided by the runtime, such as `atob`, `localStorage`, or `document`, which are APIs provided by the browser. Once you leave the browser runtime, you will not have these APIs available.

But this does not mean that APIs that can be used on both the browser and Node.js runtimes are built-in APIs of the language. For example, `console`, `setTimeout`, and the recently natively supported `fetch` in Node.js (https://github.com/nodejs/node/pull/41749) can be used on both the browser and Node.js, but they are all provided by the runtime.

In other words, the browser implements the APIs of `console` and `setTimeout`, implements the timer mechanism, and provides them to JavaScript for use, and Node.js also implements the same APIs and provides them to JavaScript for use. Although they look like the same function on the surface, the implementation behind them is different. This is like you can buy tuna rice balls at both Family Mart and 7-11, although they are both tuna rice balls, the suppliers behind them are actually different, and the production methods are also different.

With the concept of runtime, if you encounter a function that can be used in the browser but not in Node.js in the future, you will know why.
