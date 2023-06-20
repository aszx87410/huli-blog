---
title: "Understanding JavaScript's Number One Headache: this"
date: 2019-02-23 22:10
tags: [Front-end,JavaScript,]
categories:
  - JavaScript
---

# Introduction

In JavaScript, there is a topic that is very difficult for beginners and even experienced developers to fully understand: "What is this?". As a front-end engineer who uses JavaScript as a tool for a living, I have been struggling with this issue for a long time.

I originally thought that I would never write an article about this.

There are two reasons for this. First, there are already a lot of articles explaining this topic, and each one is written very well. After reading the [What's THIS in JavaScript ?](https://kuro.tw/posts/2017/10/12/What-is-THIS-in-JavaScript-%E4%B8%8A/) series, I felt that the explanation was very complete. If I am not confident that I can explain it more clearly or from a different perspective, it seems unnecessary to write another article. The second reason is that if you want to "completely" understand this, the cost may be much higher than you think.

<!-- more -->

Here, "completely" means that you can explain why the value of this is like this in any situation. Let me give you an example:

``` js
var value = 1;
  
var foo = {
  value: 2,
  bar: function () {
    return this.value;
  }
}
  
//範例1
console.log(foo.bar());
//範例2
console.log((foo.bar)());
//範例3
console.log((foo.bar = foo.bar)());
//範例4
console.log((false || foo.bar)());
//範例5
console.log((foo.bar, foo.bar)());
```

Can you answer it? If not, it means that you don't "completely" understand this. The reason why the cost of completely understanding this is very high is because "completely understanding this" means "memorizing the ECAMScript specification". The value of this is not something we imagine out of thin air. In fact, there is a complete definition behind it, which is the so-called ECMAScript specification. You must first understand this specification before you can fully understand the object referred to by this in each situation.

If you really want to completely understand this, I recommend this article: [JavaScript深入之从ECMAScript规范解读this](https://github.com/mqyqingfeng/Blog/issues/7). The example above is taken from this article. If you want to see the answer and understand why, you can read this article.

Since I mentioned so many reasons why I shouldn't write about this earlier, why did I still jump in and write about it?

Because after reading so many articles and absorbing a lot of essence, I found that if there is a good entry point, this may not be so difficult to understand. With the method I teach in this article, you will not completely understand this. You may answer the five examples above incorrectly, but you can still solve the basic questions.

This is also the origin of the title: "Not completely complete, but guaranteed to be easy to understand". The purpose of this article is to provide a different perspective on this, starting from why there is this, and then using a set of rules to explain the value of this, at least so that you no longer misunderstand this and know what this is in some common situations.

# To talk about this, we must start with object-oriented programming

(If you have no idea about object-oriented programming in JavaScript, you can first complete the relevant basics and read this article: [It's time to understand JavaScript's prototype chain](https://github.com/aszx87410/blog/issues/18))

If you have written other programming languages, you know that this is never a difficult thing. It represents the instance itself in object-oriented programming.

Let me give you an example:

``` js
class Car {
  setName(name) {
    this.name = name
  }
  
  getName() {
    return this.name
  }
}
  
const myCar = new Car()
myCar.setName('hello')
console.log(myCar.getName()) // hello
```

In the above example, we declare a class `Car` and write two methods, `setName` and `getName`, using `this.name` to access the properties of this instance.

Why write like this? Because this is the only way, where else do you want to store the property `name`? There is no other place for you to store it. So the role of this is obvious here, and it refers to the instance itself.

In the above example, `myCar.setName('hello')`, so this will be `myCar`. In the world of object-oriented programming, the role of this is so simple.

Or in other words, I think:

> Once you leave object-oriented programming, this doesn't really matter.

Assuming that this can only be used in a class, there should be no problem, right? Have you seen anyone who writes Java or C++ complaining that this is difficult to understand? No, because the role of this is very simple.

So what is the problem? The problem is that in JavaScript, you can access this anywhere. So the this in JavaScript is different from the one used in other programming languages, which is why this is difficult to understand.

Although the definition of this is different, I think it is essentially similar. The first step to understanding this is to tell yourself: "Once you leave the object, you don't need to pay much attention to the value of this, because it doesn't make much sense."

# Not much meaning of this

``` js
function hello(){
  console.log(this)
}
  
hello()
```

What is the value of `this`?

As we mentioned earlier, in this case, I will tell you that `this` has no meaning, and you should not think that `this` will point to the `hello` function. There is no such thing.

Just remember what I said earlier: "When it is detached from the object, the value of `this` has no meaning."

In this meaningless situation, the value of `this` in the browser will be `window`, in node.js it will be `global`, and in strict mode, the value of `this` will be `undefined`.

This rule should be easy to remember. Let me summarize it for you:

1. In strict mode, it is always `undefined`.
2. In non-strict mode, it is `window` in the browser.
3. In non-strict mode, it is `global` in node.js.

This is what you see in other articles as "default binding", but I don't intend to use any proprietary terms to talk about `this` in this article. I think that not using these terms will not hinder your understanding, and may even help you understand better. I'm not saying that proprietary terms are not important, but that you can learn the concepts first and then come back to supplement the proprietary terms.

Once detached from the object, the value of `this` has no meaning, and in the case of no meaning, there will be a default value, which is also easy to remember. In strict mode, it is `undefined`, and in non-strict mode, it is the global object.

# Changing the value of this

Although `this` may have a default value, we can change it through some methods. There are three ways to change it.

The first two are very similar and are called `call` and `apply`. Both of these are functions that can call a function. Let me give you an example:

``` js
'use strict';
function hello(a, b){
  console.log(this, a, b)
}
  
hello(1, 2) // undefined 1 2
hello.call(undefined, 1, 2) // undefined 1 2
hello.apply(undefined, [1, 2]) // undefined 1 2
```

We have a function called `hello`, which logs the value of `this` and two parameters. When we call `hello(1, 2)`, because it is in strict mode, `this` is `undefined`, and `a` and `b` are 1 and 2.

When we call `hello.call(undefined, 1, 2)`, we ignore the first parameter. You can see that it is actually the same as `hello(1, 2)`.

The difference with `apply` is that the parameters passed in are an array. So these three ways of calling a function are equivalent and exactly the same. In addition to directly calling the function, you can also use `call` or `apply` to call it, and the difference is in the way the parameters are passed.

The difference between `call` and `apply` is that one is the same as calling a function normally, and the other is wrapped in an array.

What is the first parameter we just ignored?

You may have guessed that it is the value of `this`!

``` js
'use strict';
function hello(a, b){
  console.log(this, a, b)
}
  
hello.call('yo', 1, 2) // yo 1 2
hello.apply('hihihi', [1, 2]) // hihihi 1 2
```

It's that simple. Whatever you pass as the first parameter, the value of `this` inside will be that. Even if there is already a `this`, it will still be overridden by this method:

``` js
class Car {
  hello() {
    console.log(this)
  }
}
  
const myCar = new Car()
myCar.hello() // myCar instance
myCar.hello.call('yaaaa') // yaaaa
```

The value of `this` should have been the `myCar` instance, but it was overridden by the parameter we passed in when using `call`.

In addition to the above two methods, there is one last way to change the value of `this`: `bind`.

``` js
'use strict';
function hello() {
  console.log(this)
}
  
const myHello = hello.bind('my')
myHello() // my
```

`bind` will return a new function. Here we bind the `hello` function with `my`, so when we call `myHello()`, it will output `my`.

These are the three methods that can change the value of `this`. You may wonder what will happen if we use `call` and `bind` at the same time:

``` js
'use strict';
function hello() {
  console.log(this)
}
  
const myHello = hello.bind('my')
myHello.call('call') // my
```

The answer is that it will not change. Once it is bound with `bind`, the value will not change.

One thing to note here is that in non-strict mode, if you pass a primitive as the parameter to `call`, `apply`, or `bind`, it will be converted to an object. For example:

``` js
function hello() {
  console.log(this)
}
  
hello.call(123) // [Number: 123]
const myHello = hello.bind('my')
myHello() // [String: 'my']
```

Let's summarize:

1. `this` basically has no meaning outside of the object, and if forced to output, it will give a default value.
2. `this` can be changed using `call`, `apply`, and `bind`.

# this in objects

At the beginning, we demonstrated `this` in object-oriented classes, but in JavaScript, there is another way to create objects:

``` js
const obj = {
  value: 1,
  hello: function() {
    console.log(this.value)
  }
}
  
obj.hello() // 1
```

This is different from the object-oriented example at the beginning. This example directly creates an object without using a class, so you won't see the keyword `new`.

Before we continue, remember one thing:

> The value of `this` has nothing to do with where the code is located in the scope, but only with "how you call it".



This mechanism is exactly the opposite of the scope. If you are not sure what I am talking about, you can read this article first: [All functions are closures: talking about scope and closure in JS](https://github.com/aszx87410/blog/issues/35).

Let's review the scope with a simple example:

``` js
var a = 10
function test(){
  console.log(a)
}
  
const obj = {
  a: 'ojb',
  hello: function() {
    test() // 10
  },
  hello2: function() {
    var a = 200
    test() // 10
  }
}
  
test() // 10
obj.hello()
obj.hello2()
```

No matter where I am or how I call the `test` function, the `a` it prints will always be the `a` of the global variable because that's how the scope works. `test` cannot find `a` in its own scope, so it looks up one level, which is the global scope. This has nothing to do with where you call `test`. The scope of the `test` function is determined when it is "defined".

However, `this` is completely different. The value of `this` will vary depending on how you call it. Do you remember `call`, `apply`, and `bind` that we just talked about? This is one of the examples. You can call a function in different ways to make the value of `this` different.

So you need to be very clear that these are two completely different operating modes, one is static (scope), and the other is dynamic (this). To see the scope, look at where the function is in the code; to see `this`, look at how the function is called.

Let's take the most common example:

``` js
const obj = {
  value: 1,
  hello: function() {
    console.log(this.value)
  }
}
  
obj.hello() // 1
const hey = obj.hello
hey() // undefined
```

It's obviously the same function, why is `this.value` 1 the first time it's called and undefined the second time?

Remember what I just said: "To see `this`, look at how the function is called."

Before we continue, let me teach you the most important trick I learned from [What is `this` in JavaScript?](https://zhuanlan.zhihu.com/p/23804247), which is a very convenient method.

In fact, we can convert all function calls into the form of `call` to see. For example, for the example above, it would be like this:

``` js
const obj = {
  value: 1,
  hello: function() {
    console.log(this.value)
  }
}
  
obj.hello() // 1
obj.hello.call(obj) // 轉成 call
const hey = obj.hello
hey() // undefined
hey.call() // 轉成 call
```

The rule is that whatever you are before calling the function, you put it at the end. So `obj.hello()` becomes `obj.hello.call(obj)`, and `hey()` has nothing in front of it, so it becomes `hey.call()`.

After converting to this form, do you remember that the first parameter of `call` is `this`? So you can immediately know what the value of `this` is!

Let's take a more complicated example:

``` js
const obj = {
  value: 1,
  hello: function() {
    console.log(this.value)
  },
  inner: {
    value: 2,
    hello: function() {
      console.log(this.value)
    }
  }
}
  
const obj2 = obj.inner
const hello = obj.inner.hello
obj.inner.hello()
obj2.hello()
hello()
```

You can think about what values each of the three functions will print.

Now I'm going to reveal the answer. Just convert it to the form we just talked about:

``` js
obj.inner.hello() // obj.inner.hello.call(obj.inner) => 2
obj2.hello() // obj2.hello.call(obj2) => 2
hello() // hello.call() => undefined
```

I want to explain the last `hello` function in particular because nothing is passed in, so it is bound by default and is `window` in non-strict mode, so it logs `window.value`, which is undefined.

As long as you convert the function call into the form of `call`, it is easy to see what the value of `this` is.

This is also what I have been saying: "To see `this`, look at how the function is called", and if you want to see how it is called, just convert it to the form of `call`.

By now, you should be able to solve 90% of the problems related to `this`. Let's try it out (for readability, there are no blank lines to avoid errors, so please scroll down to see the code, and the answer will be below):

``` js
function hello() {
  console.log(this)
}
  
var a = { value: 1, hello }
var b = { value: 2, hello }
hello()
a.hello()
b.hello.apply(a)
```

Just follow what we said before and convert it to the form of `call`:

``` js
hello() // hello.call() => window（瀏覽器非嚴格模式）
a.hello() // a.hello.call(a) => a
b.hello.apply(a) => 直接用 apply，所以就是 a
```

Here's a different question, so be careful (assuming it's running in a browser, non-strict mode):

``` js
var x = 10
var obj = {
  x: 20,
  fn: function() {
    var test = function() {
      console.log(this.x)
    }
    test()
  }
}
  
obj.fn()
```

If you get this question wrong, it must be because you forgot our most important sentence:

> To see `this`, look at how the function is called.

How do we call `test`? `test()`, so it's `test.call()` which is the default binding, and the value of `this` will be `window`, so `this.x` will be 10 because a global variable `x = 10` is declared on the first line.

To avoid forgetting what we talked about earlier, let's review:

1. `this` outside of an object basically has no meaning.
2. Meaningless `this` will be given a default value based on strict mode and the environment.
3. The default value under strict mode is undefined, and under non-strict mode in a browser, the default value is window.
4. `this` can be changed using `call`, `apply`, and `bind`.
5. To see `this`, look at how the function is called.
6. You can think of `a.b.c.hello()` as `a.b.c.hello.call(a.b.c)`, and so on, to easily find the value of `this`.

# Non-conformist Arrow Functions

The part about `this` should have ended above, but the arrow functions introduced in ES6 have a slightly different way of working. They don't have their own `this`, so "the `this` at the place where it is declared is what its `this` is." Okay, I know this sounds super confusing, let's look at an example:

``` js
const obj = {
  x: 1,
  hello: function(){
    // 這邊印出來的 this 是什麼，test 的 this 就是什麼
    // 就是我說的：
    // 在宣告它的地方的 this 是什麼，test 的 this 就是什麼
    console.log(this)     
    const test = () => {
      console.log(this.x)
    }
    test()
  }
}
  
obj.hello() // 1
const hello = obj.hello
hello() // undefined
```

In the `hello` function on line 5, we declare the `test` arrow function, so the `this` of `hello` is what the `this` of `test` is.

So when we call `obj.hello()`, the `this` of `test` will be `obj`; when we call `hello()`, the `this` of `test` will be the global object. This rule is actually the same as before, the only difference is that the `this` of arrow functions is not determined by themselves, but by the `this` at the place where they are declared.

If you want to see more complex examples, you can refer to this article: [Ironman Competition: Arrow Functions](https://wcc723.github.io/javascript/2017/12/21/javascript-es6-arrow-function/)

# Practical Application: React

If you've written React, you'll know that there are some concepts that today's tutorial can be useful for. For example, we must bind some methods in the constructor, have you ever wondered why?

Let's first see what happens if we don't bind:

``` js
class App extends React.Component {
  onClick() {
    console.log(this, 'click')
  }
  render() {
    return <button onClick={this.onClick}>click</button>
  }
}
```

The value logged at the end will be `undefined`. Why? This detail depends on the React source code, only React knows how the `onClick` function we passed down is actually called.

So why bind? To ensure that we always get the instance itself in `onClick`.

``` js
class App extends React.Component {
  constructor() {
    super()
   
    // 所以當你把 this.onClick 傳下去時，就已經綁定好了 this
    // 而這邊的 this 就是這個 component
    this.onClick = this.onClick.bind(this)
  }
  onClick() {
    console.log(this, 'click')
  }
  render() {
    return <button onClick={this.onClick}>click</button>
  }
}
```

There is another way to use arrow functions:

``` js
class App extends React.Component {
  render() {
    return <button onClick={() => {
      console.log(this)
    }}>click</button>
  }
}
```

Why can arrow functions also be used? Because as we mentioned earlier, "the `this` at the place where it is declared is what its `this` is," so the `this` logged here will be the `this` of the `render` function, and the `this` of `render` is the component itself.

If you've forgotten a bit, you can scroll to the top of the article, because we've already mentioned these things at the beginning.

# Summary

I've read at least a dozen or twenty articles on explaining `this`, the more common ones are about explaining different binding methods and when to use which binding. But I haven't mentioned these in this article because I don't think they affect understanding (but it's best to supplement related terms later).

I've been confused before, and `this` has confused me a lot. Recently, because of teaching, I had to understand `this`, and I really understand a lot more than before. From my experience, I think one of the reasons why `this` is complicated is that "you can use `this` outside of objects," so I repeatedly emphasized that I think `this` outside of objects is meaningless.

The time when I really understood `this` was when I saw [What is the value of `this`?](https://zhuanlan.zhihu.com/p/23804247), which was really enlightening. Changing the general function call to the form of using `call` is an easy-to-understand and easy-to-remember method, and it can be applied in 90% of scenarios.

Finally, I emphasize again that this article has omissions. The examples at the beginning cannot be explained with the knowledge learned in this article. You really have to look at ECMAScript. I also didn't mention the `this` of browser events, but this part is relatively simple. I only hope that this article can give beginners who have been stuck in `this` for a long time some new ideas, and after reading this article, they can think about the value of `this` and its existence from different perspectives.

After writing this article, I've explained almost all the questions about JavaScript that are very common but I didn't understand before. Interested friends can refer to other topics:

1. [It's time to understand JavaScript's prototype chain](https://github.com/aszx87410/blog/issues/18)
2. [In-depth discussion of parameter passing in JavaScript: call by value or reference?](https://github.com/aszx87410/blog/issues/30)
3. [I know you understand hoisting, but do you understand it deeply enough?](https://github.com/aszx87410/blog/issues/34)
4. [All functions are closures: talking about scope and closure in JS](https://github.com/aszx87410/blog/issues/35)

Reference:

1. [JavaScript Deep Dive: Understanding `this` from the ECMAScript Specification](https://github.com/mqyqingfeng/Blog/issues/7)
2. [What is the value of `this` in JavaScript? Explained clearly](https://zhuanlan.zhihu.com/p/23804247)
3. [What's `this` in JavaScript?](https://kuro.tw/posts/2017/10/12/What-is-THIS-in-JavaScript-%E4%B8%8A/)
4. [JS `this`](https://github.com/nightn/front-end-plan/blob/master/js/js-this.md)
