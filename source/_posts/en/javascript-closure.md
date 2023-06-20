---
title: 'All Functions are Closures: Discussing Scope and Closure in JS'
date: 2018-12-08 22:10
tags: [Front-end,JavaScript]
categories:
  - JavaScript
---

# Introduction

Please forgive me for using a somewhat sensational title, because I really can't think of any other title that is better. In the end, I chose a controversial title, but it is also interesting to use such a title to stimulate discussion. Moreover, what I said is based on facts.

Before reading this article, please read the previous article: [I know you understand hoisting, but do you understand it deeply?](https://github.com/aszx87410/blog/issues/34), because the content of the article is partly related, so you must have the concept of Execution Context and Variable Object before you can absorb the content of this article.

If you are only interested in the sentence in the article title: "All Functions are Closures", you can scroll down directly, because to talk about closures, we must start with scope, so this article will not be too short according to convention, and there will be a certain degree of elaboration in the front.

Okay, let's start with scope.

<!-- more -->

# Scope

What is scope?

My favorite explanation is: "Scope is the range of life of a variable. Once it is out of this range, the variable cannot be accessed."

Let's take a simple example:

``` js
function test(){
  var a = 10
}
console.log(a) // Uncaught ReferenceError: a is not defined
```

Before ES6, the only way to create scope was through functions. Each function has its own scope, and you cannot access the variables defined inside the function outside the scope. However, in ES6, let and const were introduced, which have block scope, but that is not the focus of this article, so I will skip it for now.

In addition to this function scope, there is also a scope called global, which is actually what we often call "global" or "global variable", which can be accessed anywhere, as shown in the following example:

``` js
var I_am_global = 123
function test() {
  console.log(I_am_global) // 123
}
test()
```

From the above example, you can find an interesting thing, that is, you can access variables outside the function inside the function, but you cannot enter the function from outside. Here, I want to quote a very interesting explanation I saw before, which compares scope to a celebrity and function to a region.

Global variables are international superstars, such as Tom Cruise. Everyone knows this person wherever they go because he is so famous. The variables inside the function are like your neighbor who sings well. Everyone in the community knows his existence, but once he leaves the community (exceeds this function), no one knows who he is.

So the structure of the function layer by layer is like a region. The outermost layer is the earth, followed by the five continents, Asia, Taiwan, Taipei City, Daan District, and Daan Forest Park. People who exercise in Daan Forest Park know their friends who often jog there and also know the celebrities in Taipei City, but people living in Taipei City may not necessarily know who the district chief of Daan District is because it is beyond their scope.

The above statement can be converted into code like this:

``` js
function taiwan() {
  var taiwan_star = 'taiwan_star'
  function taipei() {
    function daan() {
      var daan_star = 'daan_star'
      console.log(taiwan_star) // taiwan_star
    }
    daan()
    console.log(daan_star) // Uncaught ReferenceError: daan_star is not defined
  }
  taipei()
}
taiwan()
```

So now you should have a better understanding of the term scope, which is the range of life of a variable. Once it exceeds that range, it cannot be accessed. The range is the function itself and its interior. Therefore, if you declare a variable inside a function, it cannot be accessed outside the function.

You cannot access the outside from the inside, but the "inside" can access the "outside":

``` js
function test() {
  var a = 100
  function inner() {
    console.log(a) // 100
  }
  inner()
}
test()
```

For the function `inner`, `a` is not its own variable, and this kind of variable that is not in its own scope and is not passed in as a parameter can be called a free variable, which can be translated as a free variable (it sounds cool).

For `inner`, `a` is a free variable.

What will be the value of `a`?

Because `a` cannot be found in the scope of `inner`, it will look for it in the scope of `test`. If it still cannot be found, it will continue to look up the scope chain until it is found. Therefore, you can find that this will form a "scope chain", inner function scope -> test function scope -> global scope, constantly looking up this chain. If it still cannot be found in the end, an error will be thrown.

By this point, you should have a basic understanding of the concept. Next, I will ask a question to disrupt and confuse your understanding:

``` js
var a = 100
function echo() {
  console.log(a) // 100 or 200?
}
  
function test() {
  var a = 200
  echo()
}
  
test()
```

Should the final log output of `a` be 100 or 200?

I know! It's 100, because the `a` in the global variable is 100...wait, but when I was in `test`, I declared a variable named `a` and set it to 200, and the `a` in `echo` may also be 200...it's so confusing.

The answer is 100. You just need to follow the principles we mentioned earlier. The "a" inside the "echo" function is the same as the global "a", and has nothing to do with the "a" inside the "test" function.

However, it is reasonable to be confused because in some programming languages, "a" will indeed be 200! The final value of "a" (or in other words, how the value of the free variable is determined) is related to how the programming language determines the "scope".

The method we introduced at the beginning is called static scope. Why is it called "static"? It means that the scope has nothing to do with where the function is "called". You can see the scope of the function by looking at the structure of the code, and it will not change.

For example, in the above example, the "a" printed out will be the global "a", even though I declared another "a" inside the "test" function and called the "echo" function. This has nothing to do with the scope. The static scope is determined when the function is "declared", not when it is "executed".

On the other hand, if the programming language uses dynamic scope, the value of "a" logged out will be 200 instead of 100. In other words, the value of "a" inside the "echo" function is dynamically determined during program execution, and you cannot determine the value of "a" just by looking at the structure of the code.

JavaScript uses static scope, so you can determine the scope by analyzing the structure of the code. By the way, one of the most difficult problems in JavaScript is "this". The principle behind it is similar to dynamic scope. The value of "this" is also dynamically determined during program execution, which is why many people cannot figure out what its value is.

The more academic term for static scope is lexical scope. To understand what "lexical" means, you must first understand a bit about how compilers work. During compilation, there are several steps where the program parses and analyzes your code, and one of these steps is called Lexical Analysis. It is to correctly analyze every word in the code.

For example, the sentence "a = 13 + 2" may be grouped into "a", "=", "13", "+", and "2" after lexical analysis. This is just a basic understanding. If you want to know more about the details of compilers, please refer to relevant books or articles, or wait until I have completed this foundation and share it with you in plain language.

The reason it is called lexical scope is that during compilation, the scope can be determined, hence the name.

That's all for the content related to scope. Let's review a few keywords:

- Scope chain
- Free variable
- Static scope (lexical scope)
- Dynamic scope

# Closure

Now let's finally get into the content related to closures. Before that, let me introduce what closures are and what characteristics they have.

Please see the following sample code:

``` js
function test() {
  var a = 10
  function inner() {
    console.log(a) // 10
  }
  inner()
}
  
test()
```

There is nothing special, just executing an internal function. But what if we don't execute "inner" directly, but return this function?

``` js
function test() {
  var a = 10
  function inner() {
    console.log(a) // 還是 10
  }
  return inner
}
  
var inner = test()
inner()
```

Something magical happened, the code still outputs 10.

What's so magical about it? The magical thing is that after a function is executed, all related resources should be released. However, even though "test" has finished executing, I can still access "a" when calling "inner"!

In other words, the variable "a" is "closed" inside the "inner" function, so as long as "inner" exists, "a" will never be at peace and can only be trapped inside.

The main reason is that I returned a function inside the function, which caused this phenomenon of something being closed even though it has been executed, and this situation is what people commonly know as a closure.

What are the benefits of closures? One of the advantages is that it can hide variables inside so that they cannot be accessed from outside. For example, I have a variable that records the balance and a function that deducts money, but I have set a limit that the maximum deduction is only 10 dollars:

``` js
var my_balance = 999
function deduct(n) {
  my_balance -= (n > 10 ? 10 : n) // 超過 10 塊只扣 10 塊
}
  
deduct(13) // 只被扣 10 塊
my_balance -= 999 // 還是被扣了 999 塊
```

Although we have written the "deduct" function to operate, the variable is still exposed outside, and anyone can directly modify it. At this time, if we use closures to rewrite it, the world will be different:

``` js
function getWallet() {
  var my_balance = 999
  return {
    deduct: function(n) {
      my_balance -= (n > 10 ? 10 : n) // 超過 10 塊只扣 10 塊
    }
  }
}
  
var wallet = getWallet()
wallet.deduct(13) // 只被扣 10 塊
my_balance -= 999 // Uncaught ReferenceError: my_balance is not defined
```

Because I hid the "balance" variable inside the function, it cannot be accessed from outside. If you want to modify it, you can only use the "deduct" function I exposed, which achieves the purpose of hiding information and ensures that the variable will not be easily modified.

But compared to the usage of this closure, I believe many people should have learned about closures from this painful experience:

``` js
var btn = document.querySelectorAll('button')
for(var i=0; i<=4; i++) {
  btn[i].addEventListener('click', function() {
    alert(i)
  })
}
```

Suppose there are five buttons on the page, and I want the first one to pop up 0 when pressed, the second one to pop up 1 when pressed, and so on. So I wrote the code above, which looks very reasonable.

Who knows when I click on a button, why the hell does every button pop up 5, and why do they all pop up the same number? Where did 5 come from?

Even I myself had a similar experience before realizing that I was not familiar with the scope and closure. Now that I have experience, I can fully understand the above code.

First of all, you might think the loop above is like this:

``` js
btn[0].addEventListener('click', function() {
  alert(0)
})
  
btn[1].addEventListener('click', function() {
  alert(1)
})
  
...
```

But it's actually like this:

``` js
btn[0].addEventListener('click', function() {
  alert(i)
})
  
btn[1].addEventListener('click', function() {
  alert(i)
})
  
...
```

If you think about it carefully, you will find that the latter is more reasonable. I just added a function to it, which will pop up i when pressed, and I didn't execute this function directly.

So when the user clicks the button, the screen will pop up i. What is the value of this i? Because the loop has already finished running when you click the button, i has long been 5 (the last round of the loop, i plus one becomes 5, and the condition i<=4 is not met, so the loop exits), and the screen pops up the number 5.

The several functions I added don't have the variable i itself, so they look for the variable i in the outer layer of the scope, and then they find the variable i in the loop above, so the i referred to by these functions is the same i.

So how to solve this problem? Add a function!

``` js
function getAlert(num) {
  return function() {
    alert(num)
  }
}
for(var i=0; i<=4; i++) {
  btn[i].addEventListener('click', getAlert(i))
}
```

Note that getAlert(i) will "return" a function that pops up i, so I generated five new functions, each with its own value to pop up.

Or if you want to be cool, write it like this:

``` js
for(var i=0; i<=4; i++) {
  (function(num) {
    btn[i].addEventListener('click', function() {
      alert(num)
    })
  })(i)
}
```

Wrap a function in an IIFE (Immediately Invoked Function Expression) and execute it immediately by passing in i, so a new function will be called immediately every time the loop runs, creating a new scope.

If you think all of the above is too cumbersome and don't want to use it, congratulations, after the introduction of block scope in ES6, you just need to simply change the var used in the loop to let:

``` js
for(let i=0; i<=4; i++) {
  btn[i].addEventListener('click', function() {
    alert(i)
  })
}
```

Because of the characteristics of let, a new scope is actually generated every time the loop runs, so the value popped up by alert will be the value you want. If you still feel a little confused, you can think of the loop like this:

``` js
{ // 塊級作用域
  let i=0
  btn[i].addEventListener('click', function() {
    alert(i)
  })
}
{ // 塊級作用域
  let i=1
  btn[i].addEventListener('click', function() {
    alert(i)
  })
}
...
```

So far, we have a preliminary understanding of closures, but we seem to have no clear definition of "what is a closure". "Closure is a function that can enclose values" sounds strange. If you go to Wikipedia, it will tell you:

> In computer science, a closure is a record storing a function together with an environment.

If you go to the English Wikipedia, you can see that it says:

> Operationally, a closure is a record storing a function together with an environment.

Okay, it still seems a bit vague, but let's stop here for the definition of closures. It's good to have a vague concept in your mind. Let's come back to deal with the scope in ECMAScript.

# Scope in ECMAScript

Before we start, if you forget the operating model we talked about before, please go back to [I know you understand hoisting, but how deep do you understand?](https://github.com/aszx87410/blog/issues/34) to review, because we will use it later.

Here I will still use ES3 with less content as an example. Note that many terms have changed after ES6, but the principles are roughly the same.

Last time we saw something related to hoisting in the section `10.1.3 Variable Instantiation`. This time we will look at the next section, which is `10.1.4 Scope Chain and Identifier Resolution`.

> Every execution context has associated with it a scope chain. A scope chain is a list of objects that are searched when evaluating an Identifier. When control enters an execution context, a scope chain is created and populated with an initial set of objects, depending on the type of code.

Each EC has its own scope chain, which is established when entering the EC.

Next, let's look at `10.2.3 Function Code` under `10.2 Entering An Execution Context`:

> The scope chain is initialised to contain the activation object followed by the objects in the scope chain stored in the [[Scope]] property of the Function object.

This paragraph describes what the scope chain contains. It states that when entering an EC, the scope chain is initialized to the activation object followed by the objects in the scope chain stored in the `[[Scope]]` property of the Function object.

In fact, the above paragraph only wants to say one thing, that is, the following will be done when entering an EC:

``` js
scope chain = activation object + [[Scope]]
```

The next thing to deal with is two questions: what is the activation object (AO), and what is `[[Scope]]`?

In `10.1.6 Activation Object`, you can find an explanation of AO:

> When control enters an execution context for function code, an object called the activation object is created and associated with the execution context.
> 
> The activation object is initialised with a property with name arguments and attributes { DontDelete }
> 
> The activation object is then used as the variable object for the purposes of variable instantiation.

Here, it is mentioned that `When control enters an execution context for function code`, which means that only when entering a "function" will this AO be generated, and then the AO will be used as the VO for variable instantiation.

So what is AO? You can directly regard it as another special type of VO, which only appears in the EC of the function. Therefore, we have VO in the global scope, and AO in the function scope, but they do the same thing, which is to put some related information in it.

What is the difference? The difference is that AO will have an `arguments` inside it. After all, it is for the function, so it must be stored, and the rest is almost the same. If you are lazy and use the terms VO and AO interchangeably, I think it is acceptable because the difference is really too subtle.

After solving the problem of AO, what is `[[Scope]]`? In `13.2 Creating Function Objects`, you can see a more detailed explanation:

> Given an optional parameter list specified by FormalParameterList, a body specified by FunctionBody, and a scope chain specified by Scope, a Function object is constructed as follows
> 
> (omitted in the middle)
> 
> 7.Set the [[Scope]] property of F to a new scope chain (10.1.4) that contains the same objects as Scope.

It means that when you create a function, you will give it a Scope, and this Scope will be set to `[[Scope]]`.

What is the Scope given when creating a function? What else can it be? Of course, it is the Scope of the current EC.

After reading these paragraphs, we can actually summarize the following process:

1. When function A is created, set `A.[[Scope]] = scope chain of current EC`
2. When entering a function A, a new EC is generated, and set `EC.scope_chain = AO + A.[[Scope]]`

To fully understand it, let's run through this whole process with the following very simple code as an example:

``` js
var v1 = 10
function test() {
  var vTest = 20
  function inner() {
    console.log(v1, vTest) //10 20
  }
  return inner
}
var inner = test()
inner()
```

## Step 1: Enter Global EC
Now enter the Global EC and initialize VO and scope chain. As mentioned earlier, `scope chain = activation object + [[Scope]]`, but since this is not a function, there is no `[[Scope]]`, and without AO, VO is used directly. In short, the final Global EC will look like this:

``` js
globalEC = {
  VO: {
   v1: undefined,
   inner: undefined,
   test: function 
  },
  scopeChain: globalEC.VO
}
```

As for the VO part, it is initialized as previously mentioned. The only additional step now is the addition of the `scopeChain` property. According to the definition, the scope chain is the globalEC's own VO/AO.

Don't forget the last step, which is to set the `[[Scope]]` of the function. Therefore, the `[[Scope]]` of the `test` function will be `globalEC.scopeChain`, which is `globalEC.VO`.

## Step 2: Execute the Code

Next, execute the code. After running `var v1 = 10`, it encounters `var inner = test()`. We are now preparing to enter the test EC. Before entering, our current information looks like this:

``` js
globalEC = {
  VO: {
   v1: 10,
   inner: undefined,
   test: function 
  },
  scopeChain: globalEC.VO
}
  
test.[[Scope]] = globalEC.scopeChain
```

## Step 3: Enter the test EC
As usual, when entering, first establish the test EC and AO, and remember that `scope chain = activation object + [[Scope]]`.

``` js
testEC = {
  AO: {
    arguments,
    vTest: undefined,
    inner: function
  },
  scopeChain: 
    [testEC.AO, test.[[Scope]]]
  = [testEC.AO, globalEC.scopeChain]
  = [testEC.AO, globalEC.VO]
}
  
globalEC = {
  VO: {
   v1: 10,
   inner: undefined,
   test: function 
  },
  scopeChain: globalEC.VO
}
  
test.[[Scope]] = globalEC.scopeChain
```

As you can see, the scope chain of the testEC is its own AO plus the previously set `[[Scope]]`. In essence, the scope chain is just the VO/AO combination of the upper-level EC!

Finally, don't forget to set the scope of `inner`, `inner.[[Scope]] = testEC.scopeChain`.

# Step 4: Execute the code in test

Actually, only `var vTest = 20` and `return inner` are executed, and after execution, it becomes like this:

``` js
testEC = {
  AO: {
    arguments,
    vTest: 20,
    inner: function
  },
  scopeChain: [testEC.AO, globalEC.VO]
}
  
globalEC = {
  VO: {
   v1: 10,
   inner: function,
   test: function 
  },
  scopeChain: globalEC.VO
}
  
inner.[[Scope]] = testEC.scopeChain = [testEC.AO, globalEC.VO]
```

Then return `inner`, and the `test` function ends. Resources should be released, but have you noticed that `inner.[[Scope]]` still remembers `testEC.AO`? Because someone still needs it, it cannot be released like this, even though the test has ended, testEC.AO still exists in memory.

# Step 5: Enter the inner EC

I won't go into detail here, just follow the same principles to initialize:

``` js
innerEC = {
  AO: {
    arguments
  },
  scopeChain:
  [innerEC.AO, inner.[[Scope]]]
= [innerEC.AO, testEC.scopeChain]
= [innerEC.AO, testEC.AO, globalEC.VO]
}
  
testEC = {
  AO: {
    arguments,
    vTest: 20,
    inner: function
  },
  scopeChain: [testEC.AO, globalEC.VO]
}
  
globalEC = {
  VO: {
   v1: 10,
   inner: function,
   test: function 
  },
  scopeChain: globalEC.VO
}
  
inner.[[Scope]] = testEC.scopeChain = [testEC.AO, globalEC.VO]
```

Have you noticed that, as I just said, the scope chain is just the VO/AO combination?

# Step 6: Execute inner

Find the variables `v1` and `vTest` in the scope chain, and since they are not found in their own AO, look up to the upper level. Find `vTest` in `testEC.AO`, but `v1` is still not found, so look up one level to `globalEC.VO`, and finally find `v1`. Successfully obtain the values of these two variables and print them out.

End.

The above process is explained in more detail, and you can open a small window next to it to see the code step by step. It is believed that it will be easier to understand. In fact, when we discussed hoisting last time, we already talked about this model, and today we just supplemented the part that was not mentioned last time, that is, the scope chain. After adding it, this model is much more complete, not only can it explain hoisting, but also why variables can still be accessed after the function is executed.

Because these variables are left in the scope chain of the innerEC, they cannot and should not be garbage collected, which is why this phenomenon occurs.

After understanding that the scope chain is just the VO/AO combination, it is easy to understand what we mean by "looking up in the scope chain", which means to look up one level to see if there is such a variable, because if there is, it must exist in the VO/AO.

Finally, one thing to note about this model is that whether or not I return the internal function (in the example above, `inner`), it does not affect the operation of this mechanism.

This means that even if my code looks like this:

``` js
var v1 = 10
function test() {
  var vTest = 20
  function inner() {
    console.log(v1, vTest) //10 20
  }
  inner() // 不回傳直接執行
}
test()
```

The resulting model is exactly the same as the previous code, and `inner` has the same scope chain and stores the VO/AO of the test and global ECs.

Have you noticed that we are stepping towards our title step by step?

# All functions are closures.

Let's take a look at the definition of closures on the wiki:

> In computer science, a closure (also lexical closure or function closure) is a function that has references to free variables. The references are to values in the lexically enclosing scope that has been closed over, i.e., the scope that was in effect when the closure was created, not when invoked. A closure—unlike a plain function—allows the function to access those captured variables through the closure's reference to them, even when the function is invoked outside their scope.

If you think that a closure must "leave the environment that created it," then the statement "all functions are closures" is obviously not true. However, if you agree that the definition of a closure is "an entity composed of a function and the related referencing environment," then it means that in JavaScript, all functions are closures.

Why? Because this is the operating mechanism of JavaScript. Every function you declare stores `[[Scope]]`, and this information contains the referenced environment.

And this statement is not something I made up. In one of the most classic series of articles explaining ECMAScript, [ECMA-262-3 in detail. Chapter 6. Closures.](http://dmitrysoshnikov.com/ecmascript/chapter-6-closures/), it says:

> Let’s make a note again, that all functions, independently from their type: anonymous, named, function expression or function declaration, because of the scope chain mechanism, are closures.
> 
> from the theoretical viewpoint: all functions, since all they save at creation variables of a parent context. Even a simple global function, referencing a global variable refers a free variable and therefore, the general scope chain mechanism is used;

So theoretically, all functions in JavaScript are closures.

> from the practical viewpoint: those functions are interesting which:

> continue to exist after their parent context is finished, e.g. inner functions returned from a parent function;
> 
> use free variables.

But if you only care about closures from a "practical" point of view, we would say that closures must use free variables and must be able to exist after the context in which they were created has ended. This is the closure we are truly concerned with.

So what exactly is a closure? It depends on your perspective. But undoubtedly, from a theoretical point of view, all functions in JavaScript are closures. If you still don't believe it, let me show you what V8 thinks.

# Exploring V8

Let's write a simple piece of code and see what it compiles to:

``` js
var a = 23
function yoyoyo(){
  
}
yoyoyo()
```

We put a 23 here to make it easier to locate this piece of code in the byte code. Only functions have names that can be identified, and it's harder to find things written in the global scope.

The result is as follows:

```
[generating bytecode for function: ]
Parameter count 6
Frame size 16
         0x3e0ed5f6a9da @    0 : 6e 00 00 02       CreateClosure [0], [0], #2
         0x3e0ed5f6a9de @    4 : 1e fa             Star r1
   10 E> 0x3e0ed5f6a9e0 @    6 : 91                StackCheck 
   70 S> 0x3e0ed5f6a9e1 @    7 : 03 17             LdaSmi [23]
         0x3e0ed5f6a9e3 @    9 : 1e fb             Star r0
   95 S> 0x3e0ed5f6a9e5 @   11 : 4f fa 01          CallUndefinedReceiver0 r1, [1]
         0x3e0ed5f6a9e8 @   14 : 04                LdaUndefined 
  107 S> 0x3e0ed5f6a9e9 @   15 : 95                Return 
  
[generating bytecode for function: yoyoyo]
Parameter count 1
Frame size 0
   88 E> 0x3e0ed5f6b022 @    0 : 91                StackCheck 
         0x3e0ed5f6b023 @    1 : 04                LdaUndefined 
   93 S> 0x3e0ed5f6b024 @    2 : 95                Return 

```

Just look at the keywords. Do you see what's happening when the function is created? It's `CreateClosure`. We're just creating a simple function and calling it, but V8 is still using the `CreateClosure` instruction.

What if we create a new function inside a function?

``` js
function yoyoyo(){
  function inner(){}
}
yoyoyo()
```

Result:

```
[generating bytecode for function: yoyoyo]
Parameter count 1
Frame size 8
         0x2c9f0836b0fa @    0 : 6e 00 00 02       CreateClosure [0], [0], #2
         0x2c9f0836b0fe @    4 : 1e fb             Star r0
   77 E> 0x2c9f0836b100 @    6 : 91                StackCheck 
         0x2c9f0836b101 @    7 : 04                LdaUndefined 
  106 S> 0x2c9f0836b102 @    8 : 95                Return 
```

It still calls `CreateClosure`. Finally, let's try the one we're familiar with, which is to return the created function:

``` js
function yoyoyo(){
  function inner(){}
  return inner
}
yoyoyo()
```

Result:

```
[generating bytecode for function: yoyoyo]
Parameter count 1
Frame size 8
         0x3f4bde3eb0fa @    0 : 6e 00 00 02       CreateClosure [0], [0], #2
         0x3f4bde3eb0fe @    4 : 1e fb             Star r0
   77 E> 0x3f4bde3eb100 @    6 : 91                StackCheck 
  116 S> 0x3f4bde3eb101 @    7 : 95                Return 
```

What's the difference? The only difference is that the former loads undefined with `LdaUndefined` before returning, while the latter does not, so it returns the created function. But the instruction for creating the function is exactly the same, and it's called `CreateClosure`.

Looking only at the compiled code may not be fair, it would be even better to see how V8 works internally.

I used to try to find it before, but V8 was too big. This time, I happened to come across this article while looking for information: [Analyze implementation of closures in V8](https://bugzilla.mozilla.org/show_bug.cgi?id=542071). Although it is a nine-year-old article, it mentions some keywords that led me to some interesting places.

The first one is [src/interpreter/interpreter-generator.cc](https://github.com/v8/v8/blob/d84e9496d23cf1dc776ae32199d81accfabaafb5/src/interpreter/interpreter-generator.cc#L2502), which records all the instructions of the byte code. For `CreateClosure`, it is described as follows:

```
// CreateClosure <index> <slot> <tenured>
//
// Creates a new closure for SharedFunctionInfo at position |index| in the
// constant pool and with the PretenureFlag <tenured>.
```

This file is very helpful for later viewing of byte code, so I want to mention it here.

The second one is [src/contexts.h](https://github.com/v8/v8/blob/ac0c19b623cdf30c42c5893379a05d555cc2722c/src/contexts.h#L392), which contains a lot of information. You can see this comment:

```
// JSFunctions are pairs (context, function code), sometimes also called
// closures. A Context object is used to represent function contexts and
// dynamically pushed 'with' contexts (or 'scopes' in ECMA-262 speak).
//
// At runtime, the contexts build a stack in parallel to the execution
// stack, with the top-most context being the current context. All contexts
// have the following slots:
//
// [ scope_info     ]  This is the scope info describing the current context. It
//                     contains the names of statically allocated context slots,
//                     and stack-allocated locals.  The names are needed for
//                     dynamic lookups in the presence of 'with' or 'eval', and
//                     for the debugger.
```

In addition to closures, which we are most interested in, it also mentions context and scope info, which are similar concepts with different names.

But the most important sentence is:

> JSFunctions are pairs (context, function code), sometimes also called closures.

Every JS function records context information, which confirms the mechanism we discussed earlier.

The third and last one is where I unexpectedly found the place where V8 handles scope, in [src/ast/scopes.cc](https://github.com/v8/v8/blob/91041c1260788b823895996b8a522d9e40b58c13/src/ast/scopes.cc#L1837). The link leads to `LookupRecursive`, which describes the process of finding variables. First, it looks for them in the scope, then it looks up, and if it still can't find them, it declares them globally.

It's been so long since I've been familiar with this process, and it's really interesting to see how V8 implements it. Although I can't understand C++ very well, fortunately, there are many comments in the article, so I can understand about 50-60% of the code just by reading the comments.

# Conclusion

There is one small thing to explain first. In this article and the previous one, I deliberately did not mention `eval` and `with` because they make the scope much more complicated, so I intentionally left them out. When I looked at the V8 code, I saw a lot of code dealing with these operations. If you are interested in these operations, you can find related articles to read.

In the process of thoroughly understanding hoisting last time, we got the concept of the operation of the most important underlying mechanism and also saw V8's byte code. This time, we supplemented the previous model to make it more complete. As long as we interpret the operation of the program according to that model, we can easily understand hoisting and closures.

This time, we also went deeper into V8 and directly saw the code related to scope and context. However, V8 is still a very large project, and I can't even finish reading a few files, let alone understand it. Therefore, I just wanted to take a fun perspective to see it.

The goal of this article is the same as the previous one. For those who are not familiar with this topic, I hope it can help you understand it. For those who are already familiar with it, I hope it can bring some new ideas. After all, I didn't see anyone directly running to V8 to find related code segments by looking left and right.

References:

1. [Talking about JS's scope from static/dynamic scope](http://creeperyang.github.io/2015/01/JavaScript-dynamic-scope-vs-static-scope/)
2. [MDN](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Closures)
3. [In-depth understanding of JavaScript closures](https://pjchender.blogspot.com/2017/05/javascript-closure.html)
4. [JavaScript Scope (1)](https://ithelp.ithome.com.tw/articles/10203387)
5. [Interpretation of JS scope](https://github.com/nightn/front-end-plan/issues/1)
6. [ECMA-262-3 in detail. Chapter 6. Closures.](http://dmitrysoshnikov.com/ecmascript/chapter-6-closures/)
7. [Grokking V8 closures for fun (and profit?)](https://mrale.ph/blog/2012/09/23/grokking-v8-closures-for-fun.html)
8. [Understanding JavaScript Closures](https://javascriptweblog.wordpress.com/2010/10/25/understanding-javascript-closures/)
9. [https://javascript.info/closure](https://javascript.info/closure)
10. [Analyze implementation of closures in V8](https://bugzilla.mozilla.org/show_bug.cgi?id=542071)

Please paste the Markdown content you want me to translate.
