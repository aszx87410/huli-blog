---
title: 'A Deep Dive into Parameter Passing in JavaScript: Call by Value or Reference?'
date: 2018-06-23 22:10
tags: [Front-end,JavaScript]
categories:
  - JavaScript
---

# Introduction

Originally, I was planning to write about the differences and implementations of shallow and deep copying. However, while researching, I stumbled upon articles related to call by value and call by reference, and the more I delved into it, the more interesting it became. I thought I had understood this issue, but the more I read, the more confused I became.

There are two ways to write this article. One is to record in detail my process of researching this issue, my doubts, and how I arrived at a solution, essentially writing in chronological order. The other is to organize my findings and express them in a simpler and more understandable way.

In the past, I have mostly taken the second approach, reorganizing and summarizing my findings to write an article that is relatively easy to understand, leading readers step by step through my thought process to arrive at a solution.

However, this time I want to try the first approach, taking readers through the materials I usually read when writing articles and explaining my thought process. This should be quite interesting.

Let's go!

<!-- more -->

# Beautiful Mistakes

As mentioned earlier, my decision to research parameter passing was a beautiful mistake. I was originally planning to write about shallow and deep copying.

While researching, I came across this article: [[Javascript] 關於 JS 中的淺拷貝和深拷貝
](https://web.archive.org/web/20200220061943/http://larry850806.github.io/2016/09/20/shallow-vs-deep-copy//). After reading it, I realized that if I wanted to talk about deep copying, I would have to first explain why we need deep copying, which would require discussing the differences between objects and other primitive types.

At this point, I thought of an old question: Is JavaScript's object passed by value or by reference?

I vaguely remembered that the answer was the former, or neither, but rather a new term called pass by sharing.

To verify that my memory was correct, I continued to search and finally found [[筆記] 談談JavaScript中by reference和by value的重要觀念](https://pjchender.blogspot.com/2016/03/javascriptby-referenceby-value.html) and [重新認識 JavaScript: Day 05 JavaScript 是「傳值」或「傳址」？](https://ithelp.ithome.com.tw/articles/10191057). I remembered reading the latter and confirmed that my memory was correct.

Okay, before we continue, I need to introduce these three terms and their differences, otherwise we won't be able to proceed.

# Parameter Passing in Functions

Let's start with a simple example:

``` js
function swap(a, b) {
  var temp = a;
  a = b;
  b = temp;
}
  
var x = 10;
var y = 20;
swap(x, y);
console.log(x, y) // 10, 20
```

After executing `swap`, the values of `x` and `y` are not swapped. Why? Because what you passed in was not "the real x and y," but rather "copies of the values of x and y."

In other words, `a` and `b` are actually two new variables that store the same values as `x` and `y`, but changing `a` will not change `x` because they are two different variables.

You can refer to the beautiful animation below:

![value 1](https://user-images.githubusercontent.com/2755720/49351722-bfc86c80-f6ef-11e8-97c5-efac22512139.gif)


This method is called call by value (or pass by value), which copies the "value" when calling a function.

Up to this point, it should be quite easy to understand. Now we will slowly move on to the more complex parts. There is another method called call by reference, which means "what you passed in is the real x and y, and a and b inside the function are just aliases, changing a will change x."

Obviously, for primitive types like numbers in JavaScript, there is no call by reference, because you can never change variables outside the function through arguments inside the function.

What about objects?

``` js
function add(obj) {
  obj.number++
}
  
var o = {number: 10}
add(o)
console.log(o.number) // 11
```

What! You actually successfully changed something outside the function inside the function! Is this call by reference?

Don't be hasty. At first glance, it seems like it, but there is an operation that exposes a flaw:

``` js
function add(obj) {
  // 讓 obj 變成一個新的 object
  obj = {
    number: obj.number + 1
  }
}
  
var o = {number: 10}
add(o)
console.log(o.number) // 10
```

If it is really call by reference, then if you change the value of obj inside the function, the value of o outside will also be changed and become the new object. However, from the example above, it doesn't seem to be the case, so this is not call by reference.

Neither call by value nor call by reference, so what should we call it?

Some people call this method call by sharing, which means that we let the obj inside the function "share" the same object as o outside, so you can modify the data of the "shared object" through the obj inside.

Although it looks no different from call by reference, the biggest difference is that if you reassign obj inside the function, it means that you want this obj to point to a new object, so o outside still retains its original value.

After introducing a new term, it seems that all the problems have been solved, and the conclusion is: "In JavaScript, primitive types are call by value, and objects are call by sharing."

However, all of this is just my naive idea. One day, I saw a sentence...

# JavaScript only has call by value

At first glance, this sentence makes no sense. Didn't we just say it's call by sharing? How did it become call by value again?

But actually, this sentence should be interpreted as follows:

When you declare an object, in the underlying implementation, this object actually stores a memory location, or if you use C to explain it, the underlying of the object is a pointer.

Let's review pointers first. You can think of pointers as a type of variable, but the difference is that the value it stores is a "memory location".

![p1 2](https://user-images.githubusercontent.com/2755720/49351736-c6ef7a80-f6ef-11e8-8c60-806ac95221f5.png)

> What is the value of the variable o?

The answer to this question is the key to understanding the sentence "JavaScript only has call by value".

From a higher level, the answer will naturally be "the value of o is {number: 10}". But if you look at it from the underlying implementation, the answer will be "the value of o is 0x01".

Let's continue with the second answer. Assuming the value of o is 0x01, then when you call the function, the value passed in is actually 0x01, so the variable inside the function can operate on the same thing through this memory location.

It's just like the picture we drew before, o and obj two variables will "point to" the same place. The underlying implementation principle is to pass the memory location of o to obj, otherwise how can they point to the same place.

If you look at it from this perspective, call by sharing (passing memory location) is actually a kind of call by value, and the explanation is: it is actually passing a copy of the value, but this value is a memory location.

At first glance, it makes sense, but there is one point that I can't figure out no matter how I think:

> If you look at it from the underlying implementation, isn't call by reference also a kind of call by value?

Because from the underlying implementation, call by reference is also passing the memory location, so doesn't that mean the whole world only has call by value?

Later, I found an article with a similar idea: [Re: [問題] 請問傳參考到底是什麼?](https://www.ptt.cc/bbs/C_and_CPP/M.1245595402.A.2A1.html)

But after reading it, I still didn't get an answer, only a vague concept. I think this may be a problem of naming conventions.

With the spirit of exploring the root cause, I decided to see what ECMAScript says.

# Journey to explore the Bible

The ECMAScript spec is the Bible of JavaScript, where you can find deeper implementation details, and the content will never be wrong.

Most of the related articles I can find now are sourced from here: [ECMA-262-3 in detail. Chapter 8. Evaluation strategy.](http://dmitrysoshnikov.com/ecmascript/chapter-8-evaluation-strategy/)

I originally thought this was an excerpt from ECMA-262-3, but after reading it, I found that it was not. It was just someone's notes after reading ECMA-262-3.

However, this article is actually well written. We can directly look at the conclusion part:

> It can be either “call by value”, with specifying that the special case of call by value is meant — when the value is the address copy. From this position it is possible to say that everything in ECMAScript are passed by value.
> 
> Or, “call by sharing”, which makes this distinction from “by reference”, and “by value”. In this case it is possible to separate passing types: primitive values are passed by value and objects — by sharing.
> 
> The statement “objects are passed by reference” formally is not related to ECMAScript and is incorrect.

Unfortunately, it does not specify which part of ECMA-262 mentions these, and no article I searched for had any reference to ECMA-262.

I had to find it myself.

I downloaded `ECMA-262 edition 8` from [ecma international](https://www.ecma-international.org/publications/standards/Ecma-262.htm) and used a few keywords to search for:

1. call by reference
2. call by value
3. pass by reference
4. pass by value

The result? I found nothing. I then narrowed down the keywords and searched for `reference`, `sharing`, and so on, and found `6.2.4 The Reference Specification Type`, which seemed relevant but did not contain the most crucial part.

Searching through an 800-page document like this was exhausting, and I still had no results. I then thought, "Let me search for `arguments`," and found two seemingly relevant sections (`9.4.4 ArgumentsExoticObjects` and `9.2 ECMAScript Function Objects`), but they did not provide detailed explanations.

Since I couldn't find anything using the previous keywords, I decided to try searching for the definition of the equal sign. If we want to compare two objects, we should find something about how to compare whether two objects are the same, which should mention related terms like `reference`!

Finally, I found this section:

![ecma1](https://user-images.githubusercontent.com/2755720/49351744-cfe04c00-f6ef-11e8-8599-dd0bb4eecd95.png)

> 8. If x and y are the same Object value, return true. Otherwise, return false.

Okay, it's as good as not saying anything. After searching for an hour or two and making little progress, I decided to give up on this nearly 900-page version.

Later, I downloaded the first edition of ECMA-262, which is much shorter, with less than 200 pages. After searching for several keywords and finding no results, I decided to quickly scan the entire book.

In conclusion, I still did not find anything related to call by value/reference, but I found some interesting things. For example, the way to determine equality is written differently:

![ecma2](https://user-images.githubusercontent.com/2755720/49351745-d373d300-f6ef-11e8-9978-cc13dc959ec5.png)

> 11.9.3 The Abstract Equality Comparison Algorithm
> 
> 13.Return true if x and y refer to the same object or if they refer to objects joined to each other (see 13.1.2). Otherwise, return false.

There is a mention of something called "joined objects":

![ecma3](https://user-images.githubusercontent.com/2755720/49351752-d79ff080-f6ef-11e8-8dec-7c8395fd1988.png)

However, it is still not quite what we are looking for.

So, I gave up on the idea of finding the answer from ECMAScript.

Feeling helpless, I remembered a programming language that also had a similar problem (whether it is call by value or call by reference): Java.

# Java is always pass-by-value

I have encountered this problem before when writing Java, and it is actually exactly the same as JavaScript. When you pass a normal value, it is passed by value, but when you pass an object, it behaves like call by reference. However, when assigning a value, it does not change the outside object.

But it seems that it is a consensus that Java is always pass by value, which can be referred to in [Is Java "pass-by-reference" or "pass-by-value"?](https://stackoverflow.com/questions/40480/is-java-pass-by-reference-or-pass-by-value), [Parameter passing in Java - by reference or by value?](http://www.yoda.arachsys.com/java/passing.html), and [Java is Pass-by-Value, Dammit!](http://www.javadude.com/articles/passbyvalue.htm).

The reason is actually the same as what we said at the beginning. Let me quote a sentence from Java is Pass-by-Value, Dammit!:

> However, Objects are not passed by reference. A correct statement would be Object references are passed by value.

And a paragraph from Parameter passing in Java - by reference or by value?:

> Now that we have some definitions of terms we can return to the question. Does Java pass objects by reference or by value?

> The answer is NO! The fact is that Java has no facility whatsoever to pass an object to any function! The reason is that Java has no variables that contain objects.

> The reason there is so much confusion is people tend to blur the distinction between an object reference variable and an object instance. All object instances in Java are allocated on the heap and can only be accessed through object references. So if I have the following:

> StringBuffer g = new StringBuffer( "Hello" );
> 
> The variable g does not contain the string "Hello", it contains a reference (or pointer) to an object instance that contains the string "Hello".

The value of the variable g is not the string "Hello", but "a reference to the string Hello", so when you call a function, you pass in this reference.

> I pass in a reference, but this is not called call by reference?

It sounds super strange, but the root cause is actually "this reference is not that reference". Let me quote a paragraph from Call by value?:

In Java, Call by value refers to passing the value stored in a variable as a parameter, regardless of whether it is a primitive type or a class declaration type. Java does not allow the handling of memory addresses, so the term "reference" is used to explain the behavior of variables declared as class types. However, this "reference" is completely different from the "reference" in C++, and there is no Call by reference behavior in C++ for passing parameters by value, passing by reference, returning by value, or passing by reference.

Although what we pass in is indeed a reference, it is not the same as the "call by reference" in C++, so it cannot be called "call by reference."

This paragraph is similar to what is mentioned in "11.2. By Value Versus by Reference" in the Rhino book:

Before we leave the topic of manipulating objects and arrays by reference, we need to clear up a point of nomenclature.

The phrase "pass by reference" can have several meanings. To some readers, the phrase refers to a function invocation technique that allows a function to assign new values to its arguments and to have those modified values visible outside the function.

This is not the way the term is used in this book. Here, we mean simply that a reference to an object or array -- not the object itself -- is passed to a function. A function can use the reference to modify properties of the object or elements of the array. But if the function overwrites the reference with a reference to a new object or array, that modification is not visible outside of the function.

Readers familiar with the other meaning of this term may prefer to say that objects and arrays are passed by value, but the value that is passed is actually a reference rather than the object itself.

Now, let's review C and C++ parameter passing. In C, there is only one type: call by value.

As we mentioned earlier, this does not exchange the values of `x` and `y` because `a` and `b` only store the same values as `x` and `y`, respectively, and have no other relationship.

However, in C, there is something called a "pointer" that can store memory locations. Through pointers, we can actually change the values of external variables inside a function.

This is still called call by value. If you are still unsure why, you can refer to the following example. The difference from the previous example is that I first declare two pointers pointing to `x` and `y`:

Do you remember the definition of call by value mentioned earlier? It is to copy the value of a variable and pass it in. The same applies here. We pass in two variables `ptr_x` and `ptr_y` that store the memory locations of `x` and `y`, respectively, and when we call the function, we copy these two "values" and pass them in. Therefore, the values printed out for `a` and `b` in the function will be the same as the values stored in `ptr_x` and `ptr_y`.

In simple terms, previously when we used call by value, the "value" could be a number or a string. In the current example, the value is a "memory location," which is also a type of data.

However, some people also refer to this as call by pointer or call by address, but in principle, it is still a type of call by value.

One thing to note here is that even though `a` and `ptr_x` have the same "value," they are still different variables with different memory locations.

Now let's see how call by reference works in C++. Just add `&` to the function's argument to make it call by reference:

``` c++
#include <stdio.h>
  
// 注意到這邊多了 &，其他都跟 call by value 一模一樣
void swap(int &a, int &b) {
  
  // 印出 a 跟 b 所存的值與記憶體位置
  printf("%ld, %ld\n", a, b); // 10, 20
  printf("%ld, %ld\n", &a, &b); // 0x44, 0x40
  int temp = b;
  b = a;
  a = temp;
}
  
int main(){
  int x = 10;
  int y = 20;
  
  // 印出 x 跟 y 的記憶體位置
  printf("%ld %ld\n", &x, &y); // 0x44, 0x40
  swap(x, y); // 傳記憶體位置進去
  printf("%d %d\n", x, y); // 20, 10
}
```

Here, the memory locations of `a` and `b` are exactly the same as `x` and `y`, respectively. This means that when we operate on the variable `a` inside the function, we are actually operating on the variable `x`. They are identical, just with different names. When `a` is reassigned, the value of `x` outside the function is also changed.

After seeing the differences between pass by value and pass by reference in C and C++, my initial question, "If you look at it from the perspective of low-level implementation, isn't call by reference also a type of call by value?" has been answered.

I think the biggest difference between these two is one thing: copying.

Call by value will copy the value passed in (whether it's a number or a memory location, it will be copied). Call by reference will also have similar behavior at the "lowest level of implementation," but you won't notice it.

As in the example of call by reference above, the memory location of `x` is the same as that of `a`, and the memory location of `y` is the same as that of `b`. Therefore, you can say that they are "identical" things.

However, in the case of call by value, even if you pass a pointer, the pointer itself still has a different memory location, even though the "value inside the pointer (i.e., the memory location it points to)" is the same.

In other words, when we use call by value, we "create a new variable `a` and make it store the same value as the parameter passed in." In call by reference, we only "make `a` an alias of `x`, and both are the same variable." This is the biggest difference between the two in my opinion.

# Conclusion

We have seen the implementation of each programming language, but is there a clear definition that can distinguish between pass by value and pass by reference?

I thought about it and realized that we can judge based on their behavior. Instead of looking at the definition, it's better to distinguish them based on their behavior, as different types can achieve different behaviors. The first criterion is used to distinguish whether it is pass by value or pass by reference: "When the argument is reassigned inside the function, does the external variable change?"

In JavaScript and Java, for example, when you reassign a variable inside a function, the external variable does not change, so it belongs to pass by value.

If you want to distinguish them further, you can use the second criterion to distinguish whether this pass by value is true pass by value or a branch called pass by sharing: "Can you change the value of an external variable through an argument?" (The "value" we are referring to here is unrelated to the address or reference, purely referring to values like `{numer:1}`)

In JavaScript and Java, you can change the value of an external variable through operations like `obj.number = 10` (where `obj.number` changes from 1 to 10), so it can also be called pass by sharing.

According to the first criterion, some people may notice that if it's a pointer in C, can't it also achieve this? However, C only has call by value, so isn't there a conflict?

But in fact, in the example of pointers, the object we are reassigning is `*a` instead of `a` (meaning that we are making `*a=10` instead of `a=10`). The latter is called reassigning the argument (giving `a` a new address), while the former is "reassigning the memory location pointed to by the pointer." So according to this definition, the example of pointers is still pass by value.

Depending on the level of detail, the following statements are all correct:

1. JavaScript only has pass by value
2. Primitive types in JavaScript are pass by value, and objects are pass by sharing

# Conclusion

To be honest, after researching so much information, I found that everyone's "definition" of call by reference and call by value is not exactly the same, and there is no authoritative source to guarantee that this definition is correct (maybe there is, but I didn't find it. If you know, please tell me where it is, thank you). This has caused so much ambiguity.

Regarding the explanation of technical terms, I like to quote this article: [Technical term disputes are common](https://www.ithome.com.tw/voice/94877):

> In the world of software development, the creation of terms is often arbitrary. One of the frequently debated questions in Java is whether there is "Pass by reference" or not. Nowadays, the generally accepted answer is that there is not, Java only has Pass by value. However, some people still face confusion when the term "reference" appears frequently in Java documents.

> In essence, the definition of this term is different from the definition of "reference" in C++. Java just used the term "reference" for some reason. The point is not to clarify Pass by value, but to understand what behavior occurs when manipulating objects through parameters.

We studied from JavaScript to Java, and then from Java to C and C++, just to understand the definition of "pass by reference". However, ultimately, this misunderstanding is caused by different definitions of the term "reference".

If you understand "pass by reference" as defined in C++, then neither Java nor JavaScript will have pass by reference. But if you understand the "reference" in "pass by reference" as "reference to an object", then passing an object in JavaScript is actually passing a "reference to the object", which can be interpreted as pass by reference.

The term "reference" is just too convenient, leading to different definitions in different places, which are often similar but not exactly the same.

But don't forget, the point is not in this, but to understand what behavior occurs when manipulating parameters. You need to know that when you pass an object into JavaScript, you can change the value of the original object, but reassigning it will not affect the external object. Once you understand this, I think the rest is not that important.

This time I wrote a topic that is easy to provoke debate, but I also think it's quite interesting. If you have a different opinion on this issue, or if you think I made a mistake somewhere, please feel free to correct me. Thank you.

# References
1. [[Javascript] About shallow copy and deep copy in JS](https://web.archive.org/web/20200220061943/http://larry850806.github.io/2016/09/20/shallow-vs-deep-copy//)
2. [[Note] Talking about the important concepts of by reference and by value in JavaScript](https://pjchender.blogspot.com/2016/03/javascriptby-referenceby-value.html)
3. [Reacquaint with JavaScript: Day 05 Is JavaScript "pass by value" or "pass by reference"?](https://ithelp.ithome.com.tw/articles/10191057)
4. [Re: [Question] What is passing by reference?](https://www.ptt.cc/bbs/C_and_CPP/M.1245595402.A.2A1.html)
5. [ECMA-262-3 in detail. Chapter 8. Evaluation strategy.](http://dmitrysoshnikov.com/ecmascript/chapter-8-evaluation-strategy/)
6. [A simple introduction to JavaScript parameter passing](https://www.slideshare.net/YiTaiLin/java-script-63031051)
7. [Is JavaScript pass-by-value or pass-by-reference?](https://github.com/nodejh/nodejh.github.io/issues/32)
8. [Values vs References semantics #160](https://github.com/getify/You-Dont-Know-JS/issues/160)
10. [Parameter passing in Java - by reference or by value?](http://www.yoda.arachsys.com/java/passing.html)
11. [Is Java "pass-by-reference" or "pass-by-value"?](https://stackoverflow.com/questions/40480/is-java-pass-by-reference-or-pass-by-value)
12. [Pass by value](https://openhome.cc/Gossip/Java/PassByValue.html)
13. [Call by value?](https://openhome.cc/Gossip/JavaEssence/CallByValue.html)
14. [The classic problem in Java: pass by value or pass by reference](https://blog.csdn.net/jiangnan2014/article/details/22944075)
15. [Java is Pass-by-Value, Dammit!](http://www.javadude.com/articles/passbyvalue.htm)
16. [11.2. By Value Versus by Reference](https://docstore.mik.ua/orelly/webprog/jscript/ch11_02.htm)

