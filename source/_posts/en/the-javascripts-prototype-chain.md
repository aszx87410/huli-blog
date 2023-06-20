---
title: 'Understanding JavaScript Prototype Chain'
date: 2017-08-27 22:10
catalog: true
tags: [Front-end,JavaScript]
categories:
  - JavaScript
---
## Introduction

To be honest, the prototype chain in JavaScript has always been a topic that I am afraid of. The reason is simple, it is really difficult to understand. Just a bunch of terms and complex relationships can drive you crazy, such as `prototype`, `__proto__`, `constructor`, `Object.prototype`, `Function.prototype`, `new`, etc.

However, this is indeed a very important part of JavaScript and a must-have question for interviews. Even if you don't understand it now, you will eventually have to understand it someday, otherwise you will never be able to improve your technical skills. 

There are many articles about the prototype chain that you can find on the internet, and each one has a different way of understanding it. Some of them directly use a lot of technical terms, which can scare you to death. It wasn't until recently that I read a few articles that I thought had a better perspective, that I truly understood the prototype chain.

So, let's take this opportunity to learn more about the prototype chain in JavaScript! This article is suitable for those who have a basic understanding of JavaScript but are not very clear about it. If there are any mistakes in the article, please feel free to point them out in the comments. Thank you.

<!-- more -->

## Class in JavaScript

To understand the prototype chain, you can start with these two great articles:

1. [Designing Ideas of Inheritance Mechanism in JavaScript](http://www.ruanyifeng.com/blog/2011/06/designing_ideas_of_inheritance_mechanism_in_javascript.html)
2. [Explaining JavaScript Prototype Chain from Its Design Intention](https://www.jianshu.com/p/a97863b59ef7)

These two articles explain why the mechanism of JavaScript was designed in this way. I think starting from this perspective will be a better start. (It is strongly recommended to read these two articles before continuing, which will help you better understand what the prototype chain is.)

First of all, unlike Java or other object-oriented programming languages, JavaScript does not have a class (ES6's class is just syntactic sugar). However, even without a class, it can still design a similar mechanism to achieve almost the same functionality.

In Java, if you want to create an instance from a class, you can write:

``` java
Point p = new Point();
```

So JavaScript uses this syntax and has the keyword `new`. But since JavaScript doesn't have a class, what should come after `new`?

At this point, it thought that every class calls the constructor when it is initialized, right? That is, the constructor function. So in JavaScript, just follow the constructor function!

So, the following code is easy to understand:

``` js
// constructor
function Person(name, age) {
  this.name = name;
  this.age = age;
}
  
var nick = new Person('nick', 18);
var peter = new Person('peter', 18);
```

As mentioned above, `Person` is a constructor function that can be used to create an instance with the `new` keyword.

If you only look at the declaration of `nick` below (`var nick = new Person('nick', 18);`), doesn't the syntax look 87% similar to when you were writing Java? In addition, you can also add some methods to `Person`.

``` js
function Person(name, age) {
  this.name = name;
  this.age = age;
  this.log = function () {
    console.log(this.name + ', age:' + this.age);
  }
}
  
var nick = new Person('nick', 18);
nick.log(); // nick, age:18
  
var peter = new Person('peter', 20);
peter.log(); // peter, age:20
```

However, there is still a small problem with this. The `name` and `age` properties are obviously different for each instance. But the `log` method is actually shared among all instances because they are doing the same thing.

In the current situation, although the `log` function of `nick` and `peter` are doing the same thing, they actually occupy two different spaces, meaning that they are two different functions.

``` js
function Person(name, age) {
  this.name = name;
  this.age = age;
  this.log = function () {
    console.log(this.name + ', age:' + this.age);
  }
}
  
var nick = new Person('nick', 18);
var peter = new Person('peter', 20);
  
console.log(nick.log === peter.log) // false
```

So what can we do? We can extract this function and turn it into a method that all `Person`s can share. Speaking of which, you should have heard of something called `prototype`. Just assign the `log` function to `Person.prototype`, and all instances of `Person` can share this method.

``` js
function Person(name, age) {
  this.name = name;
  this.age = age;
}
  
Person.prototype.log = function () {
  console.log(this.name + ', age:' + this.age);
}
  
var nick = new Person('nick', 18);
var peter = new Person('peter', 20);
  
console.log(nick.log === peter.log) // true
  
// The function still works the same as before
nick.log(); // nick, age:18
peter.log(); // peter, age:20
```

Some people directly add some functions to `Array.prototype` to make it easier for themselves to do some operations, and the principle is the same. However, in general, it is not recommended to directly modify objects that do not belong to you.

``` js
Array.prototype.last = function () {
    return this[this.length - 1];
};
  
console.log([1,2,3].last()) // 3
```

Finally, let's summarize for everyone. The above paragraph is actually mainly to review some basics of JavaScript for everyone.

You have a function called `Person`, which can be used as a constructor. You can use `var obj = new Person()` to create an instance of `Person`, and you can add properties or methods that you want all instances to share on `Person.prototype`.

## Exploring the Principle

I don't know if you are curious about one thing. For example, in the example of `var nick = new Person('nick', 18);`, when I call `nick.log()`, how does JavaScript find this function?

Because the `nick` instance itself does not have the `log` function. But according to the mechanism of JavaScript, `nick` is an instance of `Person`, so if it cannot be found in `nick` itself, it will try to find it from `Person.prototype`.

However, how does JavaScript know to look for the `log` function in `Person.prototype`? So it must be that `nick` and `Person.prototype` are connected in some way, so it knows where to look for the `log` function.

And the way of this connection is `__proto__`.
(Note: A better way is actually to use `Object.getPrototypeOf()`, but here for convenience, we still use the more common `__proto__`. For more detailed explanations, please refer to: [MDN: Object.prototype.__proto__](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Object/proto))

``` js
function Person(name, age) {
  this.name = name;
  this.age = age;
}
  
Person.prototype.log = function () {
  console.log(this.name + ', age:' + this.age);
}
  
var nick = new Person('nick', 18);
  
console.log(nick.__proto__ === Person.prototype) // true
```

nick's `__proto__` points to `Person.prototype`, so when JavaScript finds that nick does not have the `log` method, it will try to find `Person.prototype` through `__proto__` and see if `Person.prototype` has the `log` method.

What if `Person.prototype` still doesn't have it? Then, according to this rule, it will look for the `log` method in `Person.prototype.__proto__`, and so on, until it finds something whose `__proto__` is null. This means that this is the top level.

The chain that is constantly linked together through `__proto__` is called the prototype chain. Through this prototype chain, you can achieve similar inheritance functionality and call your parent's method.

You may have some feelings about the following code:

``` js
function Person(name, age) {
  this.name = name;
  this.age = age;
}
  
Person.prototype.log = function () {
  console.log(this.name + ', age:' + this.age);
}
  
var nick = new Person('nick', 18);
  
// As mentioned earlier, nick.__proto__ will point to Person.prototype
console.log(nick.__proto__ === Person.prototype) // true
  
// Who will Person.prototype.__proto__ point to? It will point to Object.prototype
console.log(Person.prototype.__proto__ === Object.prototype) // true
  
// Who will Object.prototype.__proto__ point to? It will point to null, which is the top of the prototype chain
console.log(Object.prototype.__proto__) // null
```

If you want to know if a property exists on an instance or in its prototype chain, you can use the `hasOwnProperty` method:

``` js
function Person(name, age) {
  this.name = name;
  this.age = age;
}
  
Person.prototype.log = function () {
  console.log(this.name + ', age:' + this.age);
}
  
var nick = new Person('nick', 18);
console.log(nick.hasOwnProperty('log')); // false
console.log(nick.__proto__.hasOwnProperty('log')); // true
```

With `hasOwnProperty`, we can simulate the process of finding upwards:

``` js
function Person(name, age) {
  this.name = name;
  this.age = age;
}
  
Person.prototype.log = function () {
  console.log(this.name + ', age:' + this.age);
}
  
var nick = new Person('nick', 18);
  
function call(obj, methodName) {
  var realMethodOwner = obj;
  
  // Keep looking up until null or the person who really owns this method is found
  while(realMethodOwner && !realMethodOwner.hasOwnProperty(methodName)) {
    realMethodOwner = realMethodOwner.__proto__;
  }
  
  // Throw an error if not found, otherwise execute this method
  if (!realMethodOwner) {
    throw 'method not found.';
  } else {
    realMethodOwner[methodName].apply(obj);
  }
}
  
call(nick, 'log'); // nick, age:18
call(nick, 'not_exist'); // Uncaught method not found.

By this point, you should have a deeper understanding of the prototype chain.

Let me ask you a question, what is `Person.__proto__`?

``` js
function Person(name, age) {
  this.name = name;
  this.age = age;
}
  
Person.prototype.log = function () {
  console.log(this.name + ', age:' + this.age);
}
  
var nick = new Person('nick', 18);
  
console.log(Person.__proto__ === Function.prototype); // true
console.log(Function.prototype.__proto__ === Object.prototype) // true
console.log(Object.prototype.__proto__); //null
```

Since `Person` is actually an instance of `Function`, `Person.__proto__` is of course `Function.prototype`!

## instanceof

As the name suggests, `A instanceof B` is used to determine whether A is an instance of B. For example:

``` js
function Person(name, age) {
  this.name = name;
  this.age = age;
}
  
Person.prototype.log = function () {
  console.log(this.name + ', age:' + this.age);
}
  
var nick = new Person('nick', 18);
  
console.log(nick instanceof Person); // true
console.log(nick instanceof Object); // true
console.log(nick instanceof Array); // false
```

From the example, it can be seen that as long as B's prototype can be found in A's prototype chain, true will be returned. After understanding the principle, we can also simulate what `instanceof` is doing:

``` js
function Person(name, age) {
  this.name = name;
  this.age = age;
}
  
Person.prototype.log = function () {
  console.log(this.name + ', age:' + this.age);
}
  
var nick = new Person('nick', 18);
  
function instanceOf(A, B) {
  
  // Already found
  if (!A) return false;
  
  // If not found, continue searching up the chain
  return A.__proto__ === B.prototype ? true : instanceOf(A.__proto__, B);
}
  
console.log(instanceOf(nick, Person)); // true
console.log(instanceOf(nick, Object)); // true
console.log(instanceOf(nick, Array)); // false
```

And `instanceof` has an interesting phenomenon, which is:

``` js
// These two are each other's instance
console.log(Function instanceof Object); // true
console.log(Object instanceof Function); // true
  
// Function's __proto__ will point to Function.prototype
// And Function.prototype's __proto__ will point to Object.prototype
console.log(Function.__proto__ === Function.prototype); // true
console.log(Function.__proto__.__proto__ === Object.prototype); //true
  
// Object's __proto__ will point to Function.prototype
console.log(Object.__proto__ === Function.prototype); // true
```

This thing will make the problem more complicated, so I won't mention it here. If you want to know, you can refer to the following two articles:

1. [Understanding JS Objects and Prototype Chains from __proto__ and prototype](https://github.com/creeperyang/blog/issues/9)
2. [Understanding JavaScript's Prototype Chain and Inheritance](https://blog.oyanglul.us/javascript/understand-prototype.html)

## constructor

By the way, each prototype has a property called `constructor`, for example, `Person.prototype.constructor`, and this property will point to the constructor function. What is the constructor of `Person.prototype`? Of course, it is `Person`.

``` js
function Person(name, age) {
  this.name = name;
  this.age = age;
}
  
Person.prototype.log = function () {
  console.log(this.name + ', age:' + this.age);
}
  
var nick = new Person('nick', 18);
  
// This is to let everyone know that we are actually looking up the prototype chain here
console.log(nick.constructor === Person); // true
console.log(nick.hasOwnProperty('constructor')); // false
  
// Person's constructor is Person
console.log(Person.prototype.constructor === Person); // true
console.log(Person.prototype.hasOwnProperty('constructor')); // true
```

So actually there is nothing special about `constructor`, `A.prototype.constructor === A`, you can use values like `Function`, `Person`, `Object`, etc. for A.

There is an interesting thing, you can execute a piece of code in this way: `[].slice.constructor('alert(1)')()`. The principle is actually to replace the `Function` of `Function('alert(1)')()` with `[].slice.constructor`.

## new

With the concept of prototype chain, it is not difficult to understand what `new` does behind the scenes.

Assuming there is a line of code: `var nick = new Person('nick');`, then it has the following things to do:

1. Create a new object, let's call it O
2. Point O's `__proto__` to Person's prototype to inherit the prototype chain
3. Call the constructor function Person with O as the context
4. Return O

We can write a piece of code to simulate this situation:

``` js
function Person(name, age) {
  this.name = name;
  this.age = age;
}
  
Person.prototype.log = function () {
  console.log(this.name + ', age:' + this.age);
}
  
function newObj(Constructor, arguments) {
  var o = new Object();
  
  // Let o inherit the prototype chain
  o.__proto__ = Constructor.prototype;
  
  // Call the constructor function
  Constructor.apply(o, arguments);
  
  // Return the created object
  return o;
}
  
var nick = newObj(Person, ['nick', 18]);
nick.log(); // nick, age:18
```

Further reading: [JS Object Mechanism Deep Dive - new Operator](http://www.cnblogs.com/aaronjs/archive/2012/07/04/2575570.html)

## Summary

Today, not only do we understand what the prototype chain is, but we also wrote some simple programs to simulate JavaScript's process of looking up the prototype chain. By implementing these mechanisms ourselves, we should have a better understanding of the prototype chain.

In the JavaScript programming language, it is through the mechanism of the prototype chain that the relationship between parent and child is linked. When you cannot find something in A, you can go to A's parent (i.e. `A.__proto__`) to find it, and if you still can't find it, you can go up further. The end of the prototype chain is `Object.prototype`, and beyond that is `null`.

When writing this article, I referred to many sources, which I have included below. Some articles come with beautiful pictures, but I think starting with pictures can be a bit confusing because you don't know how they are related to each other.

After reading this article, I suggest you take a look at the reference materials below and review your own understanding.

## Reference Materials

1. [JavaScript深入之从原型到原型链](https://github.com/mqyqingfeng/Blog/blob/master/JavaScript%E6%B7%B1%E5%85%A5%E4%B9%8B%E4%BB%8E%E5%8E%9F%E5%9E%8B%E5%88%B0%E5%8E%9F%E5%9E%8B%E9%93%BE.md)
2. [JS原型链图解教程](https://www.talkingcoder.com/article/6360227501704156372)
3. [理解JavaScript的原型链和继承](https://blog.oyanglul.us/javascript/understand-prototype.html)
4. [从__proto__和prototype来深入理解JS对象和原型链](https://github.com/creeperyang/blog/issues/9)
5. [Javascript 原型链](http://zencode.in/2.Javascript%E5%8E%9F%E5%9E%8B%E9%93%BE.html)
6. [彻底理解JavaScript原型](http://www.imooc.com/article/2088)
