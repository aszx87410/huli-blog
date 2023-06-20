---
layout: post
title: '[Javascript] Detailed Explanation of Redux Middleware'
date: 2015-09-03 15:45
catalog: true
header-img: "/img/header_img/article-bg.png"
tags: [JavaScript,Front-end,Redux,React] 
categories:
  - React
---
Previously, I wrote [an article](http://huli.logdown.com/posts/294037-javascript-redux-basic-tutorial) to briefly summarize my experience in learning Redux. I still recommend the official documentation because it is super clear.

However, when I was reading the official documentation before, I didn't fully understand the middleware part and got confused towards the end. This time, I re-read the official documentation on middleware and asynchronous operations, took notes while reading, and finally understood the implementation principle of middleware. As usual, I will share my experience.
[Official documentation (Chinese version, but this article has not been translated yet)](http://camsong.github.io/redux-in-chinese/docs/advanced/Middleware.html)

The great thing about the official documentation is that it not only teaches you how to use it, but also starts from scratch, so you know why middleware is in its current form.
<!-- more -->

#Main Content
After reading some tutorial articles, you think Redux is really great, so you start using Redux for your own product. But at this moment, you suddenly want to implement a feature: logging. You want to record every action and the changes to the store after executing the action. How to do it? Let's start with the simplest method!

##First Attempt: Most Intuitive Method
Assuming that the code for dispatching actions is originally written like this:
```javascript
store.dispatch(addTodo('Use Redux'));
```
We can directly change it to:
```javascript
let action = addTodo('Use Redux');

console.log('dispatching', action);
store.dispatch(action);
console.log('next state', store.getState());
```

##Second Attempt: Wrap it in a Function
But everyone knows that the first method cannot be done like this because there must be more than one place in the program that needs to do this. So what should we do next? Wrap it in a function.
```javascript
function dispatchAndLog(store, action) {
  console.log('dispatching', action);
  store.dispatch(action);
  console.log('next state', store.getState());
}
dispatchAndLog(store, addTodo('Use Redux'));
```
However, in this way, you need to import this function every time you need to dispatch, is there a better way?

##Third Attempt: Monkeypatching
What is `Monkeypatch`? You can Google it yourself. The idea is to replace something at runtime. Just like you can write in your chrome devtool:
```javascript
console.log = function(text){
  alert(text);
}
```
All messages that were originally displayed in the console will now be displayed using alert. How can we use it here?
```javascript
//First, save the original because it will be used later
let next = store.dispatch;

//Override the current one
store.dispatch = function dispatchAndLog(action) {
  console.log('dispatching', action);
  
  //Execute
  next(action);
  console.log('next state', store.getState());
  return;
};

//The way to call it is the same as before
store.dispatch(addTodo('Use Redux'));
```
In this way, the original code does not need to be modified at all. You just need to replace `store.dispatch` at the beginning of the program. It is easy and fun, but we soon encountered a new problem.
>If I want an error reporting mechanism now, what should I do? When dispatching an error, I want to pass the error back to the server.

Hmm... Good question. We can separate these two tasks into two functions, like this:

``` javascript
function patchStoreToAddLogging(store) {
  let next = store.dispatch;
  store.dispatch = function dispatchAndLog(action) {
    console.log('dispatching', action);
    next(action);
    console.log('next state', store.getState());
    return;
  };
}

function patchStoreToAddCrashReporting(store) {
  let next = store.dispatch;
  store.dispatch = function dispatchAndReportErrors(action) {
    try {
      next(action);
    } catch (err) {
      console.error('Caught an exception!', err);
      Raven.captureException(err, {
        extra: {
          action,
          state: store.getState()
        }
      });
      throw err;
    }
  };
}

patchStoreToAddLogging(store);
patchStoreToAddCrashReporting(store);
```

When I first read this, I was a bit confused about how this works. Won't the second function overwrite the first one? But after reading it a few times, I finally understood the essence of it, which lies in the `let next = store.dispatch;` line.

The behavior of the above code is roughly as follows:

1. Execute the first function `patchStoreToAddLogging(store);`
2. The current dispatch function (the function that actually sends the action in Redux) is saved.
3. `store.dispatch` is replaced with `dispatchAndLog`, which records and calls the original dispatch function.
4. Execute the second function `patchStoreToAddCrashReporting(store);`
5. The current dispatch function (which is now `dispatchAndLog`) is saved.
6. `store.dispatch` is replaced with `dispatchAndReportErrors`, which records and calls the original dispatch function.

Now, if we call `dispatch(..)`, here's what happens:

1. Because it was replaced earlier, `dispatchAndReportErrors` is executed.
2. `next(action)` is executed, and `next` is the original dispatch function that was saved earlier.
3. `dispatchAndLog` is executed.
4. The action is recorded, and then `next(action)` is executed, and `next` is the original dispatch function.
5. The original dispatch function is executed, and after it's done, it jumps back to the `dispatchAndLog` function.
6. It goes back to `dispatchAndLog`, prints out the changed state.
7. It goes back to `patchStoreToAddCrashReporting`, but since there are no errors, nothing happens.
8. It ends.

This way, we achieve the most important function of our middleware, which is to let the action go through layer after layer of middleware and finally reach the store. But this is still not good enough.

## Fourth attempt: Hide Monkeypatching
Previously, we directly replaced `store.dispatch`. What if we don't replace it directly, but instead return a function? What will happen?

```javascript
function logger(store) {
  let next = store.dispatch;

  // Previously:
  // store.dispatch = function dispatchAndLog(action) {

  return function dispatchAndLog(action) {
    console.log('dispatching', action);
    let result = next(action);
    console.log('next state', store.getState());
    return result;
  };
}
```

Suppose we change our `crashReporter` to this form as well. Then we can do this:

```javascript
store.dispatcher = logger(store);
store.dispatcher = crashReporter(store);
```

We're just extracting `store.dispatcher` and putting it outside the function. But the advantage of doing this is that we can do this:

```javascript
function applyMiddlewareByMonkeypatching(store, middlewares) 
  // Transform dispatch function with each middleware.
  middlewares.forEach(middleware =>
    store.dispatch = middleware(store)
  );
}
applyMiddlewareByMonkeypatching(store, [logger, crashReporter]);
```

But this is still just extracting the monkeypatching part. In the next step, we need to completely remove the monkeypatching method.

## Fifth Attempt: Removing Monkeypatching

Why do we need to override `dispatch`? One important factor is that this is the only way to continuously call the previous `dispatch`.

```javascript
function logger(store) {
  // This line is crucial to achieve chaining
  let next = store.dispatch;

  return function dispatchAndLog(action) {
    console.log('dispatching', action);
    let result = next(action);
    console.log('next state', store.getState());
    return result;
  };
}
```

Without that important line, we cannot achieve the chaining effect. However, there is another way to achieve the same result. We can receive a `next` parameter to achieve the same effect. The official documentation then quickly explains the most important part. Here, I will try to slow down the progress and explain more details, which is the concept of `currying`.

Continuing from what we just talked about, we can receive a `next` parameter, which will look like this:

```javascript
function logger(store, next) {
  return function dispatchAndLog(action) {
    console.log('dispatching', action);
    let result = next(action);
    console.log('next state', store.getState());
    return result;
  };
}
```

As you can see, it looks very similar to the previous one, except that the original `next` is now passed in as a parameter. When we use it, it becomes:

```javascript
let dispatch = store.dispatch;
dispatch = crashReporter(store, dispatch);
dispatch = logger(store, dispatch);
dispatch(addTodo('Use Redux'));

function logger(store, next) {
  return function dispatchAndLog(action) {
    console.log('dispatching', action);
    let result = next(action);
    console.log('next state', store.getState());
    return result;
  };
}

function crashReport(store, next) {
  return function dispatchAndReportErrors(action) {
    try {
      return next(action);
    } catch (err) {
      console.error('Caught an exception!', err);
      throw err;
    }
  };
}
```

The difference is that the `let next = store.dispatch;` inside the function is removed. Our middleware functions `logger` and `crashReport` are now cleaner. After changing it, we also need to change our original `applyMiddleware` to make it conform to the new format:

```javascript
function applyMiddleware(store, middlewares) {

  let dispatch = store.dispatch;
  middlewares.forEach(middleware =>
    dispatch = middleware(store,dispatch)
  );

  return Object.assign({}, store, { dispatch });
}

// The way to call it is exactly the same, except that this function now returns a store
applyMiddleware(store, [logger, crashReporter]);
```

Next, let's look at the official documentation and examples and see where they differ from what we just wrote. The first point is that we pass two parameters to `logger` and `crashReport`, but the official implementation only passes one. This is done using a technique called `currying`. What is `currying`? It is the process of breaking down a function with multiple parameters into many functions with only one parameter. You can understand it better by looking at the example:

```javascript
function max(a,b){
	return a>b?a:b;
}
max(1,5);

function maxCurrying(a){
	return function inner(b){
	  return a>b?a:b;
	}
}
maxCurrying(1)(5);
```

With this basic concept, we can also make the same changes to our `logger` function:

```javascript
// It can be compared with the original, and it is only one more layer of function wrapping
function logger(store) {
  return function wrapDispatchToAddLogging(next) {
    return function dispatchAndLog(action) {
      console.log('dispatching', action);
      let result = next(action);
      console.log('next state', store.getState());
      return result;
    };
  }
}

// ES6 syntax
const logger = store => next => action => {
  console.log('dispatching', action);
  let result = next(action);
  console.log('next state', store.getState());
  return result;
};

// Original
function logger(store, next) {
  return function dispatchAndLog(action) {
    console.log('dispatching', action);
    let result = next(action);
    console.log('next state', store.getState());
    return result;
  };
}
```

When I first looked at the official documentation, the most confusing part for me was this section. Because I rarely used this kind of function that returns a function that returns a function, I was immediately confused. So I had to find a way to reduce the number of nested functions first, and then understand `currying` before going back to understand the original code. For me, this way is easier, otherwise it would be too overwhelming.

`applyMiddleware` can be changed to this:

```javascript
function applyMiddleware(store, middlewares) {
  let dispatch = store.dispatch;
  middlewares.forEach(middleware =>
    dispatch = middleware(store)(dispatch) // the difference is here
  );
  return Object.assign({}, store, { dispatch });
}

// original
function applyMiddleware(store, middlewares) {

  let dispatch = store.dispatch;
  middlewares.forEach(middleware =>
    dispatch = middleware(store,dispatch) // the difference is here
  );

  return Object.assign({}, store, { dispatch });
}
```

In fact, at this point, it is already quite similar to the implementation of `redux` itself. In fact, the way middleware is written is the way `redux` requires it to be written. Finally, let's take a look at how to use the official provided usage:

```javascript
import { createStore, combineReducers, applyMiddleware } from 'redux';

// applyMiddleware takes createStore() and returns
// a function with a compatible API.
// Note that here, we used currying. We changed the two parameters to two functions.
// Originally, we passed in an array, but here we removed the array and just passed them in one by one.
let createStoreWithMiddleware = applyMiddleware(
  logger,
  crashReporter
)(createStore);

// Use it like you would use createStore()
let todoApp = combineReducers(reducers);

// Replace the original createStore with createStoreWithMiddleware
let store = createStoreWithMiddleware(todoApp);
```

## Summary

When I was reading the official documentation, I could understand everything until it suddenly jumped to the `currying` part. Because I was unfamiliar with this concept, I was confused. Later, I made up my mind to understand it, and after reading it again, I tried to understand what each line meant and how the process worked. After that, it became clearer.

This article is heavily based on the official example, and the code is copied directly, but with some minor changes explained here. For example, in the `applyMiddleware` of the official example, there is actually:

```javascript
middlewares = middlewares.slice();
middlewares.reverse();
```

`reverse()` is because of the order of execution, and `slice()` is to copy the array. But I don't know why it needs to be copied, maybe to avoid changing the original parameters?

In short, I hope this article can help some beginners who are confused like me. I still recommend everyone to read the official documentation. If there are any mistakes in my writing, please leave a comment or send me an email. Thank you.

Reference:
http://camsong.github.io/redux-in-chinese/docs/advanced/Middleware.html
