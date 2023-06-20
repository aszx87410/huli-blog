---
title: 'The Most Beginner-Friendly RxJS Tutorial'
date: 2017-12-08 22:07
tags:
	- Front-end
categories:
	- Front-end
---

# Introduction

I have been interested in RxJS for quite some time. I first learned about it through [redux-observable](https://redux-observable.js.org/), a middleware for Redux that Netflix uses to solve complex asynchronous problems. At that time, I hadn't even figured out `redux-saga`, and I didn't expect another new thing to come out.

Half a year ago, I spent some time searching for information on the internet, trying to understand the whole thing. However, for me, many of the tutorials were either too fast-paced or too detailed, making it difficult for beginners to follow.

This time, I had the opportunity to try to introduce `redux-observable` into a new project at work. As someone who advocates for its adoption, I must have a certain understanding of this thing. With this idea in mind, I spent some time last week studying the relevant resources again and gradually came up with a method of "I think I can explain RxJS more clearly" and share it with you here.

Before we begin, I want to give a big shoutout to last year's iT 邦幫忙鐵人賽 Web group champion: [30 Days to Master RxJS](https://ithelp.ithome.com.tw/users/20103367/ironman/1199). This series of articles is very comprehensive, and you can feel that the author has put a lot of effort into it. If you are interested in more applications after reading this article, you can read the entire series of articles.

Okay, let's get started!

<!-- more -->

# Forget About RxJS for Now

Yes, you read that right.

The first thing you need to learn about RxJS is to forget about it completely.

Forget that it exists, completely forget about it. Let me talk about a few other things first, and I'll remind you when we need to talk about RxJS.

Before we talk about the protagonist, let's do something interesting!

# Programming Basic Ability Test

Let's start with a simple warm-up exercise. The question is:

> There is an array with three types of data: numbers, strings composed of a~z, and strings composed of numbers. Please multiply each number and string composed of numbers by two and add them up.
> Example input: [1, 5, 9, 3, 'hi', 'tb', 456, '11', 'yoyoyo']

After reading the question, you should say, "What's so difficult about this?" and write the following code within a minute:

``` js
const source = [1, 5, 9, 3, 'hi', 'tb', 456, '11', 'yoyoyo'];
let total = 0;
  
for (let i = 0; i < source.length; i++) {
  let num = parseInt(source[i], 10);
  if (!isNaN(num)) {
    total += num * 2;
  }
}
```

I believe everyone can write the above code very intuitively, but if you are a fan of functional programming, you may use another way of thinking to solve the problem:

``` js
const source = [1, 5, 9, 3, 'hi', 'tb', 456, '11', 'yoyoyo'];
  
let total = source
  .map(x => parseInt(x, 10))
  .filter(x => !isNaN(x))
  .map(x => x * 2)
  .reduce((total, value) => total + value )
```

The first example is called `Imperative`, and the second example, which uses an array with a bunch of functions, is called `Declarative`. If you look up the definitions, you should see the following explanations:

> Imperative commands the machine to do things (how), so no matter what you want (what), it will be implemented according to your command; Declarative tells the machine what you want (what) and lets the machine figure out how to do it (how).

Okay, did you understand what the above is talking about?

I didn't.

So let's look at another example. In fact, you have been using Declarative all the time, but you just didn't know it. That is SQL:

``` sql
SELECT * from dogs INNER JOIN owners WHERE dogs.owner_id = owners.id
```

This sentence means: I want all the data of the dogs plus the data of the owners.

I only said "I want," so how do I get this data? I don't know, and I don't need to know. Just let the underlying SQL decide how to operate. 

If I want to do this data myself, in JavaScript, I have to write it like this (code taken from [Comparison of Declarative Programming and Imperative Programming](http://www.vaikan.com/imperative-vs-declarative/)):

``` js
//dogs = [{name: 'Fido', owner_id: 1}, {...}, ... ]
//owners = [{id: 1, name: 'Bob'}, {...}, ...]
  
var dogsWithOwners = []
var dog, owner
  
for(var di=0; di < dogs.length; di++) {
  dog = dogs[di]
  for(var oi=0; oi < owners.length; oi++) {
    owner = owners[oi]
    if (owner && dog.owner_id == owner.id) {
      dogsWithOwners.push({
        dog: dog,
        owner: owner
      })
    }
  }
}
```

You should be able to roughly experience the difference between the two. The latter requires you to decide step by step what to do, while the former just tells you: "I want this kind of data."

Next, let's focus back on the exercise of multiplying numbers by two and adding them. For me, the biggest difference is that the latter example using an array with a function, and its core concept is:

> Transform the original data into the information you want.

This is super important because in the initial example, we parsed, checked, and added the numbers ourselves step by step to get the total sum. In contrast, the latter example transformed the original data (array) through a series of transformations (map, filter, reduce) to get the answer we wanted.

If we draw it as a picture, it should look like this (please forgive me for being lazy and leaving out the part where we multiply by two, but the meaning is not affected):

![map](https://user-images.githubusercontent.com/2755720/49350819-7a09a500-f6eb-11e8-9f05-6d1303b93f60.png)

Transforming the original data through a series of transformations to get the answer you want is the biggest difference in the latter. Once you have this basic knowledge, RxJS won't seem too strange.

# Reactive Programming

When it comes to RxJS, we always talk about the term Reactive. So what is Reactive? From the literal meaning of the English word, it means "reaction, reactive", which means you need to react to something.

So Reactive is actually saying: "When something happens, I can react to it."

Let's take a well-known example:

``` js
window.addEventListener('click', function(){
  console.log('click!');
})
```

We added an event listener to the window, so we can listen to this event and print out a log every time the user clicks. In other words, this is: "When the window is clicked, I can react to it."

# Entering RxJS

If you go to the [ReactiveX](http://reactivex.io/) website, you will find that it has a clear definition of ReactiveX:

> ReactiveX is a combination of the best ideas from
the Observer pattern, the Iterator pattern, and functional programming.

The first Observer pattern is like an event listener, where we can react to something when it happens; the second Iterator pattern we skip for now, as I think it doesn't affect understanding for the time being; the third is like the initial example, where we can transform an array multiple times to get the data we want.

In Reactive Programming, the two most important things are called Observable and Observer. Actually, the most confusing thing for me at first was that my English was not good, and I didn't know who was observing and who was being observed.

Translate them into Chinese, Observable is "可被观察的" (observable), and Observer is the so-called "观察者" (observer).

What does this mean? Just like the example above, when something observable happens, the observer can react to it.

Let me give you an example directly:

``` js
Rx.Observable.fromEvent(window, 'click')
  .subscribe(e => {
    console.log('click~');
  })
```

The above code is exactly the same as what we did when we added an event listener to window, except that here we use the method provided by RxJS called `fromEvent` to convert an event into an Observable, and finally add subscribe.

Writing like this means that I have subscribed to this Observable, and whenever anything happens, the function I passed in will be executed.

So what exactly is an Observable?

An Observable is an observable object that can be anything (for example, the click event of the window in the above example). When there is new data (such as a new click event), you can receive the information of this new data and react to it.

Compared with the cold term Observable, I prefer another term, stream. In fact, each Observable is a data stream, but what is a data stream? Just imagine an array that will continue to add elements. When a new event occurs, it is pushed in. If you like a more professional term, you can call it a "series of data events on a time sequence" (taken from Reactive Programming Introduction and Tutorial (Using RxJS)).

Or I'll give another example. Another interpretation of stream is the so-called "streaming video", which means that as you continue to play, new segments will be downloaded continuously. At this time, you should have a picture in your mind, like a flowing stream, constantly flowing new things, and this thing is called a stream.

# I understand the data stream, what's next?

As mentioned above, we can convert anything into an Observable and turn it into a data stream, but isn't this the same as addEventListener? What's special?

Yes, it is really special.

I hope you haven't forgotten the little exercise we just did, which is to transform an array into the data we want through a series of transformations. I just said that you can think of Observable as an "array that will continue to add elements". What does this mean?

It means that we can also make a series of transformations on Observable! We can also use those functions used on arrays!

``` js
Rx.Observable.fromEvent(window, 'click')
  .map(e => e.target)
  .subscribe(value => {
    console.log('click: ', value)
  })
```

We convert the click event into the element clicked through map, so when we finally subscribe, the value received will be what we clicked on.

Next, let's look at a slightly more advanced example:

``` js
Rx.Observable.fromEvent(window, 'click')
  .map(e => 1)
  .scan((total, now) => total + now)
  .subscribe(value => {
    document.querySelector('#counter').innerText = value;
  })
```

First, we convert each click event into 1 through `map` (or you can also write it as `.mapTo(1)`), so a number 1 is sent out every time you click. `scan` is actually the `reduce` we used on the array at the beginning, you can think of it as just changing the name. After adding up through `scan`, it is passed to the subscriber and displayed on the page.

With just a few simple lines, a counter that calculates the number of clicks is completed.

You can use a simple gif to represent the above example:

![click_stream](https://user-images.githubusercontent.com/2755720/49350844-9ad1fa80-f6eb-11e8-9e14-861fb107e774.gif)

But Observable is not just that. Next, we will enter its most powerful place.

# Powerful Combination Techniques

What happens when you merge two arrays? For example, `[1, 2, 3]` and `[4, 5, 6]`?

It depends on what you mean by "merge". If you mean concatenation, then it's `[1, 2, 3, 4, 5, 6]`. If you mean addition, then it's `[5, 7, 9]`.

So what happens when you merge two Observables?

The difference between Observables and arrays is that Observables have an additional dimension: time.

Observables are "a series of data events over time", as I mentioned earlier, and can be thought of as an array that constantly receives new data.

Let's take a look at a great image that clearly explains what happens when two Observables are merged:

![merge 1](https://user-images.githubusercontent.com/2755720/49350845-9e658180-f6eb-11e8-871f-92b229fefdd5.png)

(Taken from: http://rxmarbles.com/#merge)

The top image represents an Observable, with each circle representing a piece of data. The bottom image is the same. When these two are merged, they become the bottom image, which should be fairly easy to understand, like merging two timelines.

Let's take a look at an example that demonstrates the power of merging. We have two buttons, +1 and -1, and a text display showing the current number:

![counter_adv](https://user-images.githubusercontent.com/2755720/49350864-b806c900-f6eb-11e8-8718-dce100ca1604.gif)

How do we achieve this functionality? The basic idea is to first map each +1 click event to the number 1 using `mapTo`, and call it Observable_plus1. Then create an Observable_minus1 that maps each -1 click event to the number -1.

After merging these two Observables, we can use `scan` to add them up, which gives us the number we should display!

``` js
Rx.Observable.fromEvent(document.querySelector('input[name=plus]'), 'click')
  .mapTo(1)
  .merge(
    Rx.Observable.fromEvent(document.querySelector('input[name=minus]'), 'click')
      .mapTo(-1)
  )
  .scan((total, now) => total + now)
  .subscribe(value => {
    document.querySelector('#counter').innerText = value;
  })
```

If you still don't understand, you can refer to the beautiful example below, which demonstrates how these two Observables are merged (`O` represents a click event, and `+1` and `-1` are the results after `mapTo`):

![plus](https://user-images.githubusercontent.com/2755720/49350866-bccb7d00-f6eb-11e8-8aff-eaca7ace9137.gif)

Let's compare what the code would look like if we didn't use Observables:

``` js
var total = 0;
document.querySelector('input[name=plus]').addEventListener('click', () => {
  total++;
  document.querySelector('#counter').innerText = total;
})
  
document.querySelector('input[name=minus]').addEventListener('click', () => {
  total--;
  document.querySelector('#counter').innerText = total;
})
```

Do you notice the huge difference between the two? As I mentioned earlier, they are two completely different ways of thinking, so the difficulty of Reactive Programming is not in understanding or syntax (you should have some concept of both by now), but in switching to a completely new way of thinking.

In the above example, we tell the computer: "When you press the plus button, add one to a variable and change the text; when you press the minus button, subtract one and also change the text", and we can achieve the functionality of the counter.

In the Reactive way, we treat pressing the plus button as a data stream, treat pressing the minus button as another data stream, and then transform and merge these two streams using various functions, so that the final stream is the result we want (the counter).

You should now be able to understand what I said at the beginning: "Transforming the original data through a series of conversions to get the answer you want" is the biggest feature of Reactive Programming.

# Combination of combinations

Let's take a more complex example, which is to implement a very simple drawing function on canvas, which is to draw when the mouse is pressed and stop when it is released.

![draw](https://user-images.githubusercontent.com/2755720/49350868-c0f79a80-f6eb-11e8-9716-a0c4d114c61f.gif)

To implement this function is very simple. Canvas provides the `lineTo(x, y)` method. As long as you continuously call this method when the mouse moves, you can continuously draw graphics. But one thing to note is that when you press the mouse, you should first call `moveTo(x, y)` to move the drawing point to the specified position. Why?

Assuming that we first draw a picture in the upper left corner and the second time we press the mouse is in the lower right corner, if we do not move first with `moveTo` but directly use `lineTo`, an extra line will be drawn from the upper left corner to the lower right corner. The difference between `moveTo` and `lineTo` is that the former only moves, and the latter connects with the last point to form a line.

![draw2](https://user-images.githubusercontent.com/2755720/49350873-c3f28b00-f6eb-11e8-8376-c87a1d261680.gif)

``` js
var canvas = document.getElementById('canvas');
var ctx = canvas.getContext('2d');
ctx.beginPath(); // Start drawing

function draw(e){
  ctx.lineTo(e.clientX,e.clientY); // Move to the position of the mouse
  ctx.stroke(); // Draw
}

// Only detect mousemove events after pressing the mouse
canvas.addEventListener('mousedown', function(e){
  ctx.moveTo(e.clientX, e.clientY); // Each time you press, you must first move the drawing point there, otherwise it will be affected by the last drawn position
  canvas.addEventListener('mousemove', draw);
})

// Stop detecting when you release the mouse
canvas.addEventListener('mouseup', function(e){
  canvas.removeEventListener('mousemove', draw);
})
```

So how to implement this function in RxJS?

First of all, intuitively, you should add the `mousedown` event, right! At least there is a beginning.

``` js
Rx.Observable.fromEvent(canvas, 'mousedown')
  .subscribe(e => {
    console.log('mousedown');
  })
```

But what should happen after the mouse is pressed? At this time, you should start listening to `mousemove`, so we write it like this, using `mapTo` to convert each `mousedown` event into a `mousemove` Observable:

``` js
Rx.Observable.fromEvent(canvas, 'mousedown')
  .mapTo(
    Rx.Observable.fromEvent(canvas, 'mousemove')
  )
  .subscribe(value => {
    console.log('value: ', value);
  })
```

Then you look at the console, you will find that every time I click, the console will print `FromEventObservable {_isScalar: false, sourceObj: canvas#canvas, eventName: "mousemove", selector: undefined, options: undefined}`

If you think about it carefully, you will find that it is quite reasonable, because I use `mapTo` to convert each mouse click event into a mousemove Observable, so what you get after subscribing is this Observable. If drawn as a graph, it looks like this:

![flat](https://user-images.githubusercontent.com/2755720/49350879-c8b73f00-f6eb-11e8-852d-14e96c9d9fed.png)


Alright, so what should we do? What I actually want is not Observable itself, but the things inside this Observable! Currently, the situation is that there is an Observable inside another Observable, with two layers. However, I just want it to be one layer. What should I do?

Here's a trick to simplify Observable:

> Whenever you have a problem, just think of Array!

As I mentioned earlier, Observable can be seen as an advanced version of an array with a time dimension. Therefore, any method that an array has, Observable usually has it too.

For example, an array may look like this: `[1, [2, 2.5], 3, [4, 5]]`, with two layers, and the second layer is also an array.

If you want to make it one layer, what should you do? Flatten it!

If you've used lodash or other similar libraries, you should have heard of the method `_.flatten`, which can flatten this kind of array into `[1, 2, 2.5, 3, 4, 5]`.

If you search for the keyword "flat" in the Rx documentation, you will find a method called [FlatMap](http://reactivex.io/documentation/operators/flatmap.html), which basically maps first and then automatically flattens it for you.

Therefore, we can change the code to this:

``` js
Rx.Observable.fromEvent(canvas, 'mousedown')
  .flatMap(e => Rx.Observable.fromEvent(canvas, 'mousemove'))            
  .subscribe(e => {
    console.log(e);
  })
```

When you click, you will find that a lot of logs will be printed out as you move the mouse, which means we succeeded.

If we draw a diagram, it will look like this (for convenience, I have changed `flatMap` to `map` and `flatten` into two steps in the picture):

![flat2](https://user-images.githubusercontent.com/2755720/49350882-ce148980-f6eb-11e8-8722-5a9ce5e2a939.png)

What's next? Next, we want to stop it when the mouse is released. How do we do that? RxJS has a method called `takeUntil`, which means taking until... happens, and the parameter passed in must be an Observable.

For example, if you write `.takeUntil(window, 'click')`, it means that if any click event of `window` occurs, this Observable will immediately terminate and will not send any more data.

Applied to the drawing example, we just need to change the parameter passed to `takeUntil` to mouse release! Let's also complete the `subscribe` and drawing function together!

``` js
Rx.Observable.fromEvent(canvas, 'mousedown')
  .flatMap(e => Rx.Observable.fromEvent(canvas, 'mousemove'))
  .takeUntil(Rx.Observable.fromEvent(canvas, 'mouseup'))         
  .subscribe(e => {
    draw(e);
  })
```

After changing it, let's experiment immediately! After clicking the mouse, the drawing starts smoothly, and it stops when the mouse is released. Perfect!

Huh, but why doesn't it respond when I click the second time? We have created an Observable that can only successfully draw one picture.

Why? Let's take a look at the diagram of `takeUntil` (taken from: http://rxmarbles.com/#takeUntil)

![takeuntil](https://user-images.githubusercontent.com/2755720/49350900-e5537700-f6eb-11e8-9a25-f53bc4a892ee.png)

In our case, as long as the `mouseup` event occurs, the "entire Observable" will stop, so only the first time can draw successfully. But what we want is not like this. What we want is only to stop when `mousemove` stops, not the entire thing.

Therefore, we should put `takeUntil` after `mousemove`, that is:

``` js
Rx.Observable.fromEvent(canvas, 'mousedown')
  .flatMap(e => Rx.Observable.fromEvent(canvas, 'mousemove')
      .takeUntil(Rx.Observable.fromEvent(canvas, 'mouseup'))  
  )
  .subscribe(e => {
    draw(e);
  })
```

If you follow the rules below, the `mousemove` Observable inside will stop sending events when the mouse is released, and our outermost Observable listens for mouse clicks and continues to listen. 

At this point, it's almost done, but there's a small bug to fix. We didn't use `moveTo` to move when `mousedown` occurred, causing the problem of connecting what was drawn last time with what was drawn this time.

What to do? There is a method called `do`, which is designed for this situation. It is used when you want to do something but don't want to affect the data flow. It's like being able to subscribe to different stages, subscribing once when `mousedown` occurs and subscribing again when you want to draw.

``` js
Rx.Observable.fromEvent(canvas, 'mousedown')
  .do(e => {
    ctx.moveTo(e.clientX, e.clientY)
  })
  .flatMap(e => Rx.Observable.fromEvent(canvas, 'mousemove')
      .takeUntil(Rx.Observable.fromEvent(canvas, 'mouseup'))  
  )
  .subscribe(e => {
    draw(e);
  })
```

At this point, we have successfully completed the drawing function.

If you want to try to see if you understand, you can try implementing the function of dragging and moving objects, which is similar to detecting mouse events and reacting.

# Take a break and get ready for the second half

The goal of the first half is to help you understand what Rx is and master a few basic concepts:

1. A data stream can be transformed into another data stream through a series of transformations.
2. These transformations are basically similar to those of arrays, such as `map`, `filter`, `flatten`, etc.
3. You can merge multiple Observables, and you can flatten two-dimensional Observables.

The focus of the second half is on practical applications, focusing on one of the most suitable scenarios for RxJS: APIs.

Earlier, we mentioned that DOM object events can be turned into data streams, but in addition to this, Promise can also be turned into data streams. The concept is actually very simple. When the Promise is resolved, a data is sent, and when it is rejected, it is terminated.

Let's take a look at a simple example. Every time you click a button, a request is sent.

``` js
function sendRequest () {
  return fetch('https://jsonplaceholder.typicode.com/posts/1').then(res => res.json())
}
  
Rx.Observable.fromEvent(document.querySelector('input[name=send]'), 'click')
  .flatMap(e => Rx.Observable.fromPromise(sendRequest()))
  .subscribe(value => {
    console.log(value)
  })
```

The reason for using `flatMap` here is the same as the drawing example just now. We need to convert the original data stream into a new data stream when the button is pressed. If only `map` is used, it will become a two-dimensional Observable, so it must be flattened with `flatten`.

You can try changing `flatMap` to `map`. The value you finally subscribe to will be a bunch of Observables instead of the data you want.

After knowing how to use Rx to handle APIs, you can do a classic example: AutoComplete.

When I was doing this example, I referred to a large part of [30 Days of RxJS (19): Practical Example - Simple Auto Complete Implementation](https://ithelp.ithome.com.tw/articles/10188457), [Reactive Programming Introduction and Tutorial (Using RxJS as an Example)](http://blog.techbridge.cc/2016/05/28/reactive-programming-intro-by-rxjs/), and [Building Streaming Applications - RxJS Detailed Explanation](http://www.alloyteam.com/2016/12/learn-rxjs/). Thanks again to these three articles.

![auto](https://user-images.githubusercontent.com/2755720/49350905-eb495800-f6eb-11e8-9ed8-3f0a1ce31d73.gif)

In order to let everyone understand the difference between Reactive Programming and the traditional way, let's first use the old method to implement this Auto Complete feature!

Let's start by writing the two bottom-level functions that are responsible for fetching data and rendering the suggestion list. We will use the Wikipedia API as an example:

``` js
function searchWikipedia (term) {
    return $.ajax({
        url: 'http://en.wikipedia.org/w/api.php',
        dataType: 'jsonp',
        data: {
            action: 'opensearch',
            format: 'json',
            search: term
        }
    }).promise();
}
  
function renderList (list) {
  $('.auto-complete__list').empty();
  $('.auto-complete__list').append(list.map(item => '<li>' + item + '</li>'))
}
```

One thing to note here is that the data returned by Wikipedia will be an array in the following format:

```
[Your input keyword, List of keywords, Introduction of each keyword, Link of each keyword]
  
// Example:
[
  "dd",
  ["Dd", "DDR3 SDRAM", "DD tank"],
  ["", "Double data rate type three SDRAM (DDR3 SDRAM)", "DD or Duplex Drive tanks"],
  [https://en.wikipedia.org/wiki/Dd", "https://en.wikipedia.org/wiki/DDR3_SDRAM", "...omitted"]
]
```

In our simple demo, we only need to take the keyword list with index 1. The `renderList` function takes an array and converts the contents of the array into `li` to display.

With these two basic functions, we can easily complete the Auto Complete feature:

``` js
document.querySelector('.auto-complete input').addEventListener('input', (e) => {
  searchWikipedia(e.target.value).then((data) => {
    renderList(data[1])
  })
})
```

The code should be easy to understand. Every time you enter something, call the API and feed the returned data to `renderList` for rendering.

The basic functionality is completed. Let's do some optimization, because this implementation actually has some problems.

The first problem is that now every time you type a letter, a request will be sent, but this is actually a bit wasteful, because the user may quickly enter: `java` to find related information, he doesn't care about `j`, `ja`, `jav` these three requests.

How to do it? We just rewrite it to send a request only if there is no new input within 250ms, which can avoid this kind of waste.

This technique is called `debounce`, and it is also very simple to implement, using `setTimeout` and `clearTimeout`.

``` js
var timer = null;
document.querySelector('.auto-complete input').addEventListener('input', (e) => {
  if (timer) {
    clearTimeout(timer);
  }
  timer = setTimeout(() => {
    searchWikipedia(e.target.value).then((data) => {
      renderList(data[1])
    })
  }, 250)
})
```

After the input event is triggered, we don't do anything directly, but set a timer that will be triggered after 250ms. If the input is triggered again within 250ms, we clear the previous timer and set a new one.

In this way, it can be ensured that if the user continuously enters text within a short period of time, the corresponding request will not be sent, but will wait until 250ms after the last letter is typed before sending the request.

After solving the first problem, there is another potential issue that needs to be addressed.

Assuming I type `a`, then delete it and type `b`, the first request will return the result for `a`, and the second request will return the result for `b`. Let's say there is a problem with the server, and the response for the second request arrives before the first one (maybe the search result for `b` is cached but not for `a`). In this case, the content for `b` will be displayed first, and when the response for the first request arrives, the content for `a` will be displayed.

However, this causes a problem with the UI. I clearly typed `b`, so why is the auto-complete suggesting keywords that start with `a`?

Therefore, we need to perform a check to see if the returned data matches the data we are currently inputting before rendering:

``` js
var timer = null;
document.querySelector('.auto-complete input').addEventListener('input', (e) => {
  if (timer) {
    clearTimeout(timer);
  }
  timer = setTimeout(() => {
    searchWikipedia(e.target.value).then((data) => {
      if (data[0] === document.querySelector('.auto-complete input').value) {
        renderList(data[1])
      }
    })
  }, 250)
})
```

At this point, we should have all the necessary functionality.

Next, let's try implementing it using RxJS!

First, let's start with a simple version that doesn't include debounce or the API order issue. We listen for the input event, convert it to a request, and then flatten it using `flatMap`. It's actually similar to the process above:

``` js
Rx.Observable
  .fromEvent(document.querySelector('.auto-complete input'), 'input')
  .map(e => e.target.value)
  .flatMap(value => {
    return Rx.Observable.from(searchWikipedia(value)).map(res => res[1])
  })
  .subscribe(value => {
    renderList(value);
  })
```

Here, we use two `map` functions, one to convert `e` to `e.target.value`, and the other to convert the returned result to `res[1]`, because we only need the list of keywords, and nothing else.

So how do we implement the `debounce` functionality?

RxJS has already implemented it for you, so all you have to do is add `.debounceTime(250)`, it's that simple.

``` js
Rx.Observable
  .fromEvent(document.querySelector('.auto-complete input'), 'input')
  .debounceTime(250)
  .map(e => e.target.value)
  .flatMap(value => {
    return Rx.Observable.from(searchWikipedia(value)).map(res => res[1])
  })
  .subscribe(value => {
    renderList(value);
  })
```

There is one final issue to address, which is the order of the requests we mentioned earlier.

Observable has a different solution, let me explain it to you.

In addition to `flatMap`, there is another way called `switchMap`, which differs in how it flattens the Observable. The former we introduced earlier, which flattens each two-dimensional Observable and "executes each one".

The difference with `switchMap` is that it will always only handle the last Observable. In our example, if the first request has not returned yet when the second request is sent, our Observable will only handle the second request, not the first.

The first request will still be sent and data will still be received, but after receiving the data, it will not be emitted to the Observable, meaning that no one is listening to this data anymore.

You can see a simple diagram below. With `flatMap`, the data for each resolved promise will be sent to our Observable:

```

![flatmap](https://user-images.githubusercontent.com/2755720/49350911-f2706600-f6eb-11e8-990a-d7bb0cbf48f4.png)

On the other hand, `switchMap` only handles the last one:

![switchmap](https://user-images.githubusercontent.com/2755720/49350913-f603ed00-f6eb-11e8-86a7-62fdc83c9345.png)

Therefore, we only need to change `flatMap` to `switchMap`, so we can always focus on the last request sent, without worrying about the order in which requests are returned, because the previous requests are no longer related to this Observable.

``` js
Rx.Observable
  .fromEvent(document.querySelector('.auto-complete input'), 'input')
  .debounceTime(250)
  .map(e => e.target.value)
  .switchMap(value => {
    return Rx.Observable.from(searchWikipedia(value)).map(res => res[1])
  })
  .subscribe(value => {
    renderList(value);
  })
```

Up to this point, it is exactly the same as the function we implemented earlier.

But actually, there is still room for improvement. Let's make a small enhancement. Currently, when I enter `abc`, the relevant keywords for `abc` will appear. Then, I delete all of `abc`, making the input blank, and an error will be returned from the API: `The "search" parameter must be set.`

Therefore, when the input is empty, we can return an empty array without sending a request. This can be done using `Rx.Observable.of([])`, which creates an Observable that sends an empty array:

``` js
Rx.Observable
  .fromEvent(document.querySelector('.auto-complete input'), 'input')
  .debounceTime(250)
  .map(e => e.target.value)
  .switchMap(value => {
    return value.length < 1 ? Rx.Observable.of([]) : Rx.Observable.from(searchWikipedia(value)).map(res => res[1])
  })
  .subscribe(value => {
    renderList(value);
  })
```

There is also a feature where clicking on a keyword in the list sets the text to the keyword. I won't demonstrate it here, but it involves creating another Observable to listen for click events, setting the text when clicked, and clearing the keyword list.

Here is the reference code:

``` js
Rx.Observable
  .fromEvent(document.querySelector('.auto-complete__list'), 'click')
  .filter(e => e.target.matches('li'))
  .map(e => e.target.innerHTML)
  .subscribe(value => {
    document.querySelector('.auto-complete input').value = value;
    renderList([])
  })
```

Although I have only introduced the most basic operations, the power of RxJS lies in the fact that there are many other features, such as `retry`, which can be easily added to enable automatic retries.

There are many other related application scenarios, and almost all of them related to APIs can be elegantly solved using RxJS.

# Asynchronous Solution for React + Redux: redux-observable

This is our last topic today, and it is also what I mentioned at the beginning.

The combination of React + Redux is very common, but there has always been a problem with the lack of standardization for handling asynchronous behavior (such as APIs). The open source community has many different solutions, such as redux-thunk, redux-promise, redux-saga, and so on.

We have talked about so many things and given so many examples to prove that Reactive programming is very suitable for solving complex asynchronous problems. Therefore, Netflix has open-sourced this [redux-observable](https://redux-observable.js.org/), which uses RxJS to handle asynchronous behavior.

After understanding RxJS, it is easy to understand the principle of `redux-observable`.

In a redux application, all actions go through middleware, where you can process actions. Alternatively, we can also see actions as an Observable, for example:

``` js
// Example only
Rx.Observable.from(actionStreams)
  .subscribe(action => {
    console.log(action.type, action.payload)
  })
```

With this, we can do some interesting things, such as detecting a certain action and sending a request, then putting the response into another action and sending it out.

``` js
Rx.Observable.from(actionStreams)
  .filter(action => action.type === 'GET_USER_INFO')
  .switchMap(
    action => Rx.Observable.from(API.getUserInfo(action.payload.userId))
  )
  .subscribe(userInfo => {
    dispatch({
      type: 'SET_USER_INFO',
      payload: userInfo
    })
  })
```

The above is a simple example, but `redux-observable` has already handled many things for us, so we just need to remember one concept:

> action in, action out

`redux-observable` is a middleware where you can add many `epics`, each of which is an Observable. You can listen to a specified action, process it, and then convert it into another action.

It is easier to understand by looking at the code:

``` js
import Actions from './actions/user';
import ActionTypes from './actionTypes/user'

const getUserEpic = action$ =>
  action$.ofType(actionTypes.GET_USER)
    .switchMap(
      action => Rx.Observable.from(API.getUserInfo(action.payload.userId))
    ).map(userInfo => Actions.setUsers(userInfo))
```

We listen to an action type (`GET_USER`), and when we receive it, we send a request and convert the result into a `setUsers` action. This is the so-called action in, action out.

What are the benefits of this? The benefit is that it clearly defines a specification. When your component needs data, it sends a `get` action. This action triggers the epic when it goes through middleware, and the epic sends a request to the server to get data, converts it into another `set` action, and updates the data to the component's props after being set by the reducer.

You can see this flowchart:

![observable](https://user-images.githubusercontent.com/2755720/49350925-fe5c2800-f6eb-11e8-9ce6-a4d15c8130a6.png)

In short, `epic` is an Observable, and you just need to make sure that the last thing you return is an action, and that action will be sent to the reducer.

Due to the length of this article, today's `redux-observable` is only conceptually introduced, and there is no time to demonstrate it. I will find time to write a practical application of `redux-observable` later.

# Conclusion

From the beginning of arrays to Observables, from drawing examples to classic Auto Complete, and finally to `redux-observable`, I hope everyone can appreciate the power and simplicity of Observables in handling asynchronous behavior.

The purpose of this article is to help everyone understand what Observable is doing and introduce some simple application scenarios. I hope to provide a simple and easy-to-understand Chinese introductory article so that more people can appreciate the power of Observables.

If you like this post, please help share it. If you find any mistakes, feel free to leave a comment and correct me. Thank you.

References:

- [30 Days to Master RxJS (01): Understanding RxJS](https://ithelp.ithome.com.tw/articles/10186104)
- [Introduction and Tutorial to Reactive Programming (Using RxJS)](http://blog.techbridge.cc/2016/05/28/reactive-programming-intro-by-rxjs/)
- [The introduction to Reactive Programming you've been missing](https://gist.github.com/staltz/868e7e9bc2a7b8c1f754)
- [Building Streaming Applications - A Comprehensive Guide to RxJS](http://www.alloyteam.com/2016/12/learn-rxjs/)
- [Epic Middleware in Redux](https://medium.com/kevin-salters-blog/epic-middleware-in-redux-e4385b6ff7c6)
- [Combining multiple Http streams with RxJS Observables in Angular2](http://blog.danieleghidoli.it/2016/10/22/http-rxjs-observables-angular/)

Videos:

- [Netflix JavaScript Talks - RxJS + Redux + React = Amazing!](https://www.youtube.com/watch?v=AslncyG8whg)
- [RxJS Quick Start with Practical Examples](https://www.youtube.com/watch?v=2LCo926NFLI)
- [RxJS Observables Crash Course](https://www.youtube.com/watch?v=ei7FsoXKPl0)
- [Netflix JavaScript Talks - RxJS Version 5](https://www.youtube.com/watch?v=COviCoUtwx4)
- [RxJS 5 Thinking Reactively | Ben Lesh](https://www.youtube.com/watch?v=3LKMwkuK0ZE)
