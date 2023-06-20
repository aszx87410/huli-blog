---
title: Console.log Issues You Need to Pay Attention to
catalog: true
header-img: /img/header_img/article-bg.png
date: 2020-03-23 23:08:32
tags: [Web]
categories:
  - Web
photos: /img/console-log-bug/cover-en.png
---

## Preface

I wrote this article because I believe that many people have encountered this problem. In summary, when using `console.log` to print an object, the printed value is different from what you expected. Let's take a look at the code below:

<!-- more -->


```js
var obj = {value: 'before'}
console.log('before:', obj) // should be {value: 'before'}
obj.value = 'after'
console.log('after:', obj)
```


This is a very simple code that logs an object, changes a property, and then logs it again. Naturally, the expected result of the first log should be: `before: {value: 'before'}`, and the second log should be: `after: {value: 'after'}`.

However, in reality, things are not quite as you imagined. The actual situation is:

1. If you open the console after executing this code, you may see that the result of the first log is `{value: 'after'}`, not `{value: 'before'}`
2. If you execute the code before opening the console, although it seems correct at first glance, if you click on the object in the console to view its details, you will see `{value: 'after'}`, as shown in the figure below, and then you will begin to doubt everything.


![](/img/console/bug.png)

If you don't believe it, you can try it yourself: [Demo link](https://aszx87410.github.io/demo/console_log_bug/)

When viewing logs, developers should expect to see the state of the log at that time. However, when you click on the details of the object, you will see the latest state, not the state at the time of the log. This is why the situation in the attached figure occurs. The preview shows the state at the time of the log, and the expanded state shows the latest state, so the two are inconsistent.

Some people may think that if the preview is correct, just look at the preview. However, the preview has limitations. When your object has too many properties, it cannot display all of them. You must expand the object to see all the properties. Once this happens, you cannot just look at the preview, you must expand the object, but then you cannot see the value of the log at that time.

This is just a simple example, and you may think it's nothing, but the scary thing about this problem is that when you first encounter it, it is often in an actual development scenario, not a simple example like this. Developers will think about where the program went wrong and why the printed output is different from what they expected, without knowing that the console is different from what they imagined.

This problem is basically "unfixable", so the best way to deal with it is:

1. Know that this problem exists and pay more attention to it in the future
2. Know how to temporarily deal with this problem
3. Know why this problem cannot be fixed

## Observing the Problem Again

As mentioned earlier, there may be two problems that may occur. Let's try to see how different browsers handle the results under two different scenarios.

First, here is the sample code used for testing:

``` js
var obj = {value: 'before'}
console.log('before:', obj) // should be {value: 'before'}
obj.value = 'after'
console.log('after:', obj)
```

1. Scenario 1: Execute this code first, then open the console to view the results
2. Scenario 2: Open the console first, then execute the code to view the results

Below are the results of various browsers on macOS Mojave 10.14.4:

### Chrome 80.0.3987.149

#### Scenario 1: Execute the code first and then open the console

Only the word "Object" is displayed, and no preview is displayed:

![](/img/console/chrome-1.png)


#### Scenario 2: Open the console first, then execute the code

The content of the console preview is correct, and after expanding the object, the latest content of the object is displayed.

![](/img/console/bug.png)

### Firefox 74.0

#### Scenario 1: Execute the code first and then open the console

The preview displayed is incorrect, and both are `{value: 'after'}`:

![](/img/console/ff-1.png)


#### Scenario 2: Open the console first, then execute the code

The content of the console preview is correct, and after expanding the object, the latest content of the object is displayed.

![](/img/console/ff-2.png)

### Safari 12.1（14607.1.40.1.4）

#### Scenario 1: Execute the code first and then open the console

Only the word "Object" is displayed, and no preview is displayed:

![](/img/console/safari-1.png)


#### Scenario 2: Open the console first, then execute the code

The content printed by the console preview is correct, and after expanding the object, the latest content of the object is printed.

Note: Because the object cannot be expanded if it is too short, I added a few properties.

![](/img/console/safari-2.png)

-----

From the above experiments, several conclusions can be drawn:

1. For scenario one: "run the program first and then open the console", Chrome and Safari will not have a preview, while Firefox will display an incorrect preview.
2. For scenario two: "open the console first and then run the program", the behavior of the three browsers is consistent, and the preview is correct. Expanding the object to view the detailed content will show the latest state of the object.

## The reason for the problem

This problem has actually existed for a long time, and there have been Stackoverflow discussion threads several years ago:

1. [Google Chrome console.log() inconsistency with objects and arrays](https://stackoverflow.com/questions/24175017/google-chrome-console-log-inconsistency-with-objects-and-arrays)
2. [console.log() shows the changed value of a variable before the value actually changes](https://stackoverflow.com/questions/11284663/console-log-shows-the-changed-value-of-a-variable-before-the-value-actually-ch)
3. [Is Chrome's JavaScript console lazy about evaluating arrays?](https://stackoverflow.com/questions/4057440/is-chromes-javascript-console-lazy-about-evaluating-arrays)

Related records can also be found in the issue trackers of various browsers:

1. [Webkit: Bug 35801 - Web Inspector: generate preview for the objects dumped into the console upon logging.](https://bugs.webkit.org/show_bug.cgi?id=35801)
2. [Mozilla: console.log doesn't show objects at the time of logging if console is closed](https://bugzilla.mozilla.org/show_bug.cgi?id=754861)
3. [Chromium: Issue 1041063: console.log() does not log the correct fields of an object at the instant it is called](https://bugs.chromium.org/p/chromium/issues/detail?id=1041063&q=console%20preview&can=1)
4. [Chromium: Issue 760776: Console Array data updates after console.log](https://bugs.chromium.org/p/chromium/issues/detail?id=760776&q=console.log%20preview&can=1)

Even MDN's documentation on `console.log` has a section specifically addressing this issue:

> Don't use console.log(obj), use console.log(JSON.parse(JSON.stringify(obj))).

> This way you are sure you are seeing the value of obj at the moment you log it. Otherwise, many browsers provide a live view that constantly updates as values change. This may not be what you want.

The above link also has people explaining why this problem exists and why it cannot be fixed.

First of all, in the case of opening devtool, the content of the preview is basically correct, so there is no problem with this. However, after expanding the object, what is displayed is not the value at the time of the log, but the latest state of the object. This is what causes confusion, because developers would expect that even if the object is expanded, it should still be the state of the log at that time.

But to achieve this function, every time `console.log` is used, the browser needs to copy all the current values to ensure that users can see the content of the log at that time when expanding the object.

Applying what others have said in the above issue, they said:

> We can't get a copy of the heap every time you console.log...

> I don't think we are ever going to fix this one. We can't clone object upon dumping it into the console and we also can't listen to the object properties' changes in order to make it always actual.

So there are difficulties in implementation, and it cannot be done. Since it cannot be fixed, we can only pay more attention to this situation. When using `console.log` to print an object, remember that:

1. The preview is basically correct (if devtool is open when you log).
2. The complete data seen after expansion will be the latest state of the object, not the state at the time of the log.

Chrome actually added a thoughtful little icon in the console to remind you of this:

![](/img/console/chrome-notice.png)

## Solutions to the problem

The solution is actually written in MDN. When printing an object, use `JSON.parse(JSON.stringify(obj))` to copy the current state of the object, and then generate a new object (commonly known as deep copy) to ensure that the current state is printed, like this:

``` js
function log() {
  var obj = {value: 'before'}
  console.log('before:', cp(obj))
  obj.value = 'after'
  console.log('after:', cp(obj))
}

function cp(obj) {
  return JSON.parse(JSON.stringify(obj))
}
```

Or there is another method, which is to try not to print the entire object. Instead of printing the entire object, print the value you really want to observe.

Or just use `debugger` to pause the program and see what the current value is, which is also a method.

## Summary

Many beginners will accidentally step on this pit when they first encounter `console.log`, and then they will find out that it is not a problem with their own code after a long time, but that the content logged is different from what they imagined. So I hope this article can let everyone know that this problem exists, so that in the future, when using `console.log` to print an object, you can pay more attention to this situation.

By the way, I personally still use `console.log` directly when printing objects, because it is more convenient. But because I know that `console.log` has this problem, once I find that the object I printed is different from what I imagined, I will use the above-mentioned deep copy to copy the value to confirm where the problem is.

Finally, please remember that arrays are also a type of object, so arrays will have the same situation.
