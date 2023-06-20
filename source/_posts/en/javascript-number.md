---
title: Common Mistakes When Using Numbers in JavaScript
catalog: true
date: 2022-03-14 21:02:51
tags: [JavaScript]
categories: [JavaScript]
---

Among the various data types in JavaScript, Number is a very commonly used one, and there are some small details that need to be paid special attention to, otherwise it is easy to write code with bugs.

This article will show you some examples, some are hypothetical scenarios, and some are problems I have encountered myself. Before continuing to explain each case, you can try to put yourself in the scenario and think about whether you know the cause of the problem and how to avoid it.

<!-- more -->

## Case 1: Starting with Duplicate IDs

When I was working at my previous company, my colleague was responsible for a system similar to a forum, and each message would have a unique ID. Since it is called an ID, it means that it cannot be duplicated. However, one day, my colleague found that the ID was duplicated! When he opened the DevTools and looked at the response content, the ID was indeed duplicated. So he went to confirm with the backend and complained about how the backend had a bug and generated duplicate IDs.

However, after the backend checked it, they said that there was no such thing, and the ID could not be duplicated. Moreover, they had checked it, so was there a problem with the frontend?

So my colleague went back to the frontend and found a strange phenomenon.

When you look at it on the "Response" tab in the developer tools, the ID is indeed not duplicated:

![](/img/javascript-number/number1.png)

However, once you switch to the "Preview" tab, you will find that the ID is actually duplicated:

![](/img/javascript-number/number2.png)

Why is there such a magical phenomenon? Is it another wonderful bug in JavaScript?

No, it's not. It's just that my colleague is not so familiar with the Number data type in JavaScript.

## Numbers with Ranges

In the previous article [Counting All Data Types in JavaScript](https://blog.huli.tw/2022/02/25/javascript-how-many-types/), we mentioned that JavaScript numbers are stored using 64 bits and follow the IEEE 754-2019 specification.

Since it is stored using 64 bits, it means that the amount of data that can be represented is limited, but numbers are infinite, so naturally, 64 bits cannot store all numbers, so there must be a limit and a safe range.

In JavaScript, you can use `Number.MAX_SAFE_INTEGER` to get the safe range of positive integers. This value will be `2^53 - 1`, which is `9007199254740991`. What does this safe range mean?

This paragraph from [MDN](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Number/MAX_SAFE_INTEGER) explains it well:

> Safe in this context refers to the ability to represent integers exactly and to correctly compare them. For example, Number.MAX_SAFE_INTEGER + 1 === Number.MAX_SAFE_INTEGER + 2 will evaluate to true, which is mathematically incorrect.

Safe refers to the ability to represent integers exactly and to correctly compare them. In other words, if it exceeds this safe range, this cannot be guaranteed. An example will make it clearer:

``` js
console.log(9007199254740992 === 9007199254740993) // true
console.log(Number('9007199254740993')) // 9007199254740992
```

By now, you should know why my colleague encountered this problem. This is because the ID passed by the backend was too large. In the Response tab, it only presents the original data returned by the backend and does not convert it into a JavaScript object. In the Preview tab, the JSON-formatted string is converted into a JavaScript object, so the ID is converted into a Number, exceeding the safe range, resulting in an error, just like the example above.

So how to solve this? The ID passed by the backend should be in string type, and when using it in the frontend, remember not to convert it into a number, and treat the ID as a string, so that there will be no errors caused by converting it into a number.

In addition, the `Number.MAX_SAFE_INTEGER` mentioned above refers to the safe range, which means that even if it exceeds this range, you can still store numbers, but they are not accurate. Do these inaccurate numbers have a range? Yes, they do, and the upper limit is `Number.MAX_VALUE`:

``` js
console.log(Number.MAX_VALUE) // 1.7976931348623157e+308
```

It's about 1.79 * 10^308, a very large number. What happens if it exceeds this range? It becomes positive infinity: `Infinity`.

``` js
console.log(Number.MAX_VALUE + 1) // 1.7976931348623157e+308
console.log(Number.MAX_VALUE * 2) // Infinity
```

Hey, didn't I say that if it's larger than `Number.MAX_VALUE`, it will be infinite? Why didn't it become `Infinity` after +1? The reason is the same as mentioned above. After exceeding the safe range, it becomes imprecise. Therefore, +1 is still the same number. If you are curious about how much to add to become `Infinity`, I found it out. It seems to be this number:

``` js
console.log(Number.MAX_VALUE + 9.9792015476735e+291) // 1.7976931348623157e+308
console.log(Number.MAX_VALUE + 9.9792015476736e+291) // Infinity
```

Anyway, in the future, when dealing with large number-related calculations, remember the upper limit of Number. If it exceeds this range, you can use the latest [BigInt data type](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/BigInt) to handle it, and you won't encounter these problems.

## Case 2: Closest Pair of Points

A few years ago, I set up a [LIOJ](https://oj.lidemy.com/) to let students practice basic programming syntax, and there are some questions I came up with.

One of the questions is not particularly difficult, and it can even be said to be quite ordinary, but only about 25% of the answers are correct.

The question link is here: [LIOJ 1033 - Closest Pair of Points](https://oj.lidemy.com/problem/1033). Interested friends can try it first to see if they can AC at once (but first familiarize themselves with the input and output mode of OJ).

The question is like this. Since the input is read from a file, it will always be a string, and the format is like this:

``` js
4
2 3
1 3
1 2
1 1
```

The first line 4 means that there are 4 sets of data, and each subsequent line is a set of coordinates represented by (x, y). The question is to find the two closest points. If there are more than two sets that are closest, please output the one that appears first in the data.

When outputting, please output the point with the smaller x first. If x is the same, please output the point with the smaller y first.

Using the test data above as an example, the answer will be:

```
1 3
2 3
```

This question seems to have no difficulty. What mistakes did everyone make that they couldn't solve?

Let's first look at a common solution:

``` js
const input = `4
2 3
1 3
1 2
1 1`

const lines = input.split('\n')
const dots = lines.slice(1).map(item => item.split(' '))
let min = Infinity
let ans1, ans2
for(let i=0; i<dots.length; i++) {
  for(let j=i+1; j<dots.length; j++) {
    let dis = distance(dots[i][0], dots[i][1], dots[j][0], dots[j][1])
    if (dis < min) {
      ans1 = dots[i]
      ans2 = dots[j]
      min = dis
    }
  }
}

// 先輸出 x 比較小的點
if (ans1[0] > ans2[0]) {
  console.log(ans2[0] + ' ' + ans2[1])
  console.log(ans1[0] + ' ' + ans1[1])
} else if (ans1[0] < ans2[0]){
  console.log(ans1[0] + ' ' + ans1[1])
  console.log(ans2[0] + ' ' + ans2[1])
} else {
  // 兩個相等，輸出 y 較小的點
  if (ans1[1] > ans2[1]) {
    console.log(ans2[0] + ' ' + ans2[1])
    console.log(ans1[0] + ' ' + ans1[1])
  } else {
    console.log(ans1[0] + ' ' + ans1[1])
    console.log(ans2[0] + ' ' + ans2[1])
  }
}

function distance(x1, y1, x2, y2) {
  return Math.sqrt(
    (x1 - x2) * (x1 - x2) +
    (y1 - y2) * (y1 - y2)
  )
}
```

It seems that there is no problem. Take each set to calculate the distance, find the minimum value after the distance is calculated, and output the result according to the requirements of the question. The test data provided by the question has also passed.

However, if you actually submit it to OJ, you will find that it is wrong. Where is the mistake? It's not wrong in calculating the distance, but in outputting:

``` js
if (ans1[0] > ans2[0]) {
  console.log(ans2[0] + ' ' + ans2[1])
  console.log(ans1[0] + ' ' + ans1[1])
} else if (ans1[0] < ans2[0]){
  console.log(ans1[0] + ' ' + ans1[1])
  console.log(ans2[0] + ' ' + ans2[1])
} else {
  // 兩個相等，輸出 y 較小的點
  if (ans1[1] > ans2[1]) {
    console.log(ans2[0] + ' ' + ans2[1])
    console.log(ans1[0] + ' ' + ans1[1])
  } else {
    console.log(ans1[0] + ' ' + ans1[1])
    console.log(ans2[0] + ' ' + ans2[1])
  }
}
```

Assuming that the two closest points found are `(11,12)` and `(2,3)`, according to the description of the question, the point with the smaller x should be output first, which is `(2,3)`. However, the above code will output `(11,12)` first. Why is this?

This is because we did not specifically convert the data into numbers during the data reading process, so the numbers we thought from beginning to end are actually strings. When calculating the distance, because subtraction (`x1 - x2`) is used, JavaScript will automatically convert it to a number and then subtract it.

However, when comparing, it will still be compared according to the original data type, which is a string. JavaScript's comparison of strings is basically based on lexicographic order. Simply put, when you look up a word in a dictionary, for example, if you want to look up `cool`, you must first turn to the page of `c`, and then start looking for `co`, and then look for `coo`. Find one word at a time, and finally find `cool`.

The comparison of lexicographic order is also similar, comparing one word at a time, so when JavaScript compares `"11"` with `2`, it compares the first word and finds that `"2"` is larger than `"1"`, so the result is `"2" > "11"`, which is completely different from the comparison logic of numbers.

Therefore, before making a comparison, please remember to check the data type of the variable. Different types will have different comparison methods. In the above code, as long as the strings are converted to numbers when reading the input, there will be no problem.

Although I wrote it like this above, in a few cases, even if you pay attention to the data type, it may not work because the underlying operation is different from what you think.

In JavaScript, the most famous case is the sorting of arrays.

``` js
let arr = [2, 11, 3, 7, 42]
arr.sort()
console.log(arr) // ???
```

The above code, I believe anyone who reads it will think that the result is either `2,3,7,11,42` or the reverse `42,11,7,3,2`, but the result is unexpected. I'm sorry, neither of them is correct. The answer is `11,2,3,42,7`:

``` js
let arr = [2, 11, 3, 7, 42]
arr.sort()
console.log(arr) // [11, 2, 3, 42, 7]
```

This is because the default sorting method of `Array.prototype.sort` will first convert the elements in the array into strings for sorting. Let's take a look at the specification (23.1.3.27.1 SortCompare, p658):

![](/img/javascript-number/sort-compare.png)

Therefore, if you want to sort numbers, you must pass the parameter `comparefn` to customize the comparison method, such as this:

``` js
let arr = [2, 11, 3, 7, 42]
arr.sort((a, b) => a - b)
console.log(arr) // [2, 3, 7, 11, 42]
```

The logic of `comparefn` is that it will pass in two elements a and b in the array. If the function returns a negative number, it means that a is in front of b. If it returns 0, it means that the order of a and b will not change. A positive number means that b is in front of a.

I remember it in another way: "Assume that the input ab is originally in the order of the array ab. Returning a positive number means that the two need to be swapped, a negative number means no swap, and 0 means the two are equal."

Therefore, if I have two numbers, 2 and 11, and I return `a - b`, it will be a negative number, so they will not be swapped, and they will be sorted from small to large. If I return `b - a`, it will be a positive number, and they will be swapped, so they will be sorted from large to small.

So why did JavaScript design it this way? Someone has asked Brendan Eich on Twitter, and the link is here: https://twitter.com/BrendanEich/status/930665293034283008

His reply was:

> You mean the default sort function? It's modeled on Perl 4 sort.
>
> Presumption was JS would be used for perlish tasks & strings were likelier in arrays than numbers. (I think that's the Perl rationale, but not sure.)
> 
> Picking a numeric sort function if the array contained only numbers required checking every element type. I had to pick a type!

I didn't understand it very well, but the general idea should be that he referred to Perl 4's sort when designing it, and assumed that JS would be used for Perl-related tasks by default, and strings would be more likely to appear in arrays than numbers. In addition, if you want to implement numeric sorting, you have to check the data type of each element in the array first.

In any case, when using `sort`, you need to pay attention to this situation, and when comparing numbers, you also need to remember to check the data type first, otherwise you may write code with bugs.

Finally, a small reminder is that when converting numbers to strings, the result may be slightly different from what you think.

``` js
console.log((12345678912345678).toString()) // 12345678912345678
console.log((1234567891234567812345).toString()) // 1.2345678912345677e+22
console.log((0.000001).toString()) // 0.000001
console.log((0.0000001).toString()) // 1e-7
```

When you convert some larger or smaller numbers, they will be converted into scientific notation. There are detailed conversion rules in the specification (6.1.6.1.20 Number::toString, p.83):

![](/img/javascript-number/number-tostring.png)

## Case 3: Floating Point Precision Issues

This should be well known, which is the classic `0.1 + 0.2 !== 0.3`:

``` js
console.log(0.1 + 0.2 === 0.3) // false
console.log(0.1 + 0.2) // 0.30000000000000004
```

If you think this is a problem unique to JavaScript, then you are wrong. This is actually a common problem in many programming languages. The root cause of the problem is similar to the number range problem we mentioned at the beginning. The space for storing numbers is limited, but the numbers are infinite, so it is impossible to express all numbers accurately.

There is another problem with floating-point numbers, which is that there may be infinitesimal numbers, such as `1/3 = 0.3333....`. When stored as floating-point numbers, some precision will be lost:

``` js
console.log((1/3).toFixed(30)) // 0.333333333333333314829616256247
```

So what should we do when writing programs?

If you don't need to do very precise calculations, but just want to avoid errors like `0.1 + 0.2 !== 0.3`, usually we will choose a reasonable error value, which means that we don't care whether they are equal or not, but consider the error. As long as the error value is within a certain range, they are considered equal. In JavaScript, for example, there is a `Number.EPSILON`:

``` js
console.log(Math.abs(0.3 - (0.1 + 0.2))) // 5.551115123125783e-17
console.log(Math.abs(0.3 - (0.1 + 0.2)) < Number.EPSILON) // true
```

However, the value of `Number.EPSILON` is 2^-52, which is actually too small. If you perform floating-point arithmetic several times, it is easy to exceed this range:

``` js
console.log(Math.abs(3.3 - (1.1 + 1.1 + 1.1))) // 4.440892098500626e-16
console.log(Math.abs(3.3 - (1.1 + 1.1 + 1.1)) < Number.EPSILON) // false
```

Therefore, a more practical approach is to determine the error value based on your usage scenario. For example, if the input you use for calculation is at most up to the third decimal place, such as `1.283` or `27.583`, then an error value of `1e-9` should be sufficient.

However, if you need higher precision calculations, do not use floating-point numbers. Using other libraries such as [decimal.js](https://mikemcl.github.io/decimal.js/) would be a better choice. In the future, we may also have the opportunity to see JavaScript [natively support](https://github.com/tc39/proposal-decimal) this feature.

If you want to know whether various programming languages have this problem, you can refer to this website: https://0.30000000000000004.com/.

If you want to further understand the principles behind floating-point numbers and more examples, you can refer to this article I have read since I was young: [The most basic concept of using floating-point numbers](http://blog.dcview.com/article.php?a=VmhQNVY%2BCzo%3D), and [What you don't know about C language: floating-point arithmetic](https://hackmd.io/@sysprog/c-floating-point).

## Case 4: Numbers that are not numbers

Have you ever seen the word `NaN` on some websites?

In JavaScript, when you perform some "not a number" operations on numbers, a thing called NaN will be generated:

``` js
console.log(Number('abc')) // NaN
console.log(500/undefined) // NaN
```

The full name of NaN is Not a Number. However, I suggest that you do not remember it this way because it is actually more like "a special number used to represent illegal numbers". Because the type of NaN is also Number:

``` js
console.log(typeof NaN) // number
```

And it also has a magical feature, which is the only value in the entire world of JavaScript that is not equal to itself (by the way, you can make a similar one yourself using Proxy or Object.defineProperty):

``` js
console.log(NaN === NaN) // false
```

But this behavior is not invented by JavaScript itself, but is specified in IEEE 754 mentioned earlier. If you want to know the reason, you can go to the answers under [Why is NaN not equal to NaN?](https://stackoverflow.com/questions/10034149/why-is-nan-not-equal-to-nan), and the best answer also quotes some answers from IEEE 754 members.

If you want to detect whether a value is NaN in JavaScript, due to historical baggage, you have two ways:

``` js
console.log(isNaN(NaN)) // true
console.log(isNaN('abc')) // true
console.log(Number.isNaN(NaN)) // true
console.log(Number.isNaN('abc')) // false
```

The first `isNaN` is a function that exists on the global object. Its specification is as follows (19.2.3 isNaN. p.468):

![](/img/javascript-number/global-isnan.png)

Simply put, if the value passed in is not a number, it will be converted to a number first, and then check whether it is NaN. Therefore, the passed in `"abc"` will be converted to a number and become NaN.

The second one is `Number.isNaN` introduced in ES6, and its specification is as follows (21.1.2.4 Number.isNaN, p.508):

![](/img/javascript-number/number-isnan.png)

Here, it first checks whether the type is a number. If it is not, it directly returns false. If it is, it then checks whether it is NaN.

So, if the version is too old and there is no `Number.isNaN`, how to implement its polyfill? We can refer to the implementation of [corejs](https://github.com/zloirock/core-js/blob/master/packages/core-js/modules/es.number.is-nan.js), which uses the feature of "not equal to itself".

``` js
// `Number.isNaN` method
// https://tc39.es/ecma262/#sec-number.isnan
$({ target: 'Number', stat: true }, {
  isNaN: function isNaN(number) {
    // eslint-disable-next-line no-self-compare -- NaN check
    return number != number;
  }
});
```

## Conclusion

When using numbers, the two most common mistakes are probably not paying attention to the range and type. As long as you remember that numbers have a range of storage, you can avoid writing similar bugs in the future. When dealing with floating-point numbers and large numbers, you should also be more careful and remind yourself not to exceed the range.

As for types, confusing strings and numbers can lead to unexpected results when adding or comparing. These are also parts that you should pay attention to. If you are really confused by types, you can also consider introducing TypeScript or similar tools, which will remind you of type problems during compilation. As for the problem with `Array.prototype.sort`, probably every novice will step on it once, after all, it is really counterintuitive.

Finally, this article only mentions some relatively superficial parts, and does not involve more knowledge related to Number, such as 0 actually has +0 and -0, and infinity is also divided into positive infinity and negative infinity. It also does not explain the underlying principles, such as:

1. How is `Number.MAX_SAFE_INTEGER` calculated?
2. Where does `Number.MAX_VALUE` come from?
3. What is the detailed principle of floating-point error? How is it stored in the system?

To explain these, we need to look at IEEE 754. Some of them I don't understand very well myself, and I will introduce them to you in the future if I have the opportunity.
