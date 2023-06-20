---
title: '[Javascript] Promise, generator, async and ES6'
date: 2015-08-26 17:04
catalog: true
tags: [JavaScript,Front-end]
categories:
  - JavaScript
---
In JavaScript, there is a super important concept called asynchronous, which is also the easiest concept to confuse and forget when you first start learning. ES6 natively supports `Promise`, which works better with `Generator`, and ES7 even supports the syntax of `async`. I think this is an evolutionary process that makes the program architecture better and more readable. So to explain these new things, let's start with the most basic callback.

<!-- more -->


Now let's assume we have three APIs. The first is an API that fetches a list of articles.
```json
[
  {
    "title": "Article 1",
    "id": 1
  },
  {
    "title": "Article 2",
    "id": 2
  },
  {
    "title": "Article 3",
    "id": 3
  }
]
```

The second is an API that fetches the content of an article given its ID.
```javascript
{
  "authorId": 5,
  "content": "content",
  "timestamp": "2015-08-26"
}
```

The third is an API that returns author information given an author ID.
```javascript
{
  "email": "aszx87410@gmail.com",
  "name": "huli",
  "id": 5
}
```

Now the functionality we want to achieve is: **fetch the email of the author of the latest article**. The process is: fetch the article list -> fetch the article information -> fetch the author. The code implementation looks like this.
``` javascript
getArticleList(function(articles){
	getArticle(articles[0].id, function(article){
    	getAuthor(article.authorId, function(author){
        	alert(author.email);
        })
    })
})

function getAuthor(id, callback){
    $.ajax("http://beta.json-generator.com/api/json/get/E105pDLh",{
    	author: id
    }).done(function(result){
    	callback(result);
    })
}

function getArticle(id, callback){
    $.ajax("http://beta.json-generator.com/api/json/get/EkI02vUn",{
    	id: id
    }).done(function(result){
    	callback(result);
    })
}

function getArticleList(callback){
	$.ajax(
    "http://beta.json-generator.com/api/json/get/Ey8JqwIh")
    .done(function(result){
        callback(result);
    });
}
```
Or refer to the online example: [Implemented with callback](http://jsfiddle.net/ddam2mof/2/)

I believe that this code should not be unfamiliar to everyone, but there is a disadvantage to this approach, which is what we commonly call callback hell. It's a bit ugly to have layer upon layer like this. So what should we do? There is something called `Promise`, which appears like this. Let's have a practical example first and then explain it!
``` javascript
getArticleList().then(function(articles){
	return getArticle(articles[0].id);
}).then(function(article){
    return getAuthor(article.authorId);
}).then(function(author){
	alert(author.email);
});

function getAuthor(id){
    return new Promise(function(resolve, reject){
        $.ajax("http://beta.json-generator.com/api/json/get/E105pDLh",{
            author: id
        }).done(function(result){
            resolve(result);
        })
    });
}

function getArticle(id){
    return new Promise(function(resolve, reject){
        $.ajax("http://beta.json-generator.com/api/json/get/EkI02vUn",{
            id: id
        }).done(function(result){
            resolve(result);
        })
    });
}

function getArticleList(){
    return new Promise(function(resolve, reject){
       $.ajax(
        "http://beta.json-generator.com/api/json/get/Ey8JqwIh")
        .done(function(result){
            resolve(result);
        }); 
    });
}
```
Online example: [Implemented with Promise](http://jsfiddle.net/ddam2mof/3/)
`Promise` is an object with three states: pending, fulfilled, and rejected. In the above example, we removed the callback function of those three functions and replaced it with returning a `Promise` object. The place where the callback should have appeared originally became `resolve`. What are the benefits of doing this? Look at the place where we call these functions at the top. The original callback hell is gone, and we flattened it. If you don't understand it very well, let's start with the most basic, calling a `Promise`.
``` javascript
getArticleList().then(function(articles){
  console.log(articles);
});

function getArticleList(){
    return new Promise(function(resolve, reject){
       $.ajax(
        "http://beta.json-generator.com/api/json/get/Ey8JqwIh")
        .done(function(result){
            resolve(result);
        }); 
    });
}
```

You can add `.then` after a Promise object to get the result after the Promise is executed. If you return another `Promise` object in `then`, you can keep chaining them. For example:

```javascript
getArticleList().then(function(articles){
	return getArticle(articles[0].id);
}).then(function(article){
    return getAuthor(article);
});
```

With this feature of Promise, you can avoid callback hell. If we add ES6 arrow functions, it can be simplified to:

``` javascript
getArticleList()
.then(articles => getArticle(articles[0].id))
.then(article => getAuthor(article.authorId))
.then(author => {
	alert(author.email);
});
```

[Online example of Promise+arrow function](http://jsfiddle.net/aszx87410/ddam2mof/4/)

The example of using Promise alone ends here. The syntax is already quite simple, and with arrow functions, it becomes more readable. However, seeing a bunch of `then` can still be a bit annoying.

What's next? ES6 has a new feature called Generator. If you don't know what it is, you can refer to my previous article [[Javascript] ES6 Generator Basics](http://huli.logdown.com/posts/292331-javascript-es6-generator-foundation). Then we can use the feature of Generator to write code that looks super synchronous but is actually asynchronous:

``` javascript
function* run(){
  var articles = yield getArticleList();
  var article = yield getArticle(articles[0].id);
  var author = yield getAuthor(article.authorId);
  alert(author.email);  
}

var gen = run();
gen.next().value.then(function(r1){
  gen.next(r1).value.then(function(r2){
      gen.next(r2).value.then(function(r3){
        gen.next(r3);
        console.log("done");
      })
  })
});
```

[Complete online example of Promise + Generator](http://jsfiddle.net/aszx87410/ddam2mof/5/)

Looking closely at the `run` generator, using the feature of `yield`, the right-hand code will be executed first, waiting for the next call and assigning it to the left-hand side. So we can call `gen.next(r1)` in the `then` event of `getArticleList()`, which will pass the return value to the `articles` variable. If you find this a bit difficult to understand, you can start with a single layer:

```javascript
function* run(){
  var articles = yield getArticleList();
  console.log(articles); 
}

var gen = run();

// The first call will execute getArticleList(), which will return a Promise
gen.next().value.then(function(r1){

  // After the first Promise is completed, pass r1 back to the generator to let articles = the return value of getArticleList()
  gen.next(r1);
  console.log('done');
});
```

Let's take another look at the top half of the above code:

``` javascript
function* run(){
  var articles = yield getArticleList();
  var article = yield getArticle(articles[0].id);
  var author = yield getAuthor(article.authorId);
  alert(author.email);  
}
```

Do you feel that it looks very similar to synchronous code? If you remove `yield`, it is exactly the same! This is the essence of Generator: using syntax that looks very similar to synchronous code, but is actually asynchronous.

Let's take a look at the second half:

``` javascript
var gen = run();
gen.next().value.then(function(r1){
  gen.next(r1).value.then(function(r2){
      gen.next(r2).value.then(function(r3){
        gen.next(r3);
        console.log("done");
      })
  })
});
```

It is easy to see that the syntax of the second half is very fixed and easy to find patterns. It is also a recursion. Therefore, it can be wrapped in a function to handle more general cases.

``` javascript
function* run(){
  var articles = yield getArticleList();
  var article = yield getArticle(articles[0].id);
  var author = yield getAuthor(article.authorId);
  alert(author.email);  
}

function runGenerator(){
	var gen = run();
    
    function go(result){
        if(result.done) return;
        result.value.then(function(r){
        	go(gen.next(r));
        });
    }
    
    go(gen.next());
}

runGenerator();
```

[Complete online example Promise + Generator + Recursion](http://jsfiddle.net/aszx87410/ddam2mof/6/)

The `co` module made by `tj` is doing almost the same thing, but it does more. The principle is similar to what we wrote above, which is to wrap a generator and write an automatic executor.

Finally, let's talk about the last thing in the title: `async`. What is it? Let's take a look at the code:

``` javascript
async function run(){
  var articles = await getArticleList();
  var article = await getArticle(articles[0].id);
  var author = await getAuthor(article.authorId);
  alert(author.email);  
}
```

[Complete online example async (cannot run)](http://jsfiddle.net/aszx87410/ddam2mof/7/)

The difference between this code and the previous one is that:

1. `function* gen()` becomes `async function run()`
2. `yield` becomes `await`

That's it. And you will find that it ends like this. You don't need to use other modules or write your own recursive executor. This is the syntax of `async`, which is just to write those automatic executors, but this syntax makes it much more convenient for us. Actually, this syntax is planned to be introduced in `ES7`, QQ.

The good news is that the ES6 code we wrote above has been converted to ES5 syntax through the `babel` library. And it has an experimental feature, which includes `async`. And `async` is in `stage 2`, **NOTE: Stage 2 and above are enabled by default.** You don't need to adjust any parameters to automatically enable it, which is really gratifying.

When I first came into contact with ES6, I was overwhelmed by a lot of dazzling things. Each one is a subject to delve into. And I used pure callbacks before (because the level is not much, so it's okay), and occasionally used `async` (node's library, different from the one above). So I think the best way to understand it is to start with the most basic callback, gradually progress to promise, then to generator, and finally to async. Only then can we understand why these things appear.

If there are any mistakes in the above, please leave a message or send me an email. Thank you.

Ref:
[ECMAScript 6 入门 异步操作](http://es6.ruanyifeng.com/#docs/async)
[JavaScript Promises](http://www.html5rocks.com/zh/tutorials/es6/promises/)
[拥抱Generator，告别异步回调](https://cnodejs.org/topic/542953d42ca9451e1bf3c251)
[深入浅出ES6（三）：生成器 Generators](http://www.infoq.com/cn/articles/es6-in-depth-generators)
