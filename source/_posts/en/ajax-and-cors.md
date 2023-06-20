---
title: 'Understanding Ajax and Cross-Origin Requests Easily'
date: 2017-08-27 22:12
catalog: true
tags: [Ajax,JavaScript,Front-end]
categories:
  - Front-end
---
## Introduction

When learning to write web pages, you usually start with HTML and CSS, which are responsible for creating and beautifying the layout. Once you have a solid foundation, you start learning JavaScript to create interactive effects. In addition to user and browser interactions, don't forget about the interaction between the client and server, which means you must learn how to use JavaScript to retrieve data from the backend server. Otherwise, your web page data will be static.

The main target audience of this article is beginners in web front-end development. I hope that after reading this article, readers who do not understand how to exchange data with the server or how to connect to APIs can have a better understanding of how to connect to the backend.

<!-- more -->

## Let's start with an example

Before we begin, let's consider a question:

> Why does the front-end need to exchange data with the backend?

Actually, this depends on the type of web page you are creating. If you are creating an official website, the entire website is likely to be static, and only HTML and CSS are required, without the need to retrieve data from the backend server.

Let's assume that today we want to create a web page that can browse the current Twitch live stream list, as shown below.

![](/img/ajax/twitch.png)

If this web page does not retrieve data from the backend, it means that the content of the web page is fixed and will remain the same no matter when it is viewed. However, this is not correct because the goal of this web page is to display "channels that are currently live," so the content will change accordingly.

Since the content will change, we must continuously update the data, retrieve data from the server, and then display it after processing it on the front-end.

After confirming the need to retrieve data, we can ask ourselves two questions:

1. Who do we retrieve data from?
2. How do we retrieve data?

The answer to the first question is obviously Twitch because Twitch has the data we need!

As for the second question, we must use the Twitch API.

## API

What is an API? You may have heard this term many times, but still don't know what it means. Let's start with its full name, which is "Application Programming Interface."

You may wonder what this is and why I can't understand it in both Chinese and English. But actually, the most important thing in these few words is the word "interface."

What is an interface? An interface is used for connection. I'll give you an example.

Isn't there a USB slot on your computer? As long as you see USB flash drives on the market, you can buy them and plug them into the USB slot, and your computer can read them. Have you ever wondered why? Although they are made by different manufacturers, they can all be read and plugged into the USB slot.

This is because there is a standard called the USB interface. After this standard was established, as long as all manufacturers develop according to this standard, they can ensure that they can connect to the computer and USB flash drives.

API is the same, but it becomes a connection between programs. For example, if I need to read a file in my program, how do I read it? Reading files is a function provided by the operating system, so I can connect to the "read file API" and use this function in my program.

I'll give you a few more examples. Suppose I want to allow my web page to log in with Facebook. What should I do? I need to connect to the "Facebook API," which is a set of standards provided by Facebook to everyone who wants to access Facebook services. Any developer who wants to access Facebook services can follow these standards to obtain the data they want. This thing is called an API.

Or maybe you are a developer of a hotel management system today, and your company has developed an ERP for hotels, which can manage the booking status of hotels and so on, and can know which rooms are empty now.

If you only use this data yourself, it would be a pity. Therefore, the company decided to provide this data to large booking websites, which can display the room status of this hotel in real-time on those websites. Therefore, data exchange is necessary, and you need to provide a "query room status API" to other websites so that they can connect to it and obtain this information.

By now, you should have some sense of what an API is. Let me give you a few more examples:

1. I want to retrieve photos from Flickr, so I need to connect to the Flickr API.
2. Google wants to allow other apps to log in and authenticate with Google, so Google needs to provide the "Google login API."
3. I want to retrieve the channels currently available on Twitch, so I need to connect to the Twitch API.

## API Documentation

Now that we know what an API is and that we need to connect to it, the next question is "how do we connect?"

Earlier, we mentioned an example of file access. This is actually more like calling a function provided by the operating system or a programming language library. You can usually find more detailed information about these functions in the official documentation, such as reading files in Node.js:

![](/img/ajax/fs.png)

(Source: https://nodejs.org/api/fs.html#fs_fs_readdir_path_options_callback)

Above, it is written which function you should call and what parameters you should pass in. 

API integration is the same. You must have documentation to know how to integrate, otherwise you cannot integrate at all because you don't even know what parameters to pass.

Let's take a look at how the [Twitch API documentation](https://dev.twitch.tv/docs/v5/guides/using-the-twitch-api/) is written.

It explains that you must have a `Client ID`, and the API Root URL is `https://api.twitch.tv/kraken`, etc. These are basic information related to the API. If you click on any API in the left column, you will see detailed information about each API:

![](/img/ajax/twitch2.png)

Here, it is written what the URL is, what parameters you should pass, etc. There are also reference examples below, which is a very complete API documentation.

Usually, when writing web pages, we directly talk about APIs, but actually we are referring to Web APIs, which are APIs transmitted through the network. Are there non-Web APIs? Yes, like the file reading API we mentioned earlier, they are all executed locally on the computer without going through any network.

But this doesn't really matter, everyone is used to talking about APIs, as long as they can understand it.

Now that we have the API documentation, we have all the information we need. Using the Twitch example above, as long as we can send a request to `https://api.twitch.tv/kraken/games/top?client_id=xxx` through JavaScript, Twitch will return the current list of the most popular games.

We have narrowed down the scope of the problem step by step. At first, it was "how to get data from Twitch", and now it is divided into: "how to use JavaScript to send a request".

## Ajax

To send a request on the browser, you must use a technology called Ajax, which stands for "Asynchronous JavaScript and XML", with the emphasis on the word "Asynchronous".

Before talking about what is asynchronous, let's first mention what is synchronous. Almost all JavaScript you originally wrote is executed synchronously. This means that when it executes to a certain line, it will wait for this line to finish executing before executing the next line, ensuring the execution order.

That is to say, the last line of the following code needs to wait for a long time to be executed:

``` js
var count = 10000000;
while(count--) {
  // Do some time-consuming operations
}
  
// Executed after a long time
console.log('done')
```

It looks reasonable. Isn't the program executed line by line? But if it involves network operations, everyone can think about the following example:

``` js
// Assuming there is a function called sendRequest to send a request
var result = sendRequest('https://api.twitch.tv/kraken/games/top?client_id=xxx');
  
// Executed after a long time
console.log(result);
```

When JavaScript executes `sendRequest`, because it is synchronous, it will wait for the response to come back before continuing to do anything. In other words, before the response comes back, the entire JavaScript engine will not execute anything! It's scary, isn't it? You click on anything related to JavaScript, and there is no response because JavaScript is still waiting for the response.

Therefore, for operations that are expected to be very time-consuming and unstable, synchronous execution cannot be used, but asynchronous execution must be used.

What does asynchronous mean? It means that after it is executed, it will not be taken care of, and it will continue to execute the next line without waiting for the result to come back:

``` js
// Assuming there is a function called sendRequest to send a request
var result = sendRequest('https://api.twitch.tv/kraken/games/top?client_id=xxx');
  
// The above request is executed, and then it executes to this line, so result will not have anything
// because the response has not returned yet
console.log(result);
```

Please note that "asynchronous functions cannot directly return results through return". Why? Because, as in the example above, after sending a request, the next line will be executed, and at this time, there is no response yet. What should be returned?

So what should we do? Let me give you a very common example! 

When I was eating in a food court in Singapore, there was a table number on each table. When you order, just tell the boss which table you are sitting at, and the boss will deliver it to you after the meal is ready.

So I don't need to stand at the door of the store and wait. I just continue to sit on my own things. Anyway, the boss will deliver it to me after the meal is ready.

The concept of asynchronous is also like this. After I send a request (after I order), I don't need to wait for the response to come back (I don't need to wait for the boss to finish), I can continue to do my own thing. After the response comes back (after the meal is ready), it will help me deliver the result (the boss will deliver it by himself).

In the ordering example, the boss can know where to send the data through the table number. What about in JavaScript? Through Function! And this function, we call it a Callback Function, a callback function.

When the asynchronous operation is completed, this function can be called and the data can be brought in.

``` js
// Assuming there is a function called sendRequest to send a request
sendRequest('https://api.twitch.tv/kraken/games/top?client_id=xxx', callMe);
  
function callMe (response) {
  console.log(response);
}
  
// Or write it as an anonymous function
sendRequest('https://api.twitch.tv/kraken/games/top?client_id=xxx', function (response) {
  console.log(response);
});
```

Now you know why network operations are asynchronous and what callback functions are.

## XMLHttpRequest

Just mentioned the concepts of Ajax, asynchronous, and callback functions, but didn't say how to send a request, just wrote a fake `sendRequest` function as a reference.

To send a request, we need to use an object prepared by the browser called `XMLHttpRequest`. The sample code is as follows:

``` js
var request = new XMLHttpRequest();
request.open('GET', `https://api.twitch.tv/kraken/games/top?client_id=xxx`, true);
request.onload = function() {
  if (request.status >= 200 && request.status < 400) {
  
    // Success!
    console.log(request.responseText);
  }
};
request.send();
```

The `request.onload` above actually specifies which function to use to handle the data when it comes back.

With the above code, you have finally succeeded and can finally connect to the Twitch API and get data from there! It's really gratifying. From now on, you will live a happy life with the skill of "connecting to the API"...

Not really.

## Same Origin Policy

Just when you thought you were already familiar with connecting to APIs and wanted to try connecting to other APIs, you found that a problem occurred with just one line:

![](/img/ajax/cors1.png)

```
XMLHttpRequest cannot load 
http://odata.tn.edu.tw/ebookapi/api/getOdataJH/?level=all. 
No 'Access-Control-Allow-Origin' header is present on the 
requested resource. Origin 'null' is therefore not allowed access.
```

Huh? Why is there this error?

In fact, for security reasons, the browser has something called the Same-origin policy.

This means that if the website you are currently on and the API website you want to call are "different sources", the browser will still help you send the request, but it will block the response, preventing your JavaScript from receiving it and returning an error.

What is a different source? Simply put, if the domain is different, it is a different source, or if one uses `http` and the other uses `https`, or if the port numbers are different, it is also a different source.

So if you are using someone else's API, in most cases it will be a different source.

I want to emphasize here that "your request is still sent", and the browser "does receive the response", but the key point is that "due to the same-origin policy, the browser does not pass the result back to your JavaScript". If there is no browser, there is actually no such problem. You can send it to whoever you want and get the response no matter what.

Okay, since we just said that different sources will be blocked, how did we successfully connect to the Twitch API?

## CORS

As we all know, it is very common to transfer data between different sources, just like we connect to the Twitch API. How can we be under the same domain as the Twitch API?

Therefore, the same-origin policy does regulate that non-same-origin requests will be blocked, but at the same time, there is another regulation that says: "If you want to transfer data between different origins, what should you do?" This regulation is called CORS.

CORS, short for Cross-Origin Resource Sharing, is a cross-origin resource sharing protocol.

This protocol tells you that if you want to open cross-origin HTTP requests, the server must add `Access-Control-Allow-Origin` to the response header.

You should be familiar with this field. If you feel unfamiliar, you can go back and look at the error message just now, which actually mentioned this header.

After the browser receives the response, it will first check the content of `Access-Control-Allow-Origin`. If it contains the origin of the request that is currently being initiated, it will allow it to pass and allow the program to receive the response smoothly.

If you carefully check the request we sent to Twitch in the beginning, you will find that the header of the response is roughly like this:

```
Content-Type: application/json
Content-Length: 71
Connection: keep-alive
Server: nginx
Access-Control-Allow-Origin: *
Cache-Control: no-cache, no-store, must-revalidate, private
Expires: 0
Pragma: no-cache
Twitch-Trace-Id: e316ddcf2fa38a659fa95af9012c9358
X-Ctxlog-Logid: 1-5920052c-446a91950e3abed21a360bd5
Timing-Allow-Origin: https://www.twitch.tv
```

The key point is this line: `Access-Control-Allow-Origin: *`, where the asterisk represents a wildcard character, meaning that any origin is accepted. Therefore, when the browser receives this response, it compares the current origin with the `*` rule, passes the verification, and allows us to accept the response of the cross-origin request.

In addition to this header, there are actually others that can be used, such as `Access-Control-Allow-Headers` and `Access-Control-Allow-Methods`, which can define which request headers and methods are accepted.

To sum up, if you want to initiate a cross-origin HTTP request and receive a response smoothly, you need to ensure that the server side has added `Access-Control-Allow-Origin`, otherwise the response will be blocked by the browser and an error message will be displayed.

## Preflight Request

Do you still remember Twitch's API documentation? It requires a `client-id` parameter, and the document says that you can pass it in the GET parameter or in the header. Let's try passing it in the header! Open Devtool, and you will see a magical phenomenon:

![](/img/ajax/cors2.png)

Huh? I clearly only sent one request, why did it become two? And the method of the first one is actually `OPTIONS`. Why did adding one header result in an extra request?

In fact, this is also related to CORS mentioned above. CORS divides requests into two types, one is a simple request. What is a simple request? There is actually a long definition, which I think you can read when you need it. But in short, if you don't add any custom headers, and it's a GET request, it's definitely a simple request (isn't this simple enough?).

On the contrary, if you add some custom headers, such as the `Client-ID` we just added, this request is definitely not a simple request.

(Definition reference: [MDN: Simple Request](https://developer.mozilla.org/zh-TW/docs/Web/HTTP/Access_control_CORS#簡單請求))

From the above classification, we know that the request we just initiated is not a simple request because it has a custom header. So why is there an extra request?

This request is called a Preflight Request, which is used to confirm whether subsequent requests can be sent because non-simple requests may contain some user data.

If this Preflight Request fails, the real request will not be sent, which is the purpose of the Preflight Request.

Let me give you an example, and you will know why this Preflight Request is needed. 

Assuming that a server provides an API URL called: `https://example.com/data/16`, you can get the data with id 16 by sending a GET request to it, and you can delete this data by sending a DELETE request to it.

If there is no Preflight Request mechanism, I can send a DELETE request to this API on any web page of any domain. As I emphasized earlier, the browser's CORS mechanism will still help you send the request, but only the response will be blocked by the browser.

Therefore, even though there is no response, the server did receive this request, so it will delete this data.

If there is a Preflight Request, when receiving the result of the request, it will know that this API does not provide CORS, so the real DELETE request will not be sent, and it will end here.

The purpose of the Preflight Request is to use an OPTIONS request to confirm whether the subsequent request can be sent.

## JSONP

Finally, let's talk about JSONP, which is another method for cross-origin requests besides CORS, called JSON with Padding.

Do you remember the same-origin policy mentioned at the beginning? If you think about it carefully, you will find that some things are not restricted by the same-origin policy, such as the `<script>` tag. Don't we often refer to third-party packages such as CDN or Google Analytics on web pages? The URLs are all from other domains, but they can be loaded normally.

JSONP uses this feature of `<script>` to achieve cross-origin requests.

Imagine you have an HTML like this:

``` html
<script>
  var response = {
    data: 'test'
  };
</script>
<script>
  console.log(response);
</script>
```

It's a very easy-to-understand piece of code, so I won't explain it much. What if you replace the above code with a URL?

``` html
<script src="https://another-origin.com/api/games"></script>
<script>
  console.log(response);
</script>
```

If the content returned by `https://another-origin.com/api/games` is the same as before:

``` js
var response = {
  data: 'test'
};
```

Then can't I get the data in the same way? And these data are still controlled by the server, so the server can give me any data. But using global variables like this is not very good. We can use the concept of Callback Function just mentioned and change it to this:

``` html
<script>
  receiveData({
    data: 'test'
  });
</script>
<script>
  function receiveData (response) {
    console.log(response);
  }
</script>
```

So what is JSONP? JSONP actually uses the above format to put data in `<script>` and bring the data back through the specified function. If you think of the first `<script>` as the server's return value, you will understand.

In practice, when operating JSONP, the server usually provides a `callback` parameter for the client to bring over. The Twitch API provides a JSONP version, and we can directly look at the example.

URL: `https://api.twitch.tv/kraken/games/top?client_id=xxx&callback=aaa&limit=1`

``` js
aaa({"_total":1069,"_links":{"self":"https://api.twitch.tv/kraken/games/top?limit=1","next":"https://api.twitch.tv/kraken/games/top?limit=1\u0026offset=1"},"top":[{"game":{"name":"Dota 2","popularity":63361,"_id":29595,"giantbomb_id":32887,"box":{"large":"https://static-cdn.jtvnw.net/ttv-boxart/Dota%202-272x380.jpg","medium":"https://static-cdn.jtvnw.net/ttv-boxart/Dota%202-136x190.jpg","small":"https://static-cdn.jtvnw.net/ttv-boxart/Dota%202-52x72.jpg","template":"https://static-cdn.jtvnw.net/ttv-boxart/Dota%202-{width}x{height}.jpg"},"logo":{"large":"https://static-cdn.jtvnw.net/ttv-logoart/Dota%202-240x144.jpg","medium":"https://static-cdn.jtvnw.net/ttv-logoart/Dota%202-120x72.jpg","small":"https://static-cdn.jtvnw.net/ttv-logoart/Dota%202-60x36.jpg","template":"https://static-cdn.jtvnw.net/ttv-logoart/Dota%202-{width}x{height}.jpg"},"_links":{},"localized_name":"Dota 2","locale":"zh-tw"},"viewers":65243,"channels":373}]})
```

URL: `https://api.twitch.tv/kraken/games/top?client_id=xxx&callback=receiveData&limit=1`

``` js
receiveData({"_total":1067,"_links":{"self":"https://api.twitch.tv/kraken/games/top?limit=1","next":"https://api.twitch.tv/kraken/games/top?limit=1\u0026offset=1"},"top":[{"game":{"name":"Dota 2","popularity":63361,"_id":29595,"giantbomb_id":32887,"box":{"large":"https://static-cdn.jtvnw.net/ttv-boxart/Dota%202-272x380.jpg","medium":"https://static-cdn.jtvnw.net/ttv-boxart/Dota%202-136x190.jpg","small":"https://static-cdn.jtvnw.net/ttv-boxart/Dota%202-52x72.jpg","template":"https://static-cdn.jtvnw.net/ttv-boxart/Dota%202-{width}x{height}.jpg"},"logo":{"large":"https://static-cdn.jtvnw.net/ttv-logoart/Dota%202-240x144.jpg","medium":"https://static-cdn.jtvnw.net/ttv-logoart/Dota%202-120x72.jpg","small":"https://static-cdn.jtvnw.net/ttv-logoart/Dota%202-60x36.jpg","template":"https://static-cdn.jtvnw.net/ttv-logoart/Dota%202-{width}x{height}.jpg"},"_links":{},"localized_name":"Dota 2","locale":"zh-tw"},"viewers":65622,"channels":376}]})
```

Have you noticed? It passes the `callback` parameter you brought over as the function name and passes the entire JavaScript object to the Function, so you can get the data inside the Function.

Combined, it would look like this:

``` html
<script src="https://api.twitch.tv/kraken/games/top?client_id=xxx&callback=receiveData&limit=1"></script>
<script>
  function receiveData (response) {
    console.log(response);
  }
</script>
```

Using JSONP, you can also access cross-origin data. However, the disadvantage of JSONP is that the parameters you need to pass can only be passed through the URL in a GET request, and cannot be passed through a POST request.

If CORS can be used, it should be prioritized over JSONP.

## Summary

The content of this article starts with the process of fetching data and tells you step by step where to fetch it and how to fetch it. If you want to fetch data using an API, what is an API? How to call Web API in JavaScript? How to access cross-origin data?

Generally speaking, I have mentioned everything related to fetching data with the front-end, but there is a regret that I did not mention the [Fetch API](https://developer.mozilla.org/en-US/docs/Web/API/Fetch_API), which is a newer standard used to fetch data. The introduction on MDN is:

> The Fetch API provides an interface for fetching resources (including across the network). It will seem familiar to anyone who has used XMLHttpRequest, but the new API provides a more powerful and flexible feature set.

Interested readers can check it out for themselves.

I hope that after reading this article, you will have a better understanding of how to connect to the back-end API and the difficulties you may encounter when connecting.
