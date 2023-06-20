---
title: "ReDoS: Attacks using regexp"
catalog: true
date: 2023-06-12 14:10:44
tags: [Security]
categories: [Security]
photos: /img/redos-regular-expression-denial-of-service/cover-en.png
---

Regular expressions (hereinafter referred to as regexp), are mainly used for string matching. After writing a pattern, it can be used to match text that meets the rules.

Whether it's a phone number, email, or ID number, regexp can be used to perform basic format validation to ensure that the string format matches specific rules.

Although regexp is convenient, if it is not written properly, it may cause some input validations to be bypassed and evolve into a security issue. In addition to this, there is another type of problem that will cause issues, which is ReDoS, the full name is: Regular expression Denial-of-Service, due to the denial of service attack caused by regular expressions.

<!-- more -->

Before talking about ReDoS, let's first mention what is DoS.

For example, suppose a website framework does not parse HTTP requests well and crashes when encountering special characters, causing the server to restart. At this time, attackers can continuously send such requests that will cause the website to crash, causing the server to keep restarting, which is a DoS attack.

If you want to divide it further, you can also divide it into which layer is being attacked, such as the network layer or the application layer, etc. This article is about attacks on the application layer.

Most of the attacks you see in network news are DDoS, with an additional D in front, meaning distributed, and most of them are attacks on the network layer. As can be seen from the DoS example we mentioned earlier, basically, it is because the website itself has problems, such as not considering special situations, etc., that attackers can use it, and DDoS is more like: "I will find a bunch of people to overload you regardless of whether you have problems or not."

To give a real-life example, suppose you run a snack shop that sells common items like dry noodles and boiled greens. Because it takes a lot of time to look at the customer's menu and what they ordered, and it feels impersonal to order with a mobile phone, you ordered a "menu reading robot" to help you look at the customer's order.

At this time, I deliberately drew symbols on the menu, but some places looked normal, making it difficult to read the menu, and the robot's recognition function was not done well and could not be interpreted, so it stopped. This is called DoS, exhausting resources with one's own strength.

I will find a hundred people to go to your place, and each person will draw a lot of blank menus and throw them to the robot, making the robot overwhelmed and unable to handle other customers' menus. This is called DDoS.

In short, DoS is usually "able to cause service interruption with a small amount of resources", while DDoS is "using a lot more resources to directly knock out your service."

Okay, let's talk about DoS. As can be seen from the example above, when your program itself has some problems, it is the easiest to have problems. If this premise is met, it is easy to use a simple method to knock out your service.

ReDoS relies on poorly written regular expressions to achieve this.

## Without further ado, let's take an example

The fastest way is to look at the example:

``` js
console.time('test');
/(a|a?)+$/.test('a'.repeat(25) +'b');
console.timeEnd('test');
// test: 2128.498046875 ms
```

A 26-character string takes 2 seconds to match. By the way, the time required for this regexp is calculated in multiples, and one more character requires 4 seconds, then 8 seconds, 16 seconds, and so on.

So why does this regexp take so long?

This is related to the implementation and principle of the regexp engine. I haven't studied the details yet, so I won't mislead the public. But simply put, the regexp engine must traverse all possibilities before it can find that the string does not match, so it takes so long.

In summary, if the regexp is not written well, it will consume a lot of time when used.

## Actual case

You may think, is it so easy to write regexp wrong?

Yes, a lot of libraries have had ReDoS vulnerabilities, and someone has compiled a detailed list: [Awesome ReDoS Security](https://github.com/engn33r/awesome-redos-security)

For example, CKEditor used to have a regexp that detects whether it is a picture URL. After passing in a carefully constructed string, it takes 6 seconds to execute:

``` js
// from: https://github.com/ckeditor/ckeditor5/commit/e36175e86b7f5ca597b39df6e47112b91ab4e0a0
const IMAGE_URL_REGEXP = new RegExp( String( /^(http(s)?:\/\/)?[\w-]+(\.[\w-]+)+[\w._~:/?#[\]@!$&'()*+,;=%-]+/.source +
    /\.(jpg|jpeg|png|gif|ico|webp|JPG|JPEG|PNG|GIF|ICO|WEBP)\??[\w._~:/#[\]@!$&'()*+,;=%-]*$/.source ) );

console.time('test');
IMAGE_URL_REGEXP.test('a.' + 'a'.repeat(100000))
console.timeLog('test')
// test: 6231.137939453125 ms
```

Although the length of the string is 100,000, if it is changed to a version without problems, the result can be obtained in less than 1 millisecond:

``` js
// from: https://github.com/ckeditor/ckeditor5/commit/e36175e86b7f5ca597b39df6e47112b91ab4e0a0
const IMAGE_URL_REGEXP = new RegExp( String( /^(http(s)?:\/\/)?[\w-]+\.[\w._~:/?#[\]@!$&'()*+,;=%-]+/.source +
    /\.(jpg|jpeg|png|gif|ico|webp|JPG|JPEG|PNG|GIF|ICO|WEBP)(\?[\w._~:/#[\]@!$&'()*+,;=%-]*)?$/.source ) );

console.time('test');
IMAGE_URL_REGEXP.test('a.' + 'a'.repeat(100000))
console.timeLog('test')
// test: 0.570068359375 ms
```

In JavaScript, these matching codes are all run on the main thread. If it is a webpage, the screen will freeze directly, and if it is executed with Node.js, the server will also be stuck and unable to handle other requests.

## How to know if there is a risk of ReDoS?

There are some ready-made tools that can help, and the one I use most often is this: https://devina.io/redos-checker

Just throw the regexp in, and it will tell you if there are any problems. If there are, it will even provide a test string for you to test again.

![devina redos checker](/img/redos-regular-expression-denial-of-service/p1.png)

However, sometimes there may be false positives, where it thinks there is a problem but there isn't, or there may actually be a problem, but the attack string it provides doesn't work. Therefore, it is still recommended to test the payload it provides again after testing to confirm.

## Application of ReDoS in attacks

The previous discussion was all about "the regexp is already written, and the user can control the input". In this case, all you have to do is find the problematic regexp and generate an attack string.

There is another situation where "the user can control the regexp". For example, suppose there is a website that provides a search function for users, and you can pass in a regexp, and the server will return whether there is a username that matches this regexp.

The server's implementation is roughly as follows (written arbitrarily, just to convey the idea):

``` js
app.get('/search', (req, res) => {
    const q = req.query.q
    return users
        .filter(user => new RegExp(q).test(user.username))
})
```

This dangerous function not only allows attackers to get all the usernames, but also has the risk of ReDoS.

For example, when `/((([^m]|[^m]?)+)+)+$/` encounters `"username"`, it takes nearly 4 seconds to complete:

``` js
console.time('test');
/((([^m]|[^m]?)+)+)+$/.test('username')
console.timeEnd('test');
// test: 3728.89990234375 ms
```

As long as you continue to extend the regexp in the same pattern, you can make this entire block of code run for more than 30 seconds or longer, paralyzing the entire server.

Another common situation when playing CTF is that you can also pass in a regexp, but the server won't tell you if it was successful. You can only judge based on the time difference, and ReDoS is very useful in this case:

``` js
console.time('CTF{a');
console.log(/CTF{[a](((((.*)*)*)*)*)!/.test('CTF{this_is_flag}'))
console.timeEnd('CTF{a');
// CTF{a: 0.071ms

console.time('CTF{t');
console.log(/CTF{[t](((((.*)*)*)*)*)!/.test('CTF{this_is_flag}'))
console.timeEnd('CTF{t');
// CTF{t: 24.577s
```

By passing in a carefully constructed regexp, you can use the time difference to know what the first character is.

Finally, a simple defense method is mentioned. The most fundamental solution is not to write flawed regexps. First, learn which patterns should be used as little as possible, and you can grasp the general direction. In addition, it seems that some people have done some automated tools to help scan the regexps that appear in the code, which is also a way to prevent problems before they occur.

## Summary

I personally think that ReDoS is a pretty interesting attack method. I never thought that such an effect could be achieved by relying on regexps.

The first time I learned about this attack, I seemed to be still a developer. I occasionally saw libraries with this vulnerability being used, but I didn't care much about it at the time. Later, I encountered this thing again in information security, and I felt that it was quite interesting.

This article is more like my personal notes, just wanting to record some payloads while the memory is still fresh, so it's easier to find them later.

Finally, here are some reference materials and further reading. Interested readers can take a look:

1. [HackTricks - Regular expression Denial of Service - ReDoS](https://book.hacktricks.xyz/pentesting-web/regular-expression-denial-of-service-redos)
2. [OWASP: Regular expression Denial of Service - ReDoS](https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS)
3. [snyk: ReDoS](https://learn.snyk.io/lessons/redos/javascript/)
