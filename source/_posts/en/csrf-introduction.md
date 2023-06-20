---
title: "Let's talk about CSRF"
date: 2017-03-12 20:47
catalog: true
header-img: "/img/header_img/article-bg.png"
tags: [Front-end,Back-end,CSRF]
categories:
  - Front-end
---
## Introduction

Recently, I encountered some cases of CSRF and took the opportunity to study it thoroughly. After in-depth research, I found that this attack is actually quite scary because it is easy to overlook. Fortunately, some frameworks now have built-in CSRF defense functions that can be easily enabled.

However, I still think it is necessary to understand what CSRF is, how it attacks, and how to defend against it. Let's start by briefly introducing it!

CSRF is a type of attack on the web, which stands for Cross Site Request Forgery. Don't confuse it with XSS, they are two different things. So what is CSRF? Let's start with an example of my own.

<!-- more -->

## Lazy deletion function
I used to have a simple backend page, which can be considered as a blog! You can publish, delete, and edit articles, and the interface looks like this:

![](/img/csrf/csrf1.png)

You can see the delete button, which can delete an article when clicked. At that time, because I was lazy, I thought that if I made this function into GET, I could complete the deletion with just a link, and I hardly needed to write any code on the front end:

``` html
<a href='/delete?id=3'>Delete</a>
```

Very convenient, right? Then I did some verification on the backend of the webpage to verify whether the request carried the session id and whether the article was written by the author of this id. If they all match, the article will be deleted.

Well, it sounds like I have done everything I should do: "Only the author himself can delete his own article", so it should be safe. Is there anything missing?

Yes, it is indeed "Only the author himself can delete his own article", but what if he does not "actively delete" it, but deletes it without knowing it? You may think I am talking about something, how can someone delete it if it is not the author who actively deletes it?

Okay, let me show you how it can be deleted!

Today, let's assume that Xiaohei is an evil villain who wants Xiaoming to delete his own article without knowing it. How to do it?

He knows that Xiaoming likes psychological tests, so he made a psychological test website and sent it to Xiaoming. But the difference between this psychological test website and other websites is that the "Start Test" button looks like this:

``` html
<a href='https://small-min.blog.com/delete?id=3'>Start Test</a>
```

After Xiaoming receives the webpage, he is very happy and clicks "Start Test". After clicking, the browser will send a GET request to `https://small-min.blog.com/delete?id=3`, and because of the operation mechanism of the browser, all the cookies of `small-min.blog.com` will be sent together. 

After receiving the request, the server checks the session and finds that it is Xiaoming, and this article is indeed written by Xiaoming, so it deletes the article.

This is CSRF. You are clearly on the psychological test website, let's say it is `https://test.com`, but you unknowingly deleted the article of `https://small-min.blog.com`. Isn't it terrible? Super scary!

This is also why CSRF is also called a one-click attack. You are hit by just one click.

You may say: "But Xiaoming will know it, won't he? He will go to the blog, won't he?"

Okay, what if we change it to this:

``` html
<img src='https://small-min.blog.com/delete?id=3' width='0' height='0' />
<a href='/test'>Start Test</a>
```

At the same time as opening the page, a deletion request is sent out, but this time Xiaoming really has no idea about it. This is in line with it!

CSRF is a way to forge a "request sent by the user himself" under different domains. To achieve this, it is very simple. Because of the mechanism of the browser, as long as you send a request to a certain domain, the associated cookies will be sent together. If the user is logged in, then this request naturally contains his information (such as session id), and this request looks like it was sent by the user himself.

## Can't I just change the deletion to POST?
Yes, smart! Let's not be so lazy and make the deletion function into POST, so that it cannot be attacked through `<a>` or `<img>`, right? Unless there is an HTML element that can send a POST request!

There is a form called "form".

``` html
<form action="https://small-min.blog.com/delete" method="POST">
  <input type="hidden" name="id" value="3"/>
  <input type="submit" value="Start Test"/>
</form>
```

After Xiao Ming clicked it, he was still tricked and the article was deleted. You may wonder, but doesn't Xiao Ming know now? I was also skeptical, so I Googled and found this article: [Example of silently submitting a POST FORM (CSRF)](http://stackoverflow.com/questions/17940811/example-of-silently-submitting-a-post-form-csrf)

The example provided in this article is as follows. The world of web pages is really vast and profound:

``` html
<iframe style="display:none" name="csrf-frame"></iframe>
<form method='POST' action='https://small-min.blog.com/delete' target="csrf-frame" id="csrf-form">
  <input type='hidden' name='id' value='3'>
  <input type='submit' value='submit'>
</form>
<script>document.getElementById("csrf-form").submit()</script>
```

Open an invisible iframe, let the result after form submit appear in the iframe, and this form can also be automatically submitted, without any operation by Xiao Ming.

At this point, you know that changing to POST is useless.

## What if I change the backend to only accept JSON?

You had a bright idea: "Since only form can submit POST on the front end, can't I change my API to receive data with JSON? Then form can't be used, right?"

[spring's document](https://docs.spring.io/spring-security/site/docs/current/reference/html/csrf.html) tells you: this is still useless!

``` html
<form action="https://small-min.blog.com/delete" method="post" enctype="text/plain">
<input name='{"id":3, "ignore_me":"' value='test"}' type='hidden'>
<input type="submit"
  value="delete!"/>
</form>
```

This will generate the following request body:

``` js
{ "id": 3,
"ignore_me": "=test"
}
```

However, it is worth noting here that `form` can only carry three types of content types: `application/x-www-form-urlencoded`, `multipart/form-data`, and `text/plain`. In the above attack, we used the last one, `text/plain`. If your backend server checks this content type, you can avoid the above attack.

The example we gave was deleting an article, which you may think is not a big deal. But what if it's a bank transfer? Attackers can write code on their own web pages to transfer money to their own accounts, and then spread this web page to receive a lot of money.

After talking so much, let's talk about how to defend! Let's start with the simplest "user".

## User's defense

The reason why CSRF attacks can succeed is that the user is in a logged-in state on the attacked web page, so they can take some actions. Although these attacks should be handled by the web page, if you are really afraid that the web page will not handle them well, you can log out every time you use the website to avoid CSRF.

Alternatively, turning off js execution or filtering out the code of these patterns not to execute is also a method (but it should be difficult to determine which code is the code of CSRF attack).

So what users can do is actually limited. The server side is the one that really needs to do something!

## Server's defense

The reason why CSRF is scary is because of the two letters CS: Cross Site. You can launch attacks under any URL. The defense against CSRF can be thought from this direction, in short: "How can I block requests from other domains."

Think about it carefully, what is the difference between a CSRF request and a request made by the user? The difference lies in the domain. The former is sent from any domain, while the latter is sent from the same domain (assuming that your API and frontend website are on the same domain).

### Check Referer

The request header contains a field called "referer", which indicates where the request came from. You can check this field to see if it is a valid domain. If it is not, you can reject it. 

However, there are three things to note about this method. First, some browsers may not include the referer field. Second, some users may disable the automatic inclusion of the referer field, which would cause your server to reject requests made by real users. 

The third thing to note is that the code that determines whether a domain is valid must be bug-free. For example:

``` js
const referer = request.headers.referer;
if (referer.indexOf('small-min.blog.com') > -1) {
  // pass
}
```

Do you see the problem with the above code? If the attacker's webpage is `small-min.blog.com.attack.com`, your check will fail.

Therefore, checking the referer is not a very complete solution.

### Add Captcha, SMS Verification, etc.

Just like when transferring money on online banking, you are required to receive an SMS verification code. Adding this extra check can ensure that you are not attacked by CSRF.

The same goes for captcha. Attackers do not know the answer to the captcha, so they cannot attack.

This is a very complete solution, but if users have to enter a captcha every time they delete a blog, they will probably be annoyed!

### Add CSRF Token

To prevent CSRF attacks, we just need to ensure that some information is "known only to the user". How do we do that?

We add a hidden field called `csrftoken` to the form. The value of this field is randomly generated by the server and stored in the server's session.

``` html
<form action="https://small-min.blog.com/delete" method="POST">
  <input type="hidden" name="id" value="3"/>
  <input type="hidden" name="csrftoken" value="fj1iro2jro12ijoi1"/>
  <input type="submit" value="Delete Post"/>
</form>
```

After submitting the form, the server compares the `csrftoken` in the form with the one stored in its session. If they are the same, it means that this is indeed a request made by the user. This `csrftoken` is generated by the server and should be changed for each different session.

Why does this work? Because the attacker does not know the value of the `csrftoken`, they cannot guess it and therefore cannot attack.

However, there is another scenario. What if your server supports cross-origin requests? What happens then? The attacker can make a request on their page, successfully obtain the CSRF token, and launch an attack. But this is only possible if your server accepts requests from that domain.

Now let's take a look at another solution.

### Double Submit Cookie

The previous solution requires server state, i.e. the CSRF token must be stored on the server to verify its correctness. The advantage of this solution is that it does not require the server to store anything.

The first half of this solution is similar to the previous one. The server generates a random token and adds it to the form. But the difference is that, in addition to not having to write this value in the session, the client side also sets a cookie named `csrftoken` with the same token value.

``` html
Set-Cookie: csrftoken=fj1iro2jro12ijoi1

<form action="https://small-min.blog.com/delete" method="POST">
  <input type="hidden" name="id" value="3"/>
  <input type="hidden" name="csrftoken" value="fj1iro2jro12ijoi1"/>
  <input type="submit" value="Delete Post"/>
</form>
```

You can think carefully about the differences between a CSRF attack request and a request made by the user. The difference lies in the fact that the former comes from a different domain, while the latter comes from the same domain. So as long as we can distinguish whether this request comes from the same domain, we win.

And the Double Submit Cookie solution is based on this idea.

When the user presses submit, the server compares the csrftoken in the cookie with the csrftoken in the form to check if they have a value and are equal, to know if it is from the user.

Why? Suppose an attacker wants to attack now. He can write a csrf token in the form at will, which is of course no problem, but because of the browser's restrictions, he cannot set the cookie of `small-min.blog.com` on his domain! So the csrftoken in the cookie of the request he sends up will not exist, and it will be blocked.

Of course, this method seems to be useful, but it also has its drawbacks, as can be seen in [Double Submit Cookies vulnerabilities](http://security.stackexchange.com/questions/59470/double-submit-cookies-vulnerabilities). If the attacker controls any of your subdomains, he can help you write cookies and successfully attack you.

### Client-side Double Submit Cookie

The reason why client-side is mentioned specifically is that the project I previously encountered was a Single Page Application. Searching the web, you will find people asking, "How can SPA get CSRF token?" Do you need to provide another API from the server? This seems a bit strange.

However, I think we can use the spirit of Double Submit Cookie to solve this problem. The key to solving this problem is to generate the csrf token from the client-side. There is no need to interact with the server API.

The other processes are the same as before, generating and putting it into the form and writing it to the cookie. Or if you are an SPA, you can also directly put this information in the request header, and you don't have to do this for every form, just add it in one place.

In fact, the library I often use, [axios](https://github.com/mzabriskie/axios), provides such a function. You can set the header name and cookie name. After setting it up, every request it sends will automatically fill in the value in the cookie for you.

```
 // `xsrfCookieName` is the name of the cookie to use as a value for xsrf token
xsrfCookieName: 'XSRF-TOKEN', // default

// `xsrfHeaderName` is the name of the http header that carries the xsrf token value
xsrfHeaderName: 'X-XSRF-TOKEN', // default
```

Why can this token be generated by the client? Because the purpose of this token itself does not contain any information, it is just to prevent "attackers" from guessing, so it doesn't matter whether it is generated by the client or the server, as long as it is not guessed. The core concept of Double Submit Cookie is: "Attackers cannot read and write cookies of the target website, so the csrf token of the request will be different from that in the cookie."

### Browser's own defense

We just mentioned what users can do, what web front-end and back-end can do, what about browsers? The reason why CSRF can exist is due to the mechanism of the browser. Is it possible to solve this problem from the browser side?

Yes! And it already exists. And the method of enabling it is very, very simple.

Google officially added this feature in Chrome 51: [SameSite cookie](https://www.chromestatus.com/feature/4672634709082112). For those interested in the detailed operation principle, please refer to [draft-west-first-party-cookies-07](https://tools.ietf.org/html/draft-west-first-party-cookies-07).

First, let's quote Google's explanation:

Enabling this feature is very simple. 

Your original cookie header looks like this:

```
Set-Cookie: session_id=ewfewjf23o1;
```

You just need to add `SameSite` at the end:

```
Set-Cookie: session_id=ewfewjf23o1; SameSite
```

However, there are two modes for `SameSite`: `Lax` and `Strict`, with the latter being the default. You can also specify the mode yourself:

```
Set-Cookie: session_id=ewfewjf23o1; SameSite=Strict
Set-Cookie: foo=bar; SameSite=Lax
```

Let's first talk about the default `Strict` mode. When you add the `SameSite` keyword, it means "this cookie can only be used by the same site and should not be added to any cross-site requests". 

This means that after you add it, all the `<a href="">`, `<form>`, and `new XMLHttpRequest` requests that are not verified by the browser to be initiated from the same site will not carry this cookie.

However, this will cause a problem. If even `<a href="...">` does not carry the cookie, when I click on a link from a Google search result or a link shared by a friend to enter a website, because the cookie is not carried, the website will become logged out. This is a very bad user experience.

There are two solutions. The first is like Amazon, where two sets of different cookies are prepared. The first set is used to maintain the login status, and the second set is used for sensitive operations (such as purchasing, account settings, etc.). The first set does not set `SameSite`, so no matter where you come from, you will be logged in. However, even if the attacker has the first set of cookies, they cannot do anything because they cannot perform any operations. The second set completely avoids CSRF because of the `SameSite` setting.

But this is still a bit troublesome, so you can consider the second solution, which is to adjust to the other mode of `SameSite`: `Lax`.

The Lax mode relaxes some restrictions. For example, `<a>`, `<link rel="prerender">`, and `<form method="GET">` will still carry the cookie. However, forms with POST methods or any methods such as POST, PUT, DELETE will not carry the cookie.

So on the one hand, you can maintain flexibility, allowing users to maintain their login status when entering your website from other websites, and on the other hand, you can prevent CSRF attacks. However, under the `Lax` mode, GET-based CSRF cannot be blocked, so this should be noted.

Speaking of this relatively new feature, I believe everyone is very interested in how well it is supported by browsers. [caniuse](http://caniuse.com/#search=samesite) tells us that currently only Chrome supports this new feature (after all, it is Google's own solution, so they naturally support it).

Although the browser support is not very high, other browsers may also implement this feature in the future, so it is worth adding `SameSite` now and not worrying about CSRF in the future.

I just briefly introduced it. [draft-west-first-party-cookies-07](https://tools.ietf.org/html/draft-west-first-party-cookies-07) discusses many details, such as what exactly is considered cross-site? Must it be on the same domain? Can subdomains be used?

You can study it yourself, or this article: [SameSite Cookie, Preventing CSRF Attacks](http://www.cnblogs.com/ziyunfei/p/5637945.html) also mentions it.

References related to SameSite:
1. [Preventing CSRF with the same-site cookie attribute](https://www.sjoerdlangkemper.nl/2016/04/14/preventing-csrf-with-samesite-cookie-attribute/)
2. [Goodbye, CSRF: Explaining the SameSite property in set-cookie](http://bobao.360.cn/learning/detail/2844.html)
3. [SameSite Cookie, Preventing CSRF Attacks](http://www.cnblogs.com/ziyunfei/p/5637945.html)
4. [SameSite - A new mechanism to prevent CSRF & XSSI](https://rlilyyy.github.io/2016/07/10/SameSite-Cookie%E2%80%94%E2%80%94%E9%98%B2%E5%BE%A1-CSRF-XSSI/)
5. [Cross-Site Request Forgery is dead!](https://scotthelme.co.uk/csrf-is-dead/)

## Summary

This article mainly introduces the attack principle of CSRF and two defense methods, focusing on common scenarios. When developing web pages, CSRF is a more commonly overlooked focus than XSS. When there are any important operations on the web page, special attention should be paid to whether there is a risk of CSRF.

This time, I found a lot of reference materials, but I found that articles related to CSRF are actually similar. If you want to know more details, you need to spend a lot of effort to find them, but fortunately, there are also many materials on Stackoverflow that can be referenced. Because I haven't delved too much into information security, if there is any part of the article that is wrong, please feel free to point it out in the comments.

I would also like to thank my friend shik for his guidance, telling me that there is such a thing as SameSite, which allows me to add the last paragraph.

I hope this article can give everyone a more comprehensive understanding of CSRF.

## References
1. [Cross-Site Request Forgery (CSRF)][1]
2. [Cross-Site Request Forgery (CSRF) Prevention Cheat Sheet][2]
3. [A more profound understanding of CSRF](http://m.2cto.com/article/201505/400902.html)
4. [[Technical Sharing] Cross-site Request Forgery (Part 2)](http://cyrilwang.pixnet.net/blog/post/31813672)
5. [Spring Security Reference](http://docs.spring.io/spring-security/site/docs/3.2.5.RELEASE/reference/htmlsingle/#csrf)
6. [Countermeasures for CSRF attacks](https://www.ibm.com/developerworks/cn/web/1102_niugang_csrf/)

[1]: https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)#Prevention_measures_that_do_NOT_work
[2]: https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)_Prevention_Cheat_Sheet
