---
title: "The Most Difficult Cookie Problem I've Ever Encountered"
date: 2017-08-27 22:07
catalog: true
tags:
	- Cookie
categories:
	- Web
---
## Preface

A few weeks ago, I encountered some problems related to cookies at work. Before that, I thought to myself: "Cookies are just like that. Even if some attributes are not familiar, just search for information online. There are no difficult problems related to cookies, right?"

However, the fact proved me wrong. I really encountered a cookie problem that took me a long time to solve.

I believe that many people are eager to try it when they see this. So let me ask you first:

> Under what circumstances will cookies not be written?

Obvious syntax errors don't need to be mentioned. In addition to this, you may answer: writing cookies for a completely different domain. For example, your webpage is on `http://a.com`, but you insist on writing cookies for `http://b.com`. Of course, cookies cannot be written in this situation.

Or, you may answer: adding the `Secure` flag to cookies that are not on https. Yes, cookies in this situation cannot be written either.

Can you think of anything else?

If you can't think of anything, let me tell you!

<!-- more -->

## The Tragic Beginning

A month ago, I wrote an article related to CSRF because I needed to implement CSRF defense at work, so I took the opportunity to study it. In short, you need to set a `csrftoken` in the cookie.

But that day, I found that no matter how I wrote it, I couldn't write it in. The URL of my test website is: `http://test.huli.com`, and the script for writing cookies is:

``` js
document.cookie = "csrftoken=11111111; expires=Wed, 29 Mar 2020 10:03:33 GMT; domain=.huli.com; path=/"
```

I just wanted to write a cookie named `csrftoken` for `.huli.com`. The problem I encountered was that no matter how I wrote it, I couldn't write it in.

There is absolutely no problem with this syntax. I have checked it several times, but I don't know why it cannot be written in. We didn't encounter any of the cases we mentioned at the beginning. This is just a simple http website, and it writes cookies for its own domain. Why can't it be written in?

At first, when I encountered this situation, I thought it might be a supernatural phenomenon on my computer. It would be fine on other people's computers, so I didn't care about it temporarily until one day, the PM said to me: "Hey, what's wrong with this page?" After careful inspection, I found that it was because he couldn't write this cookie either, which caused the server to fail to receive `csrftoken` and the verification failed.

Okay, it seems that it is not a problem on my computer now, but everyone has this problem. However, there are other people who are normal. Everyone else can, but only two of us, me and the PM, can't.

Fortunately, I know that every time I encounter such strange problems, I should first open the incognito mode to see if your browser will be interfered with by other factors. After opening the incognito mode, I found that it worked. It can set cookies. It cannot be set under normal circumstances, but it can be set in incognito browsing mode.

This is really strange. Why can't it be set? Moreover, if I change the cookie to another name, such as `csrftoken2`, it can be written in! Only the name `csrftoken` cannot be written in. But cookies cannot have reserved words or anything like that! Even if there are, `csrftoken` is definitely not a reserved word.

All of this is too strange. What is wrong with the name `csrftoken`? Why can't it be written in?

So I went to Google, using keywords such as `cookie cannot be written`, `cookie can not set`, `unable set cookie`, etc., but I found nothing. The answers I found were completely different from my situation.

I looked at it with Chrome devtool, and there are no cookies on `http://test.huli.com`. How can't it be written in?

After a period of searching for information, I also went to check the rfc of cookies: [HTTP State Management Mechanism](https://tools.ietf.org/html/rfc6265), but still did not find relevant information.

Finally, I don't know where the inspiration came from. I went to the settings of Chrome to view all the cookies of `huli.com`, and after looking at them one by one, I deleted them. After deleting them, I could write cookies normally.

Thinking about it carefully, it's quite reasonable. After all, incognito mode works, which means that something done before will affect the writing of cookies. By deleting cookies, it can be confirmed that the problem must be on other related domains. It is speculated that other domains have done something that caused `http://test.huli.com` to be unable to write cookies.

Later, I recalled the few cookies I had just deleted and found that there was another cookie with the same name, `csrftoken`.

## Clearing the Clouds

Rarely did I find a clue, so I had to follow it.

I remembered that another website responsible for backend management was written at `https://admin.huli.com`. Because it uses [django](https://docs.djangoproject.com/en/1.10/ref/settings/#std:setting-CSRF_COOKIE_NAME), the default cookie name after enabling CSRF protection is `csrftoken`.

Looking carefully with Chrome devtool, this cookie was set to `Secure` and the domain was `.admin.huli.com`. There seemed to be nothing unusual.

However, after visiting this website, I tried to go to `http://test.huli.com` again and found that I couldn't write cookies, and even the original cookies disappeared mysteriously.

Great! It seems that I am getting closer to the truth!

After deleting this same-named cookie of `.admin.huli.com`, I visited my own `http://test.huli.com` and found that everything was normal. Cookies could be written normally.

It seems that the answer is obvious, which is:

> As long as the same-named cookie of `.admin.huli.com` exists, `http://test.huli.com` cannot write the same-named cookie of `.huli.com`.

The solution is actually very obvious at this point. The first is to change the cookie name, and the second is to change the domain.

Regarding the second solution, do you remember that we wrote a cookie with the domain `.huli.com` on `http://test.huli.com`? As long as it is changed to write to the domain `.test.huli.com`, it can still work normally.

So if we explain it in more detail, the problem of not being able to write cookies occurs when:

> When a cookie with a domain of `.admin.huli.com` and `Secure` flag is already set, `http://test.huli.com` cannot write the same-named cookie of `.huli.com`.

After roughly confirming the problem, I began to adjust various variables to see if I could find out which link had a problem. Finally, I found two key points:

1. Only Chrome cannot write, Safari and Firefox can.
2. If the `Secure` flag is not set, it can be written.

## In-depth Investigation

Since there is such a powerful clue that only Chrome will have this situation, we can continue to investigate along this line. How to investigate?

Yes, it is the simplest and most direct method: find the source code of Chromium!

I have read many articles before that check the problem and finally find the source code. Finally, it's my turn. But Chromium's source code is so large, how should I start?

So I decided to Google: `chromium cookie` and found very helpful information in the first search result: [CookieMonster](https://www.chromium.org/developers/design-documents/network-stack/cookiemonster). This article explains in detail how Chromium's cookie mechanism works and explains that the core is something called `CookieMonster`.

Then you can go directly to see the source code, and you can find [cookie_monster.cc](https://chromium.googlesource.com/chromium/src/+/master/net/cookies/cookie_monster.cc) in `/net/cookies`.

Do you remember one of the key points discovered just now, which is related to the `Secure` flag? So I directly searched with `Secure` as the keyword and found a `DeleteAnyEquivalentCookie` function in the middle. The following is an excerpt from [part of the source code](https://chromium.googlesource.com/chromium/src/+/master/net/cookies/cookie_monster.cc#1625), from line 1625 to line 1647:

``` c
// If the cookie is being set from an insecure scheme, then if a cookie
// already exists with the same name and it is Secure, then the cookie
// should *not* be updated if they domain-match and ignoring the path
// attribute.
//
// See: https://tools.ietf.org/html/draft-ietf-httpbis-cookie-alone
if (cc->IsSecure() && !source_url.SchemeIsCryptographic() &&
    ecc.IsEquivalentForSecureCookieMatching(*cc)) {
  skipped_secure_cookie = true;
  histogram_cookie_delete_equivalent_->Add(
      COOKIE_DELETE_EQUIVALENT_SKIPPING_SECURE);
  // If the cookie is equivalent to the new cookie and wouldn't have been
  // skipped for being HTTP-only, record that it is a skipped secure cookie
  // that would have been deleted otherwise.
  if (ecc.IsEquivalent(*cc)) {
    found_equivalent_cookie = true;
    if (!skip_httponly || !cc->IsHttpOnly()) {
      histogram_cookie_delete_equivalent_->Add(
          COOKIE_DELETE_EQUIVALENT_WOULD_HAVE_DELETED);
    }
  }
} 
```

Here's a helpful note that says:

> If a cookie comes from an insecure scheme and there is already a cookie with the same name that is set to Secure and domain-match, then this cookie should not be set.

Although I don't quite understand what `domain-match` means, it seems that the problem we encountered with not being able to write to the cookie occurred in this section. The reference material is also thoughtfully attached: https://tools.ietf.org/html/draft-ietf-httpbis-cookie-alone
The title is "Deprecate modification of 'secure' cookies from non-secure origins."

The content is not long and can be quickly read. Here's an excerpt from a small section:

```
Section 8.5 and Section 8.6 of [RFC6265] spell out some of the
drawbacks of cookies' implementation: due to historical accident,
non-secure origins can set cookies which will be delivered to secure
origins in a manner indistinguishable from cookies set by that origin
itself.  This enables a number of attacks, which have been recently
spelled out in some detail in [COOKIE-INTEGRITY].
```

The reference material is this: [Cookies Lack Integrity: Real-World Implications](https://www.usenix.org/conference/usenixsecurity15/technical-sessions/presentation/zheng), which includes a 20-minute video that you can watch to understand why writing to the cookie is not allowed.

If you haven't watched it yet, here's a summary. To understand why the case at the beginning cannot write to the cookie, think about what would happen if it could be written to.

If `http://test.huli.com` successfully writes the `.huli.com` `csrftoken` cookie, it doesn't seem to have any impact on `http://test.huli.com`, it just adds another cookie, which seems reasonable.

However, it has some impact on `https://admin.huli.com`.

The original `.admin.huli.com` and `Secure` cookie will still be there, but now there is an additional `.huli.com` cookie with the same name. When `https://admin.huli.com` sends a request, both cookies will be sent together. So when the server receives it, it may look like this:

```
csrftoken=cookie_from_test_huli_com; csrftoken=cookie_from_admin_huli_com
```

But when encountering cookies with the same name, many people will only process the first one, so the `csrftoken` received by the server side will be `cookie_from_test_huli_com`.

This means that even though you wrote a cookie in a `Secure` way on `https://admin.huli.com`, it was overwritten by another insecure source (`http://test.huli.com`)!

What can be done with overwritten cookies? Here are a few examples given in the reference material (but I'm not sure if I understand them correctly, so please correct me if I'm wrong). The first is Gmail's window, which is divided into two parts, one is the mailbox, and the other is Hangouts. Attackers can use the method mentioned above to overwrite the user's cookie with their own session cookie. However, because Hangouts and Gmail have different domains, Gmail still uses the user's account, but Hangouts has become the attacker's account.

The attacked person is likely to unknowingly use the attacker's account to send messages, and the attacker can see those messages.

The second example is a bank's website. If the session cookie is replaced with the attacker's when the user wants to add a credit card, then this credit card will be added to the attacker's account!

In short, all of these are methods of attacking by masking the original cookie and allowing the server side to use a new cookie.

## Summary

When I first encountered this problem, I was really troubled because I couldn't figure out why a completely correct syntax command couldn't be written into the cookie, and I rarely use the website `https://admin.huli.com`, so I didn't think it was the problem.

However, after solving the problem and looking back, there were some clues during the process. For example, it can be inferred from the fact that "clearing the cookie will solve the problem" that there is interference with other cookies, and it can also be inferred from the fact that it can be written into other browsers that there are some mechanisms in Chrome.

Each clue in the process will lead you to a new path. As long as you persist, you will definitely be able to successfully navigate the maze.
