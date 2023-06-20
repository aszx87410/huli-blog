---
title: '[Experience] Struggling with DDoS: nginx, iptables and fail2ban'
date: 2016-07-21 16:38
catalog: true
tags: [Story,Server,DDoS]
categories:
  - Back-end
---
Recently, there was an incident where our server was attacked by a large number of requests. Unfortunately, the server was hosting a forum service. Assuming that the attack point was the forum homepage, each request would query the database and there were a lot of joins. Some of the instructions were POST, which would update the database. This caused the database to lock up and the CPU to skyrocket, leading to a crash.

If the forum was self-written, we could add a cache like Redis between the database and application. However, this forum system is someone else's and we cannot modify it.

<!-- more -->

First, let me briefly explain the architecture. In order to distribute traffic, there is an AWS ELB in front of two machines doing load balancing. All requests go to the ELB first and then automatically to one of the two machines in the back.

What should we do after being attacked? The first thing that comes to mind is to use the service provided by AWS: WAF to block it.
https://aws.amazon.com/tw/waf/

However, it was found that WAF was different from what was originally thought. It cannot set rules like "block IPs that send more than 100 requests within 10 seconds". We can only continue to find solutions on the Internet and found a solution to block it from nginx:

[nginx防止DDOS攻击配置](https://www.52os.net/articles/nginx-anti-ddos-setting.html)
[通过Nginx和Nginx Plus阻止DDoS攻击](http://www.infoq.com/cn/news/2016/01/Nginx-AntiDDoS)
[Module ngx_http_limit_req_module](http://nginx.org/en/docs/http/ngx_http_limit_req_module.html)
```
http {

  //Trigger condition, limit IP to 10 requests per second
  limit_req_zone $binary_remote_addr zone=one:10m rate=10r/s; 
  
  server {
    location  ~ \.php$ {

      //Action to be executed
      limit_req zone=one burst=5 nodelay;   
    }
  }
}
```

In short, we use `limit_req_zone`, which is provided by nginx, to declare a zone called `one` that stores the state with a size of 10mb. Here, `10r/s` means 10 requests per second.

Then add `limit_req zone=one burst=5 nodelay;` where you want to block it, and it will be blocked. Nginx will adjust the number of requests processed to "up to 10 per second". If an IP has more than 5 requests that have not been processed at the same time, it will return `503 service temporarily unavailable`. The value of 5 here is set by `burst`. The returned status code can also be specified by yourself, for example: `limit_req_status 505;`

Although this solution looks great, for some reason, it seems to have no effect after adding it. The server alarm is still ringing, and the database is still skyrocketing.

After consulting with other colleagues, it was learned that iptables can also block it, and it is directly blocked from the TCP layer. I found the following two pieces of information:

[淺談DDoS攻擊防護](http://blog.eztable.com/2011/05/17/how-to-prevent-ddos/)
```
-A INPUT -p tcp –dports 80 -j WEB_SRV_DOS
-A WEB_SRV_DOS -p tcp –syn –dports 80 -m recent –rcheck –second 30 –hitcount 200 -j LOG –log-prefix "[Possible DOS Attack]"
-A WEB_SRV_DOS -p tcp –syn –dports 80 -m recent –rcheck –second 30 –hitcount 200 -j REJECT  
-A WEB_SRV_DOS -p tcp –syn –dports 80 -m recent –set  
-A WEB_SRV_DOS -p tcp –dports 80 -j ACCEPT
```

[Limiting the number of connections from the same IP within a certain time using iptables](http://ishm.idv.tw/?p=188)

```
-A INPUT -p tcp --dport 80 -m recent --rcheck --seconds 1 --hitcount 5 --name HTTP_LOG --rsource -j DROP
-A INPUT -p tcp --dport 80 -m recent --set --name HTTP_LOG --rsource
-A INPUT -p tcp --dport 80 -j ACCEPT
```

The principles of the two are the same, using the `-m recent --rcheck --second 30 --hitcount 200` statement to describe how many requests to block within a few seconds, and reject or drop the connection.

Blocking directly from iptables sounds like a better solution, so that requests won't even go into nginx and will be blocked. But unfortunately, after trying it out, it still didn't work! How could this be?

Discouraged, a colleague recommended a good tool called fail2ban. After checking it out, I found that it was very easy to use and the principle was easy to understand. I decided to test it on another machine and then apply it to the formal environment machine after successful testing.

[Preventing brute force attacks with Fail2Ban (SSH, vsftp, dovecot, sendmail)](http://www.vixual.net/blog/archives/252)
[fail2ban tutorial](http://blog.vic.mh4u.org/2011/272)
[Using fail2ban in Ubuntu to judge and block large amounts of access](http://chuhw.pixnet.net/blog/post/167657289-ubuntu-%E4%B8%AD%E4%BD%BF%E7%94%A8-fail2ban-%E9%87%9D%E5%B0%8D%E5%A4%A7%E9%87%8F-access-%E5%81%9A%E5%88%A4%E6%96%B7%E5%8F%8A%E9%98%BB%E6%93%8B)

Combining the descriptions of several of them, the following process can be obtained:

1. Modify `vim /etc/fail2ban/jail.local`
2. Write
```
[http-get-dos]
enabled = true
port = http
filter = http-get-dos
logpath = /var/log/nginx/access.log # log to be judged
maxretry = 100 # maximum number of times
findtime = 5 # time interval
bantime = 600 # how long to ban
action = iptables[name=HTTP, port=http, protocol=tcp]
```
The above rule is: try 100 times within 5 seconds and ban for 600 seconds after failure.

3. Add `/etc/fail2ban/filter.d/http-get-dos.conf`
The file name here corresponds to the name set in `jail.local` just now.
```
[Definition]
failregex = ^<HOST>- - .*\"(GET|POST).*
ignoreregex =
```
The `failregex` here should be written according to your log. For example, the nginx access log looks like this:
```
106.184.3.122 - - [21/Jul/2016:11:38:29 +0000] "GET / HTTP/1.1" 200 396 "-" "Go-http-client/1.1"
```
You can write a regular expression that can capture `<HOST>`, which is the IP.

After all the settings are done, restart it and it should work. You will find that after sending requests continuously, you will be banned. You can use `iptables --list` to see if you have really been banned.

The principle of fail2ban should be to look at the log file and rules you specified, use this file to determine whether it exceeds the set rules, and if it exceeds, extract the IP and add the rules to iptables to block it. After the time is up, remove the rules.

At this point, it finally succeeded! But since the principle is also iptables, why didn't it work just now?
Remember that I mentioned the server architecture at the beginning? One ELB in front and two web servers behind. Because ELB is a service provided by AWS, the customization is very low, and even ssh cannot be used. Therefore, the solutions attempted above are individually applied to those two web servers.

Then the problem arises:
> Huh? Then the source of the web server's request is all ELB's IP, right?

That's right, you've overcome the blind spot! The reason it didn't work before was because you used iptables to block the traffic, but since the source is all ELB's IP, it only blocks ELB, not the real attacker. This causes the ELB to be blocked, and the entire service becomes super slow because of one attacker.

So in this network environment, iptables won't work! What about nginx? Do you remember our rule?
```
limit_req_zone $binary_remote_addr zone=one:10m rate=10r/s; 
```
`$binary_remote_addr` will also capture ELB's IP.

At this point, a sudden inspiration came to mind. Can we set it based on the `X-Forwarded-For` header? Then it will be the real IP. Found this article: [nginx rate limiting with X-Forwarded-For header](http://serverfault.com/questions/487463/nginx-rate-limiting-with-x-forwarded-for-header)

Replace `$binary_remote_addr` with `$http_x_forwarded_for`.

Done! After experiencing a lot of hardships, the attack traffic was finally blocked in nginx. After testing with [JMeter](http://jmeter.apache.org/), it was found that it was indeed successful, and the extra requests will directly return 503. It's really gratifying.
