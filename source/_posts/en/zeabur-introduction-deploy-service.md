---
title: Zeabur - A New Choice for Website Deployment 
date: 2024-04-14 11:40:00
catalog: true
tags: [Web]
categories: [Web]
photos: /img/zeabur-introduction-deploy-service/cover-en.png
---

In the past, when I wanted to deploy a simple service, I would go to Heroku because it was simple and free, although there were some usage restrictions, overall it was very convenient, and there were even some simple databases available. For static web pages, I would choose Netlify or GitHub Pages, both of which are simple and convenient options.

However, Heroku stopped offering free plans after the end of 2022, so many people were looking for alternative solutions, including Render or fly[dot]io, which became popular choices for many. I used to have three or four projects on Heroku myself, but after the changes at Heroku, I never touched them again.

Recently, I received an email from the founder of [Zeabur](https://zeabur.com) hoping to collaborate with me to promote this platform. After trying it out myself, I found the experience to be quite good, so I decided to write this article to introduce it.

<!-- more -->

## Zeabur First Impressions

Zeabur is a service that helps you deploy websites quickly, emphasizing simplicity and speed, requiring almost no additional configuration to successfully deploy.

I had heard about Zeabur for some time, but never had the chance to use it. This time, since I was considering a collaboration, I decided to use it for some projects that were previously on Heroku but had become inactive.

When adding a new app in the Zeabur dashboard, you can choose how to deploy it:

![Choose Deployment Method](/img/zeabur-introduction-deploy-service/p1-en.png)

I chose the most convenient option, GitHub, and then provided authorization for it to access my repository, and that was it.

Yes, it was really that simple.

After selecting the repository name, the build and deployment process started automatically, and within a minute or two, I could see it was running:

![Deployment Completed](/img/zeabur-introduction-deploy-service/p2-en.png)

After it was up and running, remember to set a public domain under the "Network" section to access it:

![Set Domain](/img/zeabur-introduction-deploy-service/p3-en.png)

I tried two projects that were previously on Heroku, one was written in Node.js, and the other was pure PHP (without any frameworks). Both projects started the subsequent processes automatically with just a click, and it was done.

Honestly, this experience was quite impressive, a true one-click deployment. I remember when using Heroku, after creating an app, I had to download the Heroku CLI, run a command, and push the code to start the deployment. In comparison, Zeabur's experience was much better (perhaps Heroku has a similar mechanism now, but I haven't used it since switching).

This smooth user experience was the main reason I agreed to collaborate.

## Pricing

Zeabur's pricing is quite complex, details can be found on this page: https://zeabur.com/pricing

Starting with the free version, it only supports static websites (similar to GitHub Pages) and serverless functions (like AWS Lambda). I don't find the static website part very appealing because honestly, I would recommend GitHub Pages instead, but the serverless part is quite good.

For example, if I have a Node.js app that doesn't do much, just a simple server without a database, it's suitable for the serverless architecture in the free version, allowing it to remain free.

But if serverless doesn't meet your needs, you'll need to switch to the paid version, which starts at a minimum of $5 per month. The paid version charges based on how much memory, CPU, storage space, and traffic you use, with a minimum of $5 per month regardless of usage, and additional charges on top of that.

So, how much resources does $5 USD get you?

If we exclude traffic and storage (which are relatively cheap if used normally), 512 MB of memory costs $2, and 0.25 vCPU costs $3, roughly adding up to these two.

By the way, Zeabur strongly supports open-source projects, so if you are a maintainer of an open-source project, you can contact [Zeabur](https://zeabur.com/docs/billing/sponsor) to get free usage for the open-source project itself, and contributors to other projects can also receive coupons.

## Pros and Cons of Zeabur

For me, the biggest advantage of Zeabur is the easy and quick deployment. Many projects can be deployed with just a click, without the need for additional configuration files (although I have only tried simple projects and cannot guarantee for more complex ones).

Many people appreciate their Mandarin customer service, which is quite rare for most PaaS providers that are based overseas.

In terms of pricing, if you have multiple small projects, it might be cost-effective to host them on Zeabur. The billing is based on usage, so for example, if you have 5 small projects each consuming an average of 100 MB of memory with minimal CPU usage, the total monthly cost could be as low as five US dollars.

Moving on to the drawbacks, one major concern is the continuity of service. Given the high failure rate of startups, there is a risk that Zeabur might shut down if revenue is insufficient, making project migration a hassle.

Another point to consider is stability. As a relatively small company with a limited user base, it remains uncertain whether the infrastructure can handle increased usage in the future. This aspect will require time to evaluate.

## Who Should Use Zeabur

If you have a short-term project that needs deployment without the hassle of managing servers and setting up environments, Zeabur could be a convenient and affordable option. This could be an event website or a project for a demo during interviews, among other possibilities.

If you frequently work on small projects that do not require significant resources, Zeabur might be a suitable choice. As mentioned earlier, the pricing model allows you to calculate whether it is more cost-effective for your needs. For services with higher demands and resource consumption, purchasing a VPS for $5 or $10 per month might be a more economical option, albeit requiring more time for environment setup.

Additionally, Zeabur offers various pre-built templates for quick service deployment, such as WordPress. If you prefer to set up your own service, these templates could be beneficial.

## Conclusion

The introduction to Zeabur concludes here. While it was mentioned that the free plan only supports static websites and serverless applications, it is worth noting that the free plan can also deploy regular containerized services (an entire server). However, there may be occasional notifications about potential service termination since no payment is involved, and no credit card is linked.

If you are interested in Zeabur's services, consider registering an account to explore and test your services. If you find it satisfactory, you can then opt for paid plans to ensure service stability.

Here is the referral link with my code: https://zeabur.com?referralCode=aszx87410

And here is the official link without my code:https://zeabur.com
