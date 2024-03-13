---
title: Transitioning from React to Vue
date: 2024-03-13 11:40:00
catalog: true
tags: [Front-end]
categories: [Front-end]
photos: /img/from-react-to-vue/cover-en.png
---

If you have read my blog before, you should know that I have always been writing in React and have never touched Vue or Angular. Since I started using React in 2015, I have been using it for work.

However, recently due to work requirements, I started working with Vue. Coincidentally, some readers asked me about my insights on transitioning from React to Vue, so I decided to write a brief post to share my thoughts.

<!-- more -->

## Before We Begin...

Although I am supposed to talk about my thoughts on transitioning from React to Vue, let me first share my thoughts on Next.js 13.4, specifically the combination of app router with RSC (React Server Components). Technically, this should be a separate post, but due to space constraints, I'll include it here.

If you're not interested, feel free to skip to the next section.

In my current company, we work with both React and Vue, using the latest versions - Next.js 14 (we started with 13.4, the first version with RSC) and Vue3.

Since we are using the latest version of Next.js, I decided to explore RSC to experience one of React's future key technologies. In conclusion: "Don't let me suffer alone, please come and use it."

(If you're not familiar with what RSC is or tend to confuse it with SSR, I recommend reading these two articles: [RSC From Scratch. Part 1: Server Components](https://github.com/reactwg/server-components/discussions/5) and [Understanding React Server Components](https://vercel.com/blog/understanding-react-server-components))

According to RSC's design principles, if used correctly, your bundle size may decrease, and your website's performance may improve. However, after using it myself, I believe that the benefits it brings are far outweighed by the complexity introduced by adopting this technology.

But first, let me emphasize that my experience is based on using Next.js's RSC, and it may not be the same for all RSC implementations. Therefore, this section will focus on "My Experience with Next.js's RSC" rather than "My Experience with RSC."

Let's start with the drawbacks.

Firstly, understanding the difference between client components and server components can be time-consuming. Perhaps I started experimenting too early, and even the official Next.js documentation was not very clear, requiring continuous trial and error to understand the concepts (for example, there was a post in the frontend community asking about this, and I had similar doubts at first).

Furthermore, in the future, when writing components, you will need to consider whether they are for the client, server, or both, adding to the mental burden.

Additionally, many server components may directly call APIs to fetch data, resulting in the client receiving pre-rendered results. While this may seem beneficial at first (after all, it's one of RSC's selling points), it actually makes frontend debugging very challenging.

Previously, apart from the initial SSR, I could open DevTools and see which requests the frontend made and what the API responses were. However, with server components, I can no longer do that; I can only see server logs to understand what happened.

If something goes wrong, I cannot easily determine whether it's an issue with my Next.js server or the API I called, significantly impacting the developer experience.

However, these issues are manageable. The most frustrating aspect is that the release of Next.js 13.4 was rushed, resulting in many features not being properly implemented or documented.

For example, Next.js has something called middleware, which intuitively seems like a file that runs before processing a request. However, the documentation did not clearly state that this middleware runs in a different execution environment from your other code (I remember they have since updated it, Next.js tends to be quite diligent with updates).

In other words, if you write `global.a = 1` in the middleware and log `global.a` in a Next.js server component, the answer will be undefined.

Furthermore, middleware does not run in a full Node.js environment but in a place called [Edge Runtime](https://nextjs.org/docs/app/building-your-application/rendering/edge-and-nodejs-runtimes), which lacks support for many functionalities and APIs.

The reason for this is that Next.js defaults to running this middleware on the edge, even if we don't actually use the edge functionality. Currently, there is no way to change this, and for more discussion, you can refer to this thread: [Switchable Runtime for Middleware (Allow Node.js APIs in Middleware) #46722](https://github.com/vercel/next.js/discussions/46722).

By the way, I currently do not support using Next.js as a full-stack framework, where both front-end and back-end projects are built on Next.js. The reason is simple - it is not suitable for this use case. The server provided by Next.js currently resembles more of a BFF (Back-end For Front-end), acting as a bridge between the front-end and other back-end services, but it cannot implement complete functionality on its own (unless your project is very small with minimal features).

If you try to move back-end functionality to Next.js, it will inevitably end in tragedy.

Having discussed the drawbacks, let's talk about the advantages. One of the main benefits is that the bundle size is indeed smaller. For example, with i18n, without any adjustments, most clients would download strings that are "out of scope," such as all Chinese strings or at least the strings under the current namespace.

However, with RSC, since the server component handles i18n directly on the server, there is no need to download any additional strings in this regard.

Apart from this, I haven't experienced significant benefits (and due to some specific features of the company's projects, having to consider both client and server components simultaneously, the existing i18n packages all have issues, so I had to create a simple one myself).

In conclusion, I personally do not recommend using the app router as the benefits it brings are far outweighed by the implementation costs, and it only complicates many things. I have been using Next.js 13.4 since around July or August last year, and the situation was even worse back then, with mismatches between the documentation and code behavior occurring.

If someone tells me that the app router in Next.js 13.4 and later is excellent, I would think either they haven't used it enough or their project is very small, so they haven't experienced the downsides. Not to mention all the default caching strategies that are enabled and some cannot be turned off.

The above is a sneak peek into my experience with Next.js RSC, as I have been using it since around July or August last year. Initially, the first two to three months of use were the most impactful, with many points to criticize, but now I have somewhat forgotten, and I am afraid to remember.

## Transitioning from Writing React to Writing Vue

This post will attempt to focus on personal insights into React and Vue themselves, rather than specific libraries or frameworks.

For example, if I used Redux in React and then switched to Pinia in Vue, and wrote, "Wow, writing Vue is really great, Pinia is so clean and easy to use, much better than React," this argument would be flawed because there are similar options like Zustand in the React ecosystem.

Therefore, the comparison should not be between Vue and React but between Redux and Pinia, turning it into a comparison of specific libraries, which is what this post aims to avoid.

However, for context, let's briefly mention these libraries and frameworks. Currently, my starting point in React is typically Next.js paired with Zustand and Tailwind, while in Vue, it's Nuxt paired with Pinia and Tailwind.

In terms of user experience, I find both to be similar (if Next.js is used as a page router), so I won't dwell on this aspect.

Furthermore, user experience may vary based on experience level and the nature of the projects. I have approximately four internal medium-sized projects using Vue, and I have been writing Vue for about four months, which isn't very long. Additionally, since these are internal tools, SSR is not enabled, and they rely solely on client-side rendering.

With these premises in mind, let's discuss my preferences for Vue. 

Starting with state management:

Firstly, Vue's two-way binding is really convenient, and v-model is very useful. In React, I used to write value + onChange, but now with v-model, it's done in one line.

The biggest difference, in my opinion, lies in the useEffect hook. In React, you often need to use useEffect extensively to handle various scenarios and dependencies, which can lead to mistakes if not careful.

However, in Vue, this isn't a concern, saving a lot of mental burden, and it's quite challenging to misuse it.

This difference in features has also added a new dimension to my technical decision-making for projects, which is the "lower limit." Previously, when considering technologies, I tended to focus on "typical use cases." For instance, after writing React for a while, I didn't find useEffect particularly challenging, and it felt natural.

However, I also admit that `useEffect` is something that requires experience to write well, with a certain learning curve. This also means that its lower limit can be quite low. A poorly written engineer can write a bunch of `useEffect` with messy dependencies but still maintain a terrifying balance, making things work just right. If I were to take over after several years, I wouldn't know where to start making changes because as long as you keep adding things inside, everything breaks down, especially when multiple effects break down together.

But I personally feel that Vue is different. No matter how poorly you write it, it stays that way. Even if a person with very poor technical skills writes it, the Vue they write will be easier to maintain than React, in my opinion. This is what I mean by "lower limit."

Now, if there's a new team where everyone is super new to frontend development, and you have to maintain the project they write after half a year, you can already anticipate that the maintainability might be poor. Choosing Vue, which has a higher lower limit, might be better in this case, at least you can make changes more easily.

Another perspective to consider is the "learning curve." If the team is short-handed and needs support between frontend and backend, then Vue might be a better choice than React because it's easier to get started with, so even if you're not familiar with frontend, you can quickly get up to speed.

In summary, in terms of state management, I think Vue is more intuitive and easier to get started with, while React is indeed more complex.

Moving on to the rendering approach, React uses JSX all the way, where the entire component is a function containing JSX. On the other hand, Vue separates the template from the functional part, and I believe both approaches have their pros and cons.

For situations where early return is needed, such as displaying loading when it's still loading, I think React is more intuitive, you can tell from the first few lines of the component. With Vue, you need to check the setup part and then go back to the template to confirm.

Additionally, `v-if` and `v-for` in Vue are quite handy, and the template looks neater, providing better readability when the structure is not significantly different.

Now that we've covered the advantages, let's talk about some drawbacks.

The first drawback I see is regarding props. I find React more intuitive in handling props as they are just function parameters, while in Vue, you need to define them separately, and when passing them, kebab-case is encouraged. For example, renaming `testProps` to `test-props`. I personally don't like this inconsistency because it can make searching a bit difficult.

Although I can still use `testProps` based on the documentation, the recommended practice is still `test-props`.

The second drawback is that only one component can exist in a file in Vue, which I find quite inflexible and can lead to a lot of small files. While some have advocated for this approach in React as well, having one component per file, I believe that's not ideal because if some components cannot be reused by others, they should be in the same file for better organization and maintenance.

However, it seems this issue can be resolved. I found some related methods:

1. [Multiple Components in One File](https://michaelnthiessen.com/multiple-components-in-one-file)
2. [Writing multiple Vue components in a single file](https://codewithhugo.com/writing-multiple-vue-components-in-a-single-file/)

Looking at these, it seems that the two drawbacks I mentioned earlier actually have solutions available. It was just that I wasn't familiar enough with Vue before, so I didn't know about them. I'll try them out later.

## Conclusion

The above is my experience using Next.js 13.4 app router + RSC, and transitioning from writing React to writing Vue.

In conclusion, Vue is indeed simple and easy to get started with, but I need to observe for a while longer. After all, the more code you write, the more you'll get a feel for it. Someone like me who has only been writing for three to four months is usually still in the honeymoon phase, experiencing only the benefits rather than the drawbacks. As you write more code and the projects become more complex, you're likely to encounter some problems you haven't faced before.

Perhaps I need to write for another year or two to gain more insights? I wonder what frontend development will look like by then.
