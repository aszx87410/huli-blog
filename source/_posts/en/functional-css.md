---
title: 'Functional CSS Experience Sharing: Is It a Blessing or a Curse?'
date: 2019-01-27 22:10
tags: [Front-end,CSS]
categories:
  - Front-end
---

# Introduction

In terms of CSS architecture, there are three mainstream methods: OOCSS, SMACSS, and BEM. The purpose of introducing these architectures is to make CSS easier to maintain. You can refer to @arvinh's [Introduction to CSS Methodology and Atomic CSS](https://blog.techbridge.cc/2017/04/29/css-methodology-atomiccss/) for an introduction and comparison of these methods.

However, today we are not going to talk about the above three methods, but another method that is not as mainstream (but seems to be slowly gaining popularity) and is not easily accepted at first glance: functional CSS.

<!-- more -->

# What is Functional CSS?

The quickest way to explain is through an example:

``` html
// 一般的寫法
<div class="hello">Hello</div>
  
.hello {
  font-weight: 700;
  color: red;
  padding: 1rem;
}
  
// Functional CSS
<div class="fw7 red pa3">Hello</div>
  
.fw7 {
  font-weight: 700;
}
.red {
  color: red;
}
.pa3 {
  padding: 1rem;
}
```

Just like functional programming, each function has no side effects and can be combined with each other. In functional CSS, each class name is responsible for only one part (not necessarily one attribute). For example, the above example will produce a div that is bold, red, and has padding.

By the way, if you have used [Bootstrap4](https://getbootstrap.com/docs/4.2/getting-started/introduction/), you have probably experienced functional CSS, which contains a lot of this type of class name.

Do you like this writing style?

If you are seeing this writing style for the first time, I think you might be thinking: "This is terrible," "Isn't this just inline style?" "This is not CSS at all!"

Don't worry, I also had the same initial reaction. However, I changed my mind later, which is why I am writing this article. Next, I will talk about my love-hate relationship with functional CSS.

# My Love-Hate Relationship with Functional CSS

At first, I thought functional CSS was very special but also very strange. To be honest, I didn't even want to try it. I just thought that writing CSS like this was too strange and it was just a curse! Moreover, the class names were not readable at all.

But one day, I read this article on hacker news: [In defense of Functional CSS](https://www.mikecr.it/ramblings/functional-css/), which completely changed my mind.

This article refutes several common criticisms. Here are a few examples from the article:

## What is the difference between inline style and functional CSS?

1. Inline style cannot have media queries.
2. The properties of inline style can be set arbitrarily (I will explain this in more detail later).
3. Inline style cannot handle `:before`, `:after`.
4. Inline style cannot be reused, but CSS class can be. I can define a rule called `.bg-red`, and if I want a red background, I just need to add it.
5. The readability of inline style and functional CSS is different. Compare `class="f-sm bg-blue"` with `style="font-size: 10px; background-color: #0000ff;"`.

I think the author's refutations are quite reasonable. There is indeed a difference between inline style and functional CSS. I think everyone can agree that if you have to choose one of these two, the latter is much more reasonable because it is reusable and more readable.

However, the main reason why most people oppose functional CSS is that it makes the HTML messy and they don't know what it is doing.

For example, the example mentioned in the original article:

``` html
<div class="profile-card">
  ...
</div>
<style>
  .profile-card {
    padding: 20px;
    margin: 20px;
    color: #eee;
    background: #333;
    border: 1px solid #555;
  }
</style>
<div class="m-5 p-5 text-gray-light bg-gray-darker border border-gray-light">
  ...
</div>
```

The first one is obviously a profile card, but you can't tell what the second one is just by looking at the HTML.

The explanation given by the author is also very good:

> You can use them together.

Yes, you can do this:

``` html
<div class="profile-card m-5 p-5 text-gray-light bg-gray-darker border border-gray-light">
  ...
</div>
```

This way, you can maintain the original class name naming method, and this naming is just to make it easier for you to identify what this element is. In fact, the functional class names behind it are still doing the styling.

If you still want to refute, it is probably because the HTML still looks messy and has a lot of class names. I think this is both an advantage and a disadvantage, depending on how you look at it.

If you have no idea what those class names mean, you will naturally think it's a bunch of garbage. But if you know what they mean, you will find that just by looking at the HTML, you can know what the style looks like. You don't have to switch between HTML and CSS, but instead just focus on the HTML because the style is written inside the class name.

For example, your original development process might be like this:

1. Create an HTML for profile-card
2. Add .profile-card class name
3. Start writing styles in profile-card.css
4. Add profile-card-avatar HTML
5. Add .profile-card-avatar class name
6. Start writing styles for this class name

But after adopting functional CSS, the development process becomes like this:

1. Create an HTML for profile-card
2. Add class name to profile-card
3. Add HTML for profile-card-avatar
4. Add class name to profile-card-avatar

You don't have to switch between HTML and CSS because there is no CSS file for you to switch to.

## But isn't the reusability too low? Do I have to write 20 classes for each button?

This criticism is basically saying that if I have a button that looks like this after using functional CSS:
`<div class="bg-blue fw5 pa1">Click me</div>`

Then if I want to use this button elsewhere, don't I have to copy this string? If I change the style of the button, don't I have to change it everywhere? This reusability is too poor.

The rebuttal given in the original article is that if this really happens, you should prioritize turning this HTML into a reusable template instead of blaming the class for it.

Or I can say it like this, you should turn this thing into a component, so the problem will be solved because you only need to change the component, not every place.

That's the gist of this article. If you're interested, you can read the original article, which is clearer and more informative. But after reading this article, I had some ideas and began to understand the benefits of functional CSS.

# What are the benefits of Functional CSS?

The first benefit is that you (almost) don't have to write CSS anymore! And you don't have to hesitate about what class name to use!

This is a salvation for a lot of developers who have naming phobia. After using functional CSS, you just need to add the corresponding class to the HTML, just like the example I mentioned above.

At this point, you may say, "How do I know what this HTML is for?"

The first solution has been mentioned above, which is to add the original class name back, so meaningful class names are used for identification purposes, and functional CSS is used for styling. But I personally think this method is a bit redundant, and it takes time to think about what to name the class.

The second solution is a component. I later realized that some problems that functional CSS may encounter can be solved by components, which can be web components or the kind of components in React or Vue.

When we have a component, we don't need class names that much because you can tell it's a button just by looking at the component's name. From the naming of the component, you can know what it is, without having to rely on class names. Moreover, even if there are class names, you still have to compare the screen to determine where you need to change, after all, some class names are named super vague, which I believe everyone has experienced.

When writing CSS, you need to consider many things, but with functional CSS, almost all of them don't exist. All you have to do is add functional CSS class names to the HTML to decorate it.

The second benefit is that once you adopt functional CSS, you can immediately generate a set of specifications for your project, like design guidelines.

What does this mean?

First of all, you may have a wrong understanding of functional CSS, that it is another form of inline style, just written as a class.

No, it's not that you can use whatever you want, but you first set the specifications, and then you choose from the available class names. For example, your product's website has two main colors, red and blue, so you wrote .bg-red and .bg-blue.

Today, a new person comes to your company, and he wants to use red, so he will use bg-red instead of writing a new class. If he really writes a new one, it can be easily caught during code review because projects that use functional CSS usually don't change the CSS file after it's written, so it's particularly obvious when there are changes.

If today we were still writing CSS in the old way, it's possible that someone would take a shortcut and write the color code directly in the CSS instead of using the variables defined in color.scss. Or, they might not have noticed the `bg-red` in color.scss and added a `bg_red` class themselves.

Yes, these issues can be caught during code review, but what I want to express is that the former requires less effort because there are fewer places to check.

Once the main `style.css` file of functional CSS is completed, this file also represents the standards of the website. The colors, padding, margin, fonts, and font sizes that can be used are all defined inside. When you want to use them, you can only find them here and cannot add them arbitrarily. Therefore, you can easily specify that the padding of the website can only be 4, 8, or 16, or that the line spacing can only be 1, 1.25, or 1.5.

In fact, when using SCSS or any CSS preprocessor in the past, you could also do this by defining all standards as variables and specifying that all rules can only use these variables. But I think functional CSS inherently contains standards.

The third advantage is a drastic reduction in file size because `padding: 4px` will only appear once in the CSS file, and `color: red` will also only appear once. For the functional CSS framework Tachyons, the minified and gzipped CSS size is only 14kb.

Now it's 14kb, and it will be 14kb in the future because all the rules you need are inside. Your CSS size will not increase with the complexity of the website, which is also great.

Adam Wathan, the author of another functional CSS framework, Tailwind, wrote a great article exploring some pros and cons and systematically showing where the advantages of functional CSS lie. I think I could never write better than that, so if you are interested in a deeper understanding, you can refer to [CSS Utility Classes and "Separation of Concerns"](https://adamwathan.me/css-utility-classes-and-separation-of-concerns/).

Anyway, after reading a lot of articles and discussing with colleagues, we decided to switch our company's product to functional CSS. There are two reasons why we want to switch:

1. It's hard to maintain CSS as it grows, and any carelessness can become technical debt in the future.
2. The CSS file is getting bigger and bigger, but it can actually be much smaller.

# Practical Experience Sharing of Functional CSS

I previously read a [case study](https://hackernoon.com/full-re-write-with-tachyons-and-functional-css-a-case-study-part-1-635ccb5fb00b) about how the author easily rewrote the entire website in ten days using Tachyons and functional CSS.

At that time, we not only had to refactor these CSS files but also fix bugs and develop new features, so it took about a month to complete the entire website switch. In fact, when we actually refactored it, we found that some of the CSS we wrote before was really difficult to maintain. Therefore, we spent more time on this part.

I mentioned several related CSS frameworks above, but I think the concept of functional CSS is simple and easy to understand, and it is more in line with our needs to implement it from scratch by referencing Tachyons' class names.

The first step is to define some commonly used classes, such as colors:

``` css
.c-red { color: $color-red; }
.c-yellow { color: $color-yellow; }
.c-white { color: white; }
.c-green { color: $color-green; }
.c-grey-83 { color: $color-grey-83; }
.c-grey-4a { color: $color-grey-4a; }
.c-grey-bb { color: $color-grey-bb; }
.c-grey-f8 { color: $color-grey-f8; }
```

And the necessary flex layout:

```css
.flex { display: flex; }
.inline-flex { display: inline-flex; }
.flex-auto { flex: 1 1 auto; }
.flex-column  { flex-direction: column; }
.flex-row     { flex-direction: row; }
.flex-wrap    { flex-wrap: wrap; }
.flex-nowrap    { flex-wrap: nowrap; }
.items-start    { align-items: flex-start; }
.items-end      { align-items: flex-end; }
.items-center   { align-items: center; }
.items-baseline { align-items: baseline; }
.items-stretch  { align-items: stretch; }
.justify-start   { justify-content: flex-start; }
.justify-end     { justify-content: flex-end; }
.justify-center  { justify-content: center; }
.justify-between { justify-content: space-between; }
.justify-around  { justify-content: space-around; }
```

In addition, you can also write some utility classes yourself:

``` css
.ellipsis {
  overflow: hidden;
  text-overflow: ellipsis;
}
  
.limit-line {
  overflow: hidden;
  text-overflow: ellipsis;
  display: block;
  display: -webkit-box;
  -webkit-line-clamp: 1;
  -webkit-box-orient: vertical;
}
  
.pointer:hover { cursor: pointer; }
```

This echoes what I mentioned earlier, that a class name can actually have more than one rule, as long as you can clearly know what it is doing from the class name.

The process of refactoring is actually very fixed, basically these steps:

1. Select the component to be refactored.
2. Start from the innermost layer, right-click to inspect, and make sure that this class name has no other side effects.
3. Replace the original style with functional CSS.
4. Remove the original class name.

During this process, you can also standardize the website's style, such as changing all padding from 5 to 4, etc., so that the website will become more and more standardized.

However, during refactoring, you may also encounter some difficulties, such as some CSS written before that did not consider maintainability for the sake of convenience, and in the end, this pit still falls on you. For example, there is a component called Card, and the requirement is that its padding is different on the homepage and the restaurant page, so it was written like this before:

``` scss
// home_page.scss
.home-page {
  .card {
     padding: 10px
    }
}
  
// restaurant_page.scss
.restaurant-page {
  .card {
    padding: 15px;
  }
}
  
// card.scss
.card {
  padding: 20px;
}
```

What's the problem? The problem is that if you only look at the CSS of `.card`, you won't notice that it has different padding on different pages! If it's just padding, the problem is small, but if you continue to write according to this logic, it may even change the color and margin, like:

``` scss
.home-page {
  .card {
     padding: 10px
    &__title {
      margin-top: 20px;
      background: red;
     }
   }
}
```

This approach puts the display logic in CSS and uses CSS to manipulate it, so there is no need to write anything extra in JS. The `Card` component will have different styles in different places.

But later I realized that this is not a good practice. The logic should be moved back to JS, so I changed it to this:

``` js
// home page
<Card type="home" />
  
// restaurant page
<Card type="restaurant" />
  
// Card component
function Card({ type }) => (
  <div className={cx({
    'padding-20': !type,
    'padding-10': type === 'home',
    'padding-15': type === 'restaurant'
  })} />
)
```

I use the component's props to distinguish between different places, and put this logic inside the component. Compared with the CSS approach, there are pros and cons, but at least it can ensure that when I render a simple `<Card />`, its style will be consistent on any page, without worrying about suddenly appearing different styles in different places.

In the process of refactoring, I actually found many such problems. If they are not removed early, CSS will only become more and more and more chaotic, and it will become super difficult to maintain. It is easy to accidentally break two places by changing one class, causing a ripple effect. Therefore, I took the opportunity to deal with these issues when rewriting to functional CSS.

Many people have a misconception about functional CSS, that is, they cannot write "other" CSS. For example, I mentioned earlier that functional CSS is a separate specification and cannot be used for things that are not written as classes, but in fact, some special cases are still possible.

For example, if you have a div with a height of 333px, do you have to write a `.height-333` class for it? If that's the case, it's really no different from inline style.

But the point that functional CSS considers should be "can it be reused". Only things that can be reused are written as class names. For example, for a height of 333px, I will directly use styled-component or even write inline style. I won't give it a `.height-333` class because the entire App may only need it.

Finally, let's take a look at the results of the rewrite. This is before the rewrite, CSS is about 400kb (before gzipped):

<img width="1209" alt="css-before" src="https://user-images.githubusercontent.com/2755720/51797394-d8f82000-223d-11e9-810d-3f6192879ea1.png">

This is after the rewrite. You can see that all the data has decreased a lot, and CSS is about 130kb. It can actually be smaller, but it is larger because there are some small pictures converted to base64 inside:

<img width="1184" alt="css-after" src="https://user-images.githubusercontent.com/2755720/51797398-e0b7c480-223d-11e9-85ea-d1c9e0036f9c.png">

After the rewrite, the CSS volume was reduced by nearly 70%.

And the key is that no matter how much the App grows in the future, the CSS can be maintained at about the same size, because the commonly used attributes have been turned into class names.

The difficulty of rewriting depends on the quality of your original CSS. For example, many of our CSS are high due to the need for speed and lack of consideration for coupling. Often, two or three CSS files need to be referenced to piece together the final style. But if this problem is handled well in the first place, the speed should be much faster. But overall, rewriting is still relatively easy, and it feels great to delete a bunch of CSS rules directly after each rewrite.

Interested friends can use this website to test their own products: [https://cssstats.com/](https://cssstats.com/).

# Summary

If you want to say what are the shortcomings of functional CSS, the ones I can think of now are that it takes some time to learn at the beginning, and if there are many styles, the HTML will be full of class names, which is harder to read and the file is larger. But overall, I still think that the advantages outweigh the disadvantages.

The advantages have been mentioned before, basically it is not necessary to worry about the coupling problem of CSS. There will never be a situation where changing one class name will break two components, because each class name will not interfere with each other. It can also ensure that when you move this component to any place, it still looks the same, and there is no special CSS behind it.

You don't have to worry about how to name class names anymore because you don't need to. This can save a lot of time. You don't have to write CSS by hand anymore, so the development speed is faster because you don't have to switch between CSS files and components. You can write the style while writing HTML, save it, and then adjust it after seeing the interface. Compared with before, there are fewer steps.

Actually, I don't have much experience with CSS, and there may be many cases that I haven't considered or advantages and disadvantages that I haven't explained clearly. If you want to study functional CSS more deeply, the resources I provided at the end of my article are very valuable references that you can check out.

But anyway, I am now one of the supporters of functional CSS.

References:

1. [In defense of Functional CSS](https://www.mikecr.it/ramblings/functional-css/)
2. [Tachyons](https://tachyons.io/docs/table-of-properties/)
3. [Full re-write in 10 days with tachyons and functional CSS: A case study ](https://hackernoon.com/full-re-write-with-tachyons-and-functional-css-a-case-study-part-1-635ccb5fb00b)
4. [Tailwind: style your site without writing any CSS!](https://jvns.ca/blog/2018/11/01/tailwind--write-css-without-the-css/)
5. [CSS Utility Classes and "Separation of Concerns"](https://adamwathan.me/css-utility-classes-and-separation-of-concerns/)
6. [Discussion on HN](https://news.ycombinator.com/item?id=18084013)
