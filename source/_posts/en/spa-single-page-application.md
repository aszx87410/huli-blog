---
title: 'Front-end Separation and SPA'
date: 2017-09-06 22:07
tags:
	- Front-end
categories:
	- Front-end
---

# Preface

This post ([You go your way, I'll go mine: Front-end Separation](http://ithelp.ithome.com.tw/articles/10187675)) is one of the articles I wrote for the iT Ironman Contest. After receiving some feedback, I decided to revise and clarify the article.

If you have the following questions, this article is perfect for you:

1. Why does the front-end have MVC?
2. What is the difference between front-end MVC and back-end MVC?
3. Why do we need SPA (Single Page Application)?

<!-- more -->

(Actually, there are many discussions about what MVC is, but since this article is not focused on that, I won't go into detail. If you are interested, you can refer to: [MVC is a big misunderstanding](http://blog.turn.tw/?p=1539))

# Let's start with the familiar process

If you want to write a simple blog, what would you do?

The answer is simple. You can choose a framework you like, such as Rails, Laravel, etc., define several URLs, design the DB schema, and start coding.

For example, for the homepage, you retrieve all the articles from the DB, put the data into the view, and render it.

In summary, the process is like this:

<img width="923" alt="server" src="https://user-images.githubusercontent.com/2755720/49350531-4b3eff00-f6ea-11e8-9d8f-448f80ddd114.png">

When you want to access the article list page, the browser sends a request to the server, and then the controller and model process the data and pass it to the view.

The view returns a complete HTML file (this action is called rendering), and the browser displays it. Since rendering is done on the server-side, it is also called server-side rendering.

This process should be the most familiar to you because many web pages are done this way.

In this situation, a front-end engineer is responsible for everything under the view folder and must use the template provided by the framework to integrate the data with HTML. When he needs to debug, he must run the entire project to see the output.

This workflow makes it difficult to separate the front-end and back-end. After all, the front-end engineer still needs to know how to run Rails, set up the DB, and maybe even configure Nginx!

Although the current method separates the data (Model) and display (View), they are still on the back-end. Is there a better way? Is there a way to let the back-end focus on providing data and the front-end focus on displaying data?

Yes!

# Client-side rendering

We just mentioned server-side rendering, where the back-end directly returns the entire HTML, and the browser displays it because the response is the complete web page.

But since we distinguish between server and client, there is another way called client-side rendering. What is it?

Everyone knows that JavaScript can dynamically generate content, and client-side rendering means that when the front-end receives the data, it uses JavaScript to dynamically fill in the content on the web page.

It's easier to understand with the code:

First, our server now only focuses on providing data, so we open an API:

``` javascript
// Homepage, output all messages directly
app.get('/', function (req, res) {
  
  // Retrieve all messages from the database
  db.getPosts(function (err, posts) {
    if (err) {
      res.send(err);
    } else {
  
      // Directly send all posts out
      res.send({
        posts: posts
      });
    }
  })
});
```

If you open the URL of this API in a browser, you should see JSON data:

``` json
{
  "posts": [
    {
      "_id": "585f662a77467405888b3bbe",
      "author": "huli",
      "content": "2222",
      "createTime": "2016-12-25T06:24:42.990Z"
    },
    {
      "_id": "585f662777467405888b3bbd",
      "author": "huli",
      "content": "1111",
      "createTime": "2016-12-25T06:24:39.601Z"
    }
  ]
}
```

The backend part is ready and providing data smoothly. Now let's take a look at the frontend, which only needs an `index.html` file.

``` html
<!DOCTYPE html>
<html>
<head>
  <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css" />
  <script src="https://code.jquery.com/jquery-1.12.4.min.js"></script>
  <script>
    $(document).ready(function() {
      getPosts();
    })
  
    // ajax fetches the posts
    function getPosts() {
      $.ajax({
        url: 'http://localhost:3000/',
        success: function(response) {
          if (!response.posts) {
            return alert('Error');
          }
          for(var i = 0; i < response.posts.length; i++) {
  
            // pass to the render function
            addPost(response.posts[i]);
          }
        },
        error: function(err) {
          console.log(err);
          alert('Fetch failed');
        }
      })
    }
  
    function addPost(post) {
      var item = '' + 
        '<div class="panel panel-default">' +
          '<div class="panel-heading">' +
            '<h3 class="panel-title">' + post.author +', Post Time：' + post.createTime + '</h3>' +
          '</div>' +
          '<div class="panel-body">' +
            post.content
          '</div>' +
        '</div>';
      $('.posts').append(item);
    }
  </script>
</head>
<body>
  <div class="container">
    <a class="btn btn-primary" href="/posts">Post a new message</a>
    <h2>Message List</h2>
    <div class="posts">
    </div>
  </div>
</body>
</html>
```

Then open `index.html`, and you can see the expected interface, which should be exactly the same as the one we generated with server-side rendering. If you right-click and inspect, you will find that all elements are there.

<img width="735" alt="ele1" src="https://user-images.githubusercontent.com/2755720/49350544-57c35780-f6ea-11e8-9325-b01c6f0c312b.png">

However, if you right-click and view the source code, you will find that it is almost empty:

<img width="553" alt="ele2" src="https://user-images.githubusercontent.com/2755720/49350552-5c880b80-f6ea-11e8-81c2-e6161bbf6efc.png">

This is the biggest difference between client-side rendering and server-side rendering. For the former, we are "dynamically" fetching data from the backend server during runtime and dynamically generating the elements you see. 

Those elements did not originally exist in `index.html`. We appended them ourselves using jQuery, so of course, nothing will appear when you view the source code.

Let's take a look at a client-side rendering diagram:

<img width="925" alt="client" src="https://user-images.githubusercontent.com/2755720/49350560-614cbf80-f6ea-11e8-88cb-d183bced83bb.png">

In the server-side, the view layer is ignored because the backend only outputs data in JSON format. The fifth step here, rendering the returned data into HTML, refers to the step where we used jQuery to dynamically append the data. 

In this situation, have you noticed that the front-end and back-end have been separated?

After this, the backend engineer no longer needs to worry about what is in the view, nor does he need to teach the front-end engineer how to run Rails. He only needs to be responsible for creating API documents and providing the data needed by the front-end.

The front-end engineer no longer needs to run those services either. They only need to open the HTML file in their familiar browser, use AJAX to get data from the backend, and dynamically generate content on their end using JavaScript.

In this scenario, the deployment of the front-end and back-end can also be completely separated. The front-end part is the simplest, just find a place to store the HTML file, such as Amazon S3. Therefore, the front-end hardly has any problems, nor does it have any traffic issues, because it is just a static file.

If the server crashes one day and the API crashes with it, users can still visit the website, they just won't see any data, or you can display an error message. But if it's the old type of architecture where everything is tied together, once the server crashes, you can't even render the page.

Furthermore, because data and view are now completely separated, it is very convenient to replace either side. For example, if you don't want to use Rails on the backend anymore and want to use Go, it's no problem! As long as the API format is the same, the backend can use C if they want to.

The front-end is the same, you can choose Angular, React, or Vue, or even hand-code it, it's not the backend engineer's concern.

# However, things are not that simple

Although this scenario sounds great, don't overlook the consequences of such changes.

What consequences? The front-end will become very complex.

Think about the development architecture we mentioned at the beginning, where everything is rendered from the backend. So I prepare a view file for each page, if the user visits `/posts`, I render `('posts.ejs')`; if they visit `/about`, I render `('about.ejs')`.

The first problem arises:

> Since we just said that the front-end only has one index.html, doesn't that mean that visiting `/posts` and visiting `/about` both go to the same file? How do I render different pages?

Because in the past, the routing part was handled by the server, as I mentioned earlier, the server decides which page to render based on different routes. But now that it's separated, the front-end only has one index.html, so what do we do?

We have to let the front-end handle it.

The front-end can manage the URL by using `window.location` or the [history API](https://developer.mozilla.org/en-US/docs/Web/API/History_API) to know which page the user wants to visit.

Here's a small detail to mention: as I just mentioned, the front-end only has one HTML file, so the URL might look like this: `https://example.com/index.html`.

There's only one URL, how do we know which page the user wants to visit?

In the past, if we wanted to visit `posts`, the URL might be: `https://example.com/posts`, but now that the front-end has become a static file, there's only that one path, what do we do?

The first method is to use a hash, for example, `https://example.com/index.html#posts`, and then the front-end can parse the string after it.

The second method is to use `nginx` or other similar services to output the index.html file for all `https://example.com/*` URLs, so it looks like it did before.

If I go to `/posts`, the server will return index.html, and if I go to `/about`, the server will return the same content.

Anyway, because the backend no longer handles the routing here, this part is completely handed over to the front-end. You must manage the URL state on the front-end to decide which page to display.

So how do we do this? The simplest way is to do it the same way as the backend did before. Wherever you go, I'll output what you need based on the URL.

The front-end code might look like this:

``` js
function render(path) {
  // Clear the entire screen
  $(body).empty();
  if (path === 'posts') {
    renderPostsPage();
  } else if (path === 'about') {
    renderAboutPage();
  }
}
```

As long as I go to a new URL, I just clear the current content and render it again. 

It's simple, but there is a big performance issue because some parts don't need to be cleared. For example, the navigation bar at the top and the footer at the bottom of the website are basically the same on every page and won't change.

For those unchanging parts, they should be preserved, otherwise it's very inefficient to clear and rebuild the same thing every time. You might say that this is like the old way of writing views on the backend, where common parts are extracted and put in the layout.

No, this is different. Backend rendering is essentially "returning a different HTML file for each different page," and what we are doing now on the frontend is also extracting common parts, but the difficulty on the frontend is "how to update only part of the screen, rather than brutally chopping and rebuilding every time."

Have you started to feel that there are more and more things to do on the frontend?

# Single Page Application

When you take this thing to the extreme, it feels like you're writing an app, and this thing is called an SPA, Single Page Application.

Just as the name suggests, we now only have one index.html file, but it works like an app.

The most classic example is Gmail. When you use Gmail, there is no page switching. All actions happen on the "same page," so the file you load from start to finish is only one index.html, and you never switch pages.

Any action you take on Gmail sends an ajax request to the server, and after the server returns the data, the client side uses JavaScript to render the screen.

So when you use Gmail, you feel like you're using an app instead of a webpage, because the page transitions are smooth, unlike regular webpages where there may be white screens in between.

Since it's called an Application, frontend engineers at this point are no longer just expected to know how to use HTML and CSS to draw screens, and use JavaScript to add small effects and interactions.

The hardest part of writing an SPA is managing the state. Because many things were done for you on the backend, you didn't have to consider this at all, but now you do.

For example, in the past, when you visited an article, let's say `/post/12`, and quickly switched back to the homepage and clicked on another article, the server would only return the corresponding HTML.

But with an SPA, consider the following process:

1. User clicks `/post/12`
2. Query API
4. User returns to homepage
5. User clicks `/posts/13`
6. Query API
7. Get response and render page

Assuming the user clicks quickly, at step 7, it is very likely that they will get the response from step 2 first, and the user will end up seeing the content of article B even though they clicked on article A.

This is just a simple example, and in practice there are many other issues to consider, such as what to display when data hasn't been retrieved yet, and how to update after data has been retrieved.

# Frontend MVC

As the frontend becomes more and more complex, you should also understand why the frontend needs MVC. If you have written pure PHP and experienced the period when business logic, view, and model were mixed together in the same file, you should also understand why MVC is needed.

Because we need to separate responsibilities, so that everyone is responsible for what they should be responsible for, and not everything is mixed together like spaghetti.

Frontend MVC is actually quite similar to backend MVC, and we also need to set up routes, as mentioned earlier. That is, set which URL goes to which controller, then go to the corresponding model to get data, and finally output the view.

Here's a comparison of what frontend and backend MVC do:

&nbsp; | Frontend | Backend
----- | ---- | ---
Model | Go to the backend API to get data | Go to the DB to get data
View  | Dynamically generate screens on the frontend | None
Controller | Call the corresponding model and render the screen | Call the corresponding model and return data

<img width="968" alt="mvc" src="https://user-images.githubusercontent.com/2755720/49350576-6e69ae80-f6ea-11e8-8827-3e8d2e6a090e.png">

You'll find that what the frontend and backend do is pretty much the same, except that the frontend focuses on rendering screens and the backend focuses on outputting data. You can also draw a complete flowchart:

<img width="933" alt="all" src="https://user-images.githubusercontent.com/2755720/49350581-76295300-f6ea-11e8-8332-3f9e80ecb0cb.png">

To explain it in words, the process is as follows:

1. The user visits the /posts URL, indicating that they want to see all the articles.
2. The front-end router handles this and calls the corresponding controller.
3. The front-end controller calls the model to get the data.
4. The front-end model gets the data through the API at the /api/posts URL.
5. The back-end router receives the request and sends it to the corresponding back-end controller.
6. The back-end controller and model get the data.
7. The back-end controller returns the data.
8. The front-end model receives the data and returns it to the front-end controller, which then passes it to the view.
9. The client-side render renders the page.

This is basically the most basic structure of a SPA. The back-end only outputs data, while the front-end is responsible for fetching data and rendering the page. By completely separating the front-end and back-end, even if the back-end fails, the front-end can still display the page (although it may display an error page or something similar); if the front-end fails, the back-end can still output data for other services to use.

Both sides are clean, and either side is easier to maintain. If a front-end engineer wants to change anything related to the interface, it has nothing to do with the back-end. It's like two different projects.

Do we really need SPA?

I think the complexity of front-end development is closely related to SPA, as you are essentially developing a complete app, so how can it not be complex?

But don't forget to ask yourself:

> Do we really need SPA?

Some scenarios require it, such as music playback websites.

Why? Because you must be able to play music while browsing other data on the website, such as artist introductions and album introductions. If you don't use SPA, when the user clicks to another page, the browser will jump to that page and the music will stop. This experience is terrible and completely unacceptable.

Therefore, this type of website must use SPA, and there is no other choice. After using it, because there is no page jumping, when you click on the artist introduction, you just send an ajax request, and then use JavaScript to render the received data into HTML and display it. No matter which page you go to, it won't really jump, and it won't load a new HTML file.

There are some places where I think it's not necessary, but using it can enhance the user experience, such as Twitch's new feature a while ago, where when you jump to another page, the live broadcast you were watching will shrink to the lower left corner.

![twitch 2](https://user-images.githubusercontent.com/2755720/49350590-7de8f780-f6ea-11e8-95b2-e2c7bc7f63dc.png)

In short, there are two scenarios where Single Page Application is needed. One is because it must be done, and the other is because it can enhance the user experience and make the operation smoother.

If you find that what you want to do does not fit these two scenarios, you can choose not to use SPA and follow the previous MVC architecture, which is rendered and processed by the server side. All of this is optional.

In addition, SPA also has some disadvantages. For example, you clearly only need to look at one page, but you have to download a large package of JavaScript or other page templates.

Or because it is client-side rendering, some search engines cannot crawl any data (because your index.html is almost empty), but Google is very powerful and will crawl the results after executing JavaScript. But this is still not good for SEO.

Of course, there are some methods to solve the above problems, such as separating the js files, so you only need to download the js file of that page when you go to that page. The solution to SEO is to combine the two. The first time is server-side rendering, and the subsequent operations are changed to client-side rendering, which can ensure that search engines can crawl the complete HTML.

But you know, being able to solve it is one thing, and how much effort it takes to solve it is another.

In summary, this article roughly talks about the most common website architecture at the beginning, and then SPA, which has led to the complexity of front-end development in recent years. When I first encountered it, I was also confused and wondered why the front-end needed MVC. But after thinking about this series of contexts, it is easy to understand the reason.

When things become more and more complicated, you need a structure to cut responsibilities, otherwise it will cause difficulties in maintenance in the future.

The more you understand the advantages and disadvantages of SPA, the more aspects you can refer to when choosing whether to use it, and you have more reasons to support the decision you made, rather than just saying "Wow! It's so trendy! I want to use it too!"

I hope this article is helpful to everyone, and finally, here is an extended reading: [Why I hate your Single Page App](https://medium.freecodecamp.org/why-i-hate-your-single-page-app-f08bb4ff9134).
