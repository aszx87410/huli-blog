---
title: 'Building RESTful API with Node.js'
date: 2016-09-29 00:23
catalog: true
header-img: "/img/header_img/article-bg.png"
tags: [Node.js,Back-end]
categories:
  - Back-end
---
(Original post published at: http://blog.techbridge.cc/2016/04/23/fast-restful-nodejs-api-backend/)

## Introduction

Some websites today use the Single Page Application approach, where the backend only provides APIs for the frontend to fetch data, achieving complete separation of the frontend and backend. There are many choices for the frontend, you can use `Angular`, `Ember.js`, or `React + Redux`. As for the backend API, it must conform to a fixed format to make it easier for frontend developers to fetch data. And this "fixed format" is most commonly known as our focus today: `RESTful`.

<!-- more -->

## What is RESTful?
Instead of starting with a hard-to-understand textual explanation, let's start with a practical example. Suppose you are writing a backend API for a blog website, and ten people may have ten different ways of doing it. For example, the "fetch all articles" feature:

1. /api/blog/getList
2. /api/blog/getAllArticle
3. /api/blog/article/getAll
4. /api/blog/fetchAll
5. /api/blog/all

But if you adopt the `RESTful` approach, it will conform to a certain format:


| Operation | Method    | URL    |
|----------|--------|----------------|
| All articles | GET    | /api/posts     |
| Single article | GET    | /api/posts/:id |
| Add article | POST   | /api/posts     |
| Delete article | DELETE | /api/posts/:id |
| Modify article | PUT/PATCH | /api/posts/:id |

In this example, the article (posts) is a `Resource`, and you can access this `Resource` by using several methods provided by HTTP in combination with different URLs.

If you are interested in `RESTful`, here are some articles worth referring to:

1. [What is REST and RESTful?](https://ihower.tw/blog/archives/1542)
2. [A Brief Talk on REST Software Architecture Style](http://blog.toright.com/posts/725)
3. [Understanding RESTful Architecture](http://www.ruanyifeng.com/blog/2011/09/restful.html)

## ORM
ORM stands for Object Relational Mapping.  
If we talk about databases, it maps your database to objects in your program. Taking the example of the blog above, your database table might look like this:

| Field | Type    | Description    |
|----------|--------|----------------|
| id | int    | id    |
| title | text    | title |
| content | text   | content   |
| created_at | timestamp   | creation time   |

Mapped to objects in Node.js, you can do this:

```js
// Create a post
Post.create({
  title: 'Hello Excel',
  content: 'test'
})

// Delete the post with id 1
Post.find(1).delete();
```

That is to say, you don't have to worry about which database is being used behind the scenes, or what the table name is. You just need to operate on the `Post` object you know.

[Sequelize](http://docs.sequelizejs.com/en/latest/) is a very useful ORM Library that can help you link objects and databases together by defining a `schema`.

## Why mention ORM suddenly?
Some readers may have already thought that there is some degree of relationship between RESTful API and ORM. How to say?

Suppose I want to write a backend API for a message board today, and I use RESTful and ORM at the same time. My program will look like this:

```js

// Fetch all messages
// GET /api/messages
Message.findAll();

// Fetch a single message
// GET /api/messages/:id
Message.find(id);

// Create a new message
// POST /api/messages
Messages.create({
  content: content
})

// Delete a message
// DELETE /api/messages/:id
Messages.find(id).delete();

// Update a message
// PUT /api/messages/:id
Messages.find(id).update({
  content: new_content
})

```

What if I am writing a backend API for a blog?  
Just replace all the `messages` above with `posts`, and you're done!  
From the above example, it can be seen that these two things are very suitable for working together because they can meet almost the same rules.

## Two wishes fulfilled at once, epilogue

[Epilogue](https://github.com/dchester/epilogue) is a Node.js library that combines `Sequelize` and `Express` to quickly build RESTful APIs.

Let's take a look at the example on the official website:

First, you need to define the database and your schema

```js
var database = new Sequelize('database', 'root', 'password');
var User = database.define('User', {
  username: Sequelize.STRING,
  birthday: Sequelize.DATE
});
```

Next, initialize express and epilogue

```js
var express = require('express'),
    bodyParser = require('body-parser');

var app = express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
server = http.createServer(app);

epilogue.initialize({
	app: app,
	sequelize: database
});
```

Finally, use epilogue to link the URL with the database. You need to provide it with the endpoint you want and the model you want to link to.

```js
var userResource = epilogue.resource({
  model: User,
  endpoints: ['/users', '/users/:id']
});
```

With these three simple steps, you have a RESTful API! Isn't it easy?

## Not just that
In the actual development process, things often don't go so smoothly. For example, your return format may be different from the database format, or some of your APIs may require authentication to call. No problem, epilogue has got you covered.

Epilogue provides seven hooks for behavior, including start, auth, fetch, data, write, send, and complete. Combined with before, action, and after, you can do what you want at any stage.

For example, if you want to make a small change before returning the result, it's `userResource.list.send.before`, or you may want to authenticate an API, which is `userResource.delete.auth`.

Here are two complete examples from the official website:

```js
// Prevent deleting user
userResource.delete.auth(function(req, res, context) {
  throw new ForbiddenError("can't delete a user");
})

// Check cache first, return cache content if available
userResource.list.fetch.before(function(req, res, context) {
  var instance = cache.get(context.criteria);

  if (instance) {
    // keep a reference to the instance and skip the fetch
    context.instance = instance;
    return context.skip;
  } else {
    // cache miss; we continue on
    return context.continue;
  }
})
```

## Conclusion
If your backend API is not very complicated and only involves basic CRUD operations, then Epilogue is definitely a suitable framework for you. As long as you open up the database schema, you can simply copy and paste the code to complete an API. If readers have similar needs in the future, it's worth giving it a try!
