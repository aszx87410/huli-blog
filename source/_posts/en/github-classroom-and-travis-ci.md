---
title: 'Using Github Classroom and Travis CI to Build a Homework Submission System'
date: 2018-02-03 22:10
tags: [Others]
categories:
  - Others
---

## Introduction

Recently, I started a side project called [Lidemy Mentor Program](https://github.com/Lidemy/mentor-program), hoping to train students to become employable engineers within four months.

As Git is one of the essential skills for engineers, it is reasonable to use Git to submit homework and cultivate students' familiarity with Git.

But the question is: how to submit homework using Git?

<!-- more -->

Previously, I opened another [front-end course](https://github.com/aszx87410/frontend-intermediate-course), and I let the students create a Github repo to submit their homework and set up a Github page so that I could see their source code and the results displayed on the webpage.

Then I set up an Issue template, and after the students finished their homework, they opened an issue to submit it, as shown in the figure below:

![p1 1](https://user-images.githubusercontent.com/2755720/49351434-775c7f00-f6ee-11e8-9c92-9f61d84e2e75.png)


The advantage of this approach is that I can manage all the homework in one place, and it is easy to see who has submitted which homework and the status of each homework:

![p2 1](https://user-images.githubusercontent.com/2755720/49351437-7a576f80-f6ee-11e8-80a7-368836876320.png)


However, the disadvantage is also apparent. As a teacher, it is challenging to "grade" the homework. That is, if I want to point out where the students wrote incorrectly, I can only leave a comment in the issue, copy its original code, and tell them how to modify it:

![p3 1](https://user-images.githubusercontent.com/2755720/49351439-7d526000-f6ee-11e8-8b62-7e1c1a5ebe51.png)

Overall, the experience of grading homework is still good, and there are no significant problems. However, since I started a new course this time, I was thinking about whether there is a better way to optimize this process.

## New Homework Submission Process

When designing the course, I always think about what I have used in my work and move the good and portable systems to the course. The purpose behind this is to let the students understand these things first and seamlessly connect them when they enter the workplace in the future.

But sometimes I don't tell them that this is the process they may encounter in their work, hoping that they will exclaim when they really encounter it: "Wow, the exercises I did in the course are actually things that will be used in work!"

For example, because this new course requires students to participate every day and self-study when I am not in class, and the company happens to be running Scrum, which requires a Stand-up meeting every morning and sending a short note in slack before starting, I introduced this system into the course.

``` markdown
*昨天*
- 完成 git 安裝
- 解 codewar 題目：Opposite number

*今天*
- 解 codewar 題目：Opposite number
- 寫作業：好多星星
```

Every day, I ask students to post what they did yesterday and today in the slack group. Although it is still far from the actual Stand-up meeting, the original intention is the same: "Organize your progress and let everyone know your progress."

Adhering to the same concept, I decided to use [Github Flow](https://guides.github.com/introduction/flow/) for the homework submission mechanism.

What is Github Flow? You can take a look at the picture I took on the official website:

![github-flow](https://user-images.githubusercontent.com/2755720/49351441-80e5e700-f6ee-11e8-9b23-b18f389346d9.png)

Simply put, if you want to make any changes, you need to follow the following principles:

1. Create a new branch
2. Submit a Pull Request
3. Wait for review
4. Confirm that there is no problem and merge it into the master

Our company also uses a similar workflow, so I am quite familiar with this process myself. What are the benefits of this process? When submitting a PR, you can easily see the changes and suggestions:

![review](https://user-images.githubusercontent.com/2755720/49351444-83484100-f6ee-11e8-8cce-5eaa8c1c6f50.png)

Isn't this the most suitable way to grade homework? You can directly add comments, correct them line by line, approve the qualified homework directly, require correction for unqualified homework, and then submit a review again.

Once you have decided to use the PR method to submit your homework, there is still one thing to decide: how to send the PR. In other words, where should the PR be opened? There are several ways to do this:

1. The teacher opens an `hw` repo, grants permission to all students, and students send PRs to `hw` after completing their homework.
2. Students open an `hw-student` repo, add the teacher as a collaborator, and send PRs after completing their homework for the teacher to review.

For the former, you must open different folders under `hw` so that each student has a place to put their own homework. The advantage is obvious, that is, everything is managed in the same place, but the disadvantage is that this repo will become very large because you may need to put the homework of 10 students at the same time.

For the latter, students open their own repo, add the teacher to it for review, which is more decentralized, but has much higher freedom, and after the course is over, students can directly use their repo as part of their portfolio. I prefer this one compared to the former.

In addition, there is actually another problem that needs to be solved, which is that sometimes homework has a fixed format to follow. For example, I have some short answer questions and have already opened a template for answering under `hw`. Students only need to write the answer according to the format, so students must copy this template to their own repo, which is actually quite troublesome.

What is a better way?

It's very simple, it combines the previous two:

> The teacher opens a repo for the homework template, and students fork this repo to their own account and use this forked repo to submit their homework.

This way, students don't have to start from scratch and can directly use the homework template and format that the teacher has already written. And this processing method is actually what we will mention later, Github Classroom.

## Github Classroom

When I first saw this, I thought it was some magical system that could automatically help you complete a lot of things related to homework. But unfortunately, it is not.

The Github Classroom system is very simple. First, you need to register an organization to use it. After entering, you can create a Classroom, which means a course.

Under each course, there is a place where you can add assignments. When adding assignments, you can associate the repo under your own account. The interface looks like this:

![gcr](https://user-images.githubusercontent.com/2755720/49351451-86dbc800-f6ee-11e8-9142-8c0c318037ba.png)

The associated repo is the repo you use to submit homework, so you can write a lot of things first, such as the rules and format for submitting homework. For me, I will first open the file, and students only need to write the answer under the specified file:

![hw](https://user-images.githubusercontent.com/2755720/49351463-99560180-f6ee-11e8-83e3-b4b657f2303e.png)

After adding the assignment, there will be an automatically generated invitation link. After the student clicks and joins, a new repo will be automatically generated under your organization.

For example, the repo I used for association is called `mentor-program`, and the student's account is abcd, so a `mentor-program-abcd` will be generated, and this repo is based on what you originally generated, so everything is exactly the same. After it is generated, it will automatically set the student and the teacher as collaborators, and the student only has developer permissions, while the teacher has admin permissions.

Therefore, the advantage of using Github Classroom is that there is an automated system to help you fork a copy of your repo to the student, and automatically set permissions, and you can see each student's repo in the background:

![gcr2](https://user-images.githubusercontent.com/2755720/49351468-9bb85b80-f6ee-11e8-823b-e2734bae7db7.png)

At this point, you have a very good homework submission system, and the process is very simple:

1. Students join through the invitation link generated by Github Classroom.
2. A `mentor-progam-student_username` repo is generated.
3. Students clone it, open a new branch, and write their homework.
4. Send a PR after completing the homework.
5. The teacher reviews it, confirms that there are no problems, and then merges it.

## Combining CI to automatically grade homework

As mentioned earlier, your students' repos are all forked from what you provided, so students can write homework according to the rules you set.

In the example I just mentioned, I first opened `hw1.js`, `hw2.js`, etc. for the students, and they just need to write the answer in the file. If you noticed, I also opened `hw1.test.js` for them, which is used for unit testing.

In the first week's homework, they were asked to implement several simple functions, such as judging prime numbers, judging palindromes, etc. So each js file only exports one function. How to verify it? Run the test!

Since these are such simple functions, we can write unit tests to verify the results are correct. At this point, I thought we could combine CI to create an automatic homework grading system.

The process is simple:

1. Students submit a PR.
2. CI is triggered and automatically runs tests on the PR.
3. The results are displayed in the PR.

The completed result will look like this, and you can see the results of the CI running tests directly in the PR:

![ci](https://user-images.githubusercontent.com/2755720/49351471-9f4be280-f6ee-11e8-978b-475c42f4dfb0.png)

The system I used is the well-known [Travis CI](https://travis-ci.org). It's easy to use. After logging in, it will automatically grab your repo, and you can see a list. Just check the box to connect Travis to Github:

![ci2](https://user-images.githubusercontent.com/2755720/49351477-a2df6980-f6ee-11e8-9229-bb4f95de49ba.png)

Before checking the box, you need to configure your repo. The principle of CI is simple: you provide some commands for it to run. For my course, it's just running `npm run test`.

Just add `.travis.yml` to the root directory of the project to specify the environment and other parameters you want to run. For example, in [my project](https://github.com/Lidemy/mentor-program/blob/master/.travis.yml):

``` yml
language: node_js
node_js:
  - "node"
cache: yarn
before_script: 
  - wget $TESTCASE_URL
notifications:
  email: false

```

Travis is smart, so it defaults to running `npm run test`, so you don't need to set anything here. You can see that I set `before_script` here, and the parameters following it are the commands you want to execute.

I set it up this way because I want the test files in the repo to be available for students to practice on their own, and they can modify them freely. The tests I use to grade the homework are stored remotely and are only retrieved when running CI to ensure that students cannot modify them.

After preparation is complete, just check the box in the CI backend and adjust some settings (such as only running tests for PRs, adjusting environment variables, etc.), and everything is done!

![ci3](https://user-images.githubusercontent.com/2755720/49351481-a5da5a00-f6ee-11e8-8cec-67f8ea12643e.png)

## Conclusion

By combining Github Classroom and Travis CI, we can easily create a system that allows students to submit homework and allows teachers to easily grade homework, even allowing the system to automatically grade homework.

If you want to go further, there are many extended applications that can be done on the CI side, such as automatically closing PRs if tests fail, or automatically responding to which homework is incorrect. You can even record these messages and create a scoreboard for students. There are many interesting applications to play with.

But if you just want the basics, simple settings are enough.

This article summarizes the process of grading homework in my recent course. It works well because it allows me to easily grade homework and forces students to become familiar with the Git process, and they will become more proficient over time.

If you have any better suggestions, please leave a comment below, and if there are any errors in the article, please let me know. Thank you.
