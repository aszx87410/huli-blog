---
title: 'An Ocean-like Programming Course: CS50'
date: 2016-03-28 21:56
catalog: true
header-img: "/img/header_img/article-bg.png"
tags: [CS50]
categories:
  - Others
---
The full name of CS50 is **Introduction to Computer Science**, which is a general education course at Harvard University. It is available on [edx](https://www.edx.org/course/introduction-computer-science-harvardx-cs50x), and anyone can take it. There are even teaching assistants to help you with programming assignments (only programming assignments, not other types of assignments like paper-based ones).

The first time I heard about CS50 was through this report: [CS50: A "hard" course taken by over 800 Harvard students, what makes it so attractive?](http://www.inside.com.tw/2014/12/17/harvard-cs50). It wasn't until I finished the course recently that I understood what makes this course so impressive.

Let's start with the meaning of the title: An Ocean-like Programming Course. Why the ocean? Because this course is **deep and wide**. How deep and wide is it? I recorded the course outline and assignments for each week. If you have a friend with a computer science background, they will know what I mean.

<!-- more -->

## Week 0
Binary, ASCII, RGB, binary search
Introduction to basic programming language: conditional statements, variables, loops, arrays, functions
Assignment: Write a program using [scratch](https://scratch.mit.edu/)

## Week 1
Introduction to C language and the concept of compilation
Introduction to various types, such as double, float, int, bool, char, long long...
Introduction to floating-point errors and overflow
Teaching basic command line operations, such as `mv`, `ls`, `cd`, `make`, etc.
Assignment: Write a simple C program (loop to print stars)

## Week 2
Introduction to function, string, array
How to use `argc` and `argv` to pass parameters
Also talked about encryption, such as RSA
Teaching command line Redirecting (`>`) and Pipe (`|`)
Assignment: String processing, simple encryption and decryption implementation

## Week 3
Search, sorting (bubble, insertion, selection, quicksort, merge), big O
Recursion, bit operations
Using GDB
Assignment: Implement O(n^2) sorting and binary search

## Week 4
Re-introduction to recursion
String, pointer, `struct`, bitmap format
File processing (`fprint`/`fopen`...)
`malloc`, memory allocation
Teaching how to use `xxd` to view files in hex
Assignment: Given a bitmap header document, process the bitmap image, such as enlarging it twice

## Week 5
In-depth discussion of memory and pointers
Data structures: `linked list`, `queue`, `stack`, `tree`, `BST`, `tries`, `hashmap`
Teaching how to use `wget` to download files and how to write a `Makefile`
Assignment: Implement a dictionary tree or hashmap

## Week 6
This week begins with topics related to the Internet, including: `IP`, `IPv6`
`domain`, `nslookup`, `traceroute`, packet
`ports`, `dns`, `vpn`, `http`, `request`, `response`
Teaching how to use `chmod` to change file permissions and how to use `curl` to grab web pages
Assignment: Write a part of an http server in C

## Week 7
Using chrome dev tool, such as viewing `html`, `request`
Basic `html` and `css` tutorials
Introduction to `php`
Introduction to get/post parameters
Basic `sql` tutorial
Teaching how to use `apt-get` to install packages
Assignment: Complete a simple `php` webpage and communicate with the database

## Week 8
Demonstrating code refactoring and explaining the concept of `MVC`
Teaching basic `SQL` syntax
Introduction to `SQL Injection`
Assignment: Connect to `Google Map API` and use `jQuery` and `ajax` to create a more interactive webpage

## Week 9
Introduction to javascript syntax
Explanation of json format
DOM model
Event handler, event mechanism
(No assignments after this week)

## Week 10
Exploring information security and privacy
Such as password security (encryption algorithm, salting)
Smart TV
Phishing emails
Two-factor authentication
Cookies, session, https
Also briefly talked about speech recognition, such as the principle behind `siri`

## Week 11
Introduction to game AI and self-driving cars. Topics covered include:
dfs, bfs
minimax
evaluation function
alpha-beta pruning
AI characteristics of different games
Also briefly touched on machine learning, such as how Netflix recommends movies to users.

## Week 12
Course review and playing some small games. Not much content this week.

When I took this course, I was amazed. Wow! They actually teach you how to write a `Makefile`, and even teach you how to use `xxd` to view files. They even give you a `bitmap` file and ask you to read it according to the format, then enlarge it and write it back! The most frustrating assignment for me was the http server, because I had to use `C` to do string processing...

From the above 12 weeks of course introduction, you can see that this course is really **deep and wide**. After finishing it, you can learn:
1. Basic programming skills: variables, arrays, conditionals, loops, functions
2. You learned pointers!
3. Directly manipulate memory and understand what the computer is doing at the low level
4. Familiar with basic sorting algorithms and data structures
5. Use of various command line instructions (I think this is super practical)
6. Basic knowledge of networks (ip, dns, server, port, request, response...)
7. Backend programming language PHP
8. Front-end HTML/CSS/JavaScript
9. Use and command of database MySQL
10. Information security (encryption and decryption, SQL injection, buffer overflow)
11. Basic understanding of machine learning, artificial intelligence, and speech recognition

I have always been self-taught in programming, although I have taken several programming-related courses after college, but they were just for review and I didn't learn much. But this course really made me admire it from the bottom of my heart. Everything introduced in the course is very practical, and some of them I have only recently used. Even the command line was not used by me before because I never had the opportunity to use it.

In addition, although the content of this course is deep, the teacher is humorous and can make the concepts vivid. For example, when talking about binary search, the teacher took the phone book as an example and tore it in half from the middle! Or when talking about binary, there are several light bulbs on the stage, and the lit ones are 1 and the dark ones are 0, which deepens the impression through such physical interaction.

In terms of course teaching, there are several points that I appreciate. 
First, start with `scratch`. After completing CS50, I decided that when I teach programming in the future, I will start with `scratch`. Because it is visualized, you can clearly see what the structure of the program looks like; and it is fast and has complete built-in resources. If you want to make a game, just drag a few characters and define some events. I think `scratch` is the best choice for programming beginners.

Second, package difficult-to-explain concepts first. Like strings, in `C`, it is actually an array formed by `char*`, or `char`. But how do you explain it to students at the beginning? So they wrote a `string` type to hide this information, and when they got to arrays later, they explained it to the students.

There is also `scanf`, which involves concepts such as `pointer` and `call by value`, which is not suitable to be explained at the beginning. But the program still needs input, what should I do? So they packaged it into a `GetInt()` function to encapsulate these details.

Third, cloud IDE. Setting up a development environment is not an easy task. CS50 and [c9](https://c9.io/) cooperate to provide an online IDE. You can write code, view files, and use command line operations, and all assignments are completed on it. Super convenient!

Finally, this is a hard course, but at the same time it is a very solid and useful course. Recommended for anyone who wants to learn programming.

If you are taking this course and cannot find anyone to discuss with, you can go to this Facebook group:
[cs50 Chinese discussion group](https://www.facebook.com/groups/556507217856457/)
