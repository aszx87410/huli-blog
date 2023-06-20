---
title: Tips for Beginners in Solving Programming Problems
date: 2019-11-01 20:34:52
catalog: true
tags: [JavaScript,Algorithm]
categories:
  - Algorithm
photos: /img/before-start-leetcode/cover-en.png
---

## Introduction

In the past few years, "problem-solving" seems to have become a trend. When students majoring in computer science go for interviews with big companies, they are required to solve problems. Even non-computer science students are expected to solve problems during interviews. It seems that if you don't solve problems, you will fall behind others and be eliminated by the company.

Actually, I have never been fond of the term "problem-solving", mainly because of the word "solving". I don't know how you interpret this word, but I feel that there is a sense of "solving problems just for the sake of solving problems", just like the tactic of solving a lot of problems. Although this tactic can be effective if used properly, I always feel that many people will end up with the mentality of "I can solve the problems I have seen, but I can't solve the ones I haven't seen". If that's the case, I don't think it's a good thing.

I have written an article before: [What should we learn when we are learning to code?](https://medium.com/@hulitw/learn-coding-9c572c2fb2), which briefly discusses this issue.

In short, I prefer to use the phrase "programming problem-solving" to express what I want to say, rather than the term "problem-solving".

<!-- more -->

When many people start practicing programming problem-solving, they start with algorithms and data structures. They may read some books or online courses, and start with the classics, such as bubble sort, selection sort, insertion sort, and then move on to more difficult ones, such as merge sort and quick sort. But I think it's too early for true beginners to learn these things.

In short, "if you can't write a multiplication table, it's useless to know KMP (or any other algorithm)." If there are two people, A can write a multiplication table but not KMP, and B can write KMP but not a multiplication table, I will definitely eliminate B. Because B is likely to have just memorized the KMP algorithm, rather than truly understanding it, otherwise I don't believe he can't write a multiplication table.

I also sincerely call on all companies to consider asking relatively simple questions during interviews. Sometimes the results can be surprisingly good. For example, finding the median, determining prime numbers, or adding large numbers, you will find that some people really can't solve them.

In short, I think it's absolutely fine to use programming problem-solving to familiarize yourself with algorithms, and it's also a great method, but you need to have a solid foundation. If you don't have a solid foundation, you're just memorizing problems.

And there's one more thing that's very important. Before you start solving problems, you need to understand the problem and grasp the scope of the problem. Many people overlook this and start solving problems directly, which is not a good thing when writing whiteboard problems.

So in this article, we will not talk about problem-solving itself, but about what you should do before you start solving problems. Let's first look at a problem, which comes from the [National Junior High School Preliminary Contest of NPSC 2007](https://contest.cc.ntu.edu.tw/npsc2007/).

## Problem Name: Who is the Unfair Person?

Since Jay Chou released his new album "Cowboy is Busy", Da Guo and Xiao Guo have often fantasized about being cowboys. Finally, one day, Da Guo brought two water guns to challenge Xiao Guo. But after playing a few games, Xiao Guo was completely soaked, while Da Guo was dry all over. Finally, Xiao Guo, who had been hiding his anger, spoke up!

Xiao Guo: "I can't even spray you..."

Da Guo: "That's probably because you're not good enough?"

Xiao Guo: "Liar~ Liar~ You must have cheated!"

Although Xiao Guo is inferior to Da Guo in everything (such as intelligence, motor skills, etc.), if Da Guo prepares a worse water gun for Xiao Guo in advance, it means that Da Guo is a bad person who has planned this game to be unfair from the beginning.

You, who happened to pass by, were caught by the two noisy guys to be the referee.

### Input Description

The input will be two strings M and N. M represents the range of Da Guo's water gun, and N represents the range of Xiao Guo's water gun. Note that for accuracy, the length unit of all ranges is nanometers. Because the water gun Da Guo brought is a product of the 22nd century, the range of the water gun is very, very far, up to 400 digits (the range must be a non-negative integer).

### Output Description

For each set of test data, you should return a string. From Xiao Guo's perspective (although he is stupid, he is still very cunning!), determine whether this is a fair game (for Xiao Guo, as long as Da Guo's range is not greater than Xiao Guo's, it is a fair game). If it is a game that is advantageous to Xiao Guo, return "Fair", otherwise return "Unfair".

### Example Input

123 456

### Example Output

Fair

*****

The above is a complete problem, including problem introduction, input description, output description, and examples. You may think it's just a matter of comparing two numbers, but it's not that simple.

Next, let's see what we should pay attention to.

## 1. Scope of the Problem

Why must the scope be given for this kind of programming problem-solving problem? To answer this question is simple. Let's take a look at the following example:

> Please write a function to determine whether a number is prime.

You may have finished writing it quickly and then submitted it. But because this problem is very unclear, you can't confirm whether your answer is correct, for example:

1. Should it return true or false? Or return the strings "YES" and "NO"?
2. What if the input is a string? Do I need to process it?
3. What if it is a decimal or negative number? Do I need to handle it specially?
4. What happens if the number exceeds the range of an integer?

If the input and output are not clearly defined, you cannot write a "correct" program because there is no such thing as "correct". Therefore, the first purpose of defining the input range is to help you clarify the problem.

For example, a good problem statement would look like this:

> Write a function that takes a positive integer n (1<=n<=100000) and returns true if n is a prime number, false otherwise.

When the problem says "given a positive integer n (1<=n<=100000)", it means you can completely ignore cases beyond this range. n will never be a string, an array, 0, a decimal or a negative number, so you don't need to worry about these cases.

By the way, this is a mistake that many people make when solving whiteboard questions during interviews. They start implementing without clarifying the problem scope.

Whiteboard questions can be discussed with the interviewer, so you should clarify the problem scope before starting to solve it, and the problem scope will actually affect your solution.

Taking the above problem as an example:

> Because the water gun brought by Da Guo is a product of the 22nd century, the range of the water gun is very, very far, up to a 400-digit number (the range must be a non-negative integer).

For example, in JavaScript, some people may naively think that this problem is testing you on comparing two "numbers". Can JavaScript store a 400-digit number? It cannot.

You can use `Number.MAX_SAFE_INTEGER` to get the largest number that can be stored in the Number type, which is less than 20 digits, let alone 400 digits.

If the problem tells you that the number is within 10 digits, you can simply convert the string to a number and compare the size, and then return the result. But if the number is 400 digits, you cannot use the Number type. So either you directly compare strings to determine the size, or you use the more trendy [BigInt](https://developer.mozilla.org/zh-TW/docs/Web/JavaScript/Reference/Global_Objects/BigInt) to solve it.

If the problem does not provide a range, you cannot decide what approach to take. So the purpose of the range is to define the problem more clearly, draw a line there, and tell you: "Hey, the problem range ends here, you don't need to consider anything beyond the boundary."

## 2. Testing after writing

If it is an Online Judge (OJ) system, you can keep trying and testing, write the code and submit it, and debug and find errors if there are any. If there are no errors, you can solve the next problem.

But in competitions or some interviews, you only have one chance, or there will be penalties if you answer incorrectly, so you should check it several times before submitting it to make sure there are no problems.

Testing is very important at this time. Basically, there are several methods to test whether the program you wrote is correct. For example, the first and simplest one: test with the sample data provided by the problem. If the sample data cannot pass, then it must be wrong.

Secondly, if possible, write a program to test it. Some problems can be done, and some cannot. For example, it may not be possible to determine whether it is a prime number, unless you find someone else's code for determining prime numbers to use. But for the above problem of comparing numbers, you can write a program to test for small ranges (less than 10 digits):

``` js
// correct implementation
function compare(a, b) { return b >= a ? 'Fair' : 'Unfair' }
  
for(let i = 1; i <=10000; i++) {
  // generate random data
  const a = Math.floor(Math.random() * 1e9)
  const b = Math.floor(Math.random() * 1e9)
  if (compare(a, b)!== stringCompare(a + '', b + '')) {
    // print data
    console.log('error', a, b)
  }
}
```

Run it ten times and you will test 100,000 data, which can ensure some correctness. In addition to this, there is one more important thing: generate your own test data, and generate boundary condition test data.

## 3. Boundary conditions

Boundary conditions are usually referred to as boundary case, corner case, edge case, etc. (the most accurate definition seems to be different, but the concept should be similar). In short, it is the test data that is easy to make your program fail, and it tests whether your program will fail under extreme conditions.

Taking the above example of comparing numbers as an example, it may be `0 0`, `0 10` and other conditions that are less likely to be considered. Or, taking the example of large number addition (adding two strings as numbers, for example, `'123'+'123' => '456'`), it will be:

1. `0 + 0`, adding two zeros
2. `0 + 9999`, no change after adding
3. `1 + 9999`, there will be a carry after adding

Finally, taking the example of judging palindrome, it may be:

1. Empty string
2. A string with only one character

These edge cases are easy to overlook and cause errors, so when generating test data, it is best to think about which edge cases are not considered. Many times, if you don't get full marks, it's because you didn't consider these edge cases.

But even if you get full marks, does it mean that you are really correct?

## 4. Possibility of false solutions

Generally speaking, we call those solutions that pass the OJ but are not correct as "false solutions". Usually, this happens because the test data on the OJ is too weak, so the false solution can pass.

For example, in the above problem of comparing numbers, although the problem states that M and N can be up to 400 digits, the test data may be lazy and only up to five digits at most. In this case, your solution of converting the string to a number and comparing the size can pass, but we won't say that this is the correct solution, because adding one more test data will make the answer wrong.

Or some problems do not limit the time complexity. The expected solution is O(n), but O(n^2) can also pass. Some false solutions are written and you will know that they are false solutions, but some you will not notice. This part actually depends on the OJ to check, and the test data must be carefully generated to avoid such false solutions.

## Conclusion

The reason for writing this article is to help beginners who have just started solving programming problems to understand that there are more important things to focus on before starting to solve the problem. Remember to define the problem clearly before starting to solve it, which is also one of the essential skills for whiteboard questions in job interviews.

If you find that the problem is not defined clearly when writing the problem, then this problem may not be that good. You can report it to the website and ask them to supplement the problem scope.

I wish everyone can find joy on the road of solving programming problems.
