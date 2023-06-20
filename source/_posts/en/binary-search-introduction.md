---
title: 'Introduction to Binary Search'
date: 2016-09-23 16:36
catalog: true
header-img: "/img/header_img/article-bg.png"
tags: [Algorithm]
categories:
  - Algorithm
---

## Introduction

When writing programs, we often use the "search" function. The simplest search is to find the number you want in a string of numbers, which is also our topic today.

This article will be divided into three parts. The first part will introduce the linear search method, the second part will introduce the binary search method, and the last part will discuss the different implementation methods of the binary search method under different conditions.

<!-- more -->

## Linear Search

To start with the basics, we'll start with the most basic linear search method.

Just like its name, the linear search method is "finding one by one from beginning to end", with a time complexity of O(n), which is easy to understand and implement.

``` javascript
function linear_search(array, target){
  for(var i=0; i<array.length; i++){
    if(array[i]==target) return i;
  }
  return -1; //not found
}
```

Or you can refer to this simple animation, recorded from [Algorithm Visualizations](https://www.cs.usfca.edu/~galles/visualization/Search.html)
![Linear Search Animation](/img/old-articles/binary-p1.gif)

## Binary Search

If the sequence to be searched is ordered, we can optimize the linear search method to make the time complexity even lower.

The principle of binary search is very similar to the process of playing "Ultimate Password" when we were young, that is, the game of guessing numbers from 1 to 99. In order to guess faster (or let the enemy guess faster), some people will shout the number 50 first. Why? Because no matter whether the number is less than 50 or greater than 50, the remaining numbers that can be guessed will definitely be cut in half, becoming 1/2 of the original. Assuming that this continues to be cut in half next time, it will probably take seven or eight guesses to "guarantee" that you can guess it.

Here's a simple verification:
If there is only one number, it can be guessed once.
If there are only two numbers, it can be guessed twice.
If there are only three numbers, it can be guessed twice.
If there are only four numbers, assuming they are 1 2 3 4, cut in half and guess 2, the result range becomes 3 4, leaving two numbers, which need to be guessed twice. So if there are four numbers, it will take three guesses to find it.

If there are eight numbers, cut in half and there are four left, so you need to guess 1 + 3 = 4 times.
...
Continuing to promote this, it will be found that the number of times that can be guaranteed to be guessed is related to taking log with 2 as the base.
The detailed mathematical formula will not be repeated here.

Therefore, the process of binary search is also very simple:

1. Determine the left boundary L and the right boundary R.
2. Take (L+R)/2 as the number M in the middle.
3. If array[M] == the number to be found, return.
4. If array[M]>the number to be found, it means that the numbers from M to R are impossible (because they are all larger than array[M]), so let R = M - 1.
5. If array[M]<the number to be found, it means that the numbers from L to M are impossible, so let L = M + 1.
6. If R>=L, continue with step 2, otherwise return -1 (indicating not found).

So L and R will become closer and closer to the number to be found, and each step can eliminate half of the possibilities. The stopping condition here is "when L>R", which means that it cannot be found. Because L means: the possible value on the far left, in other words, if there is an answer, it must be in the position >=L. R represents: the possible value on the far right, if there is an answer, it must be in the position <=R. So when L > R, >=L and <=R are already empty sets, indicating that there is no answer.

One thing to note here is `(L+R)/2`, which may cause overflow when the value is very large. To avoid this situation, it can be rewritten as `(R-L)/2 + L`.

You can refer to a simple animation recorded from [Algorithm Visualizations](https://www.cs.usfca.edu/~galles/visualization/Search.html)

(Blue is L, yellow is R, green is M, and the number to be found is 180)
![Binary Search Animation](/img/old-articles/binary-p2.gif)

``` javascript
function binary_search(array, target) {
  var L = 0, R = array.length - 1;
  while(L<=R) {
    var M = Math.floor((L+R)/2);
    if(array[M]==target){
      return M;
    } else if(array[M]>target) {
      R = M - 1;
    } else {
      L = M + 1;
    }
  }
  return -1;
}
```

## Binary Search under Different Conditions

The binary search introduced earlier is only used to find out whether a certain number exists in a sequence and, if so, at which position. If there are duplicate numbers in the sequence and the condition is slightly changed to return the "first" occurrence, for example, in the sequence 1 2 2 2 2 2 3 3, if we want to find 2, we return 1 because the first 2 appears at index 1.

Alternatively, we can change it to return the "last" occurrence. Using the same example as above, we want to return 5 because index 5 is the last 2.

There are even more complex variations, such as the following four:

1. Return the first position >= target
2. Return the first position > target
3. Return the last position <= target
4. Return the last position < target

(Refer to: [lower_bound](http://www.cplusplus.com/reference/algorithm/lower_bound/))

Combined with finding the first and last positions of target, there are a total of 6 variations. So how do we deal with them?

In fact, the principles are very similar. We still use binary search to eliminate the most numbers, but there are some slight differences in some condition judgments. If not done properly, it is easy to cause an infinite loop, such as finding the last number less than target:

``` javascript
function search(array, target){
  var L = 0, R = array.length - 1;
  while(L<=R) {
    var M = Math.floor((L+R)/2);
    if(array[M]<target){
      L = M;
    } else {
      R = M - 1;
    }
  }
  return M;
}
```

We use this example to run: `search([1,2,3,4,5],2)`. At the beginning, L=0, R=4, M=2. `array[2] = 3 > 2`, so `R = 2-1 = 1`. Then L=0, R=1, M=0. `array[0] = 1 < target`, so `L = M = 0`. Then it will repeat the same steps and fall into an infinite loop. This is one of the most common situations when writing binary search. Some conditions are not set properly, maybe just missing an equal sign or +1 -1, but it just can't be solved.

There are many articles on the Internet that explain how to set these conditions:

1. [Implementation and Application Summary of Binary Search](http://www.cnblogs.com/ider/archive/2012/04/01/binary_search.html)
2. [Talking about Binary Search](http://duanple.blog.163.com/blog/static/709717672009049528185/)
3. [Simple Analysis and Summary of Binary Search](http://zhengboyang.com/2016/03/18/%E4%BA%8C%E5%88%86%E6%90%9C%E7%B4%A2%E6%B3%95%E7%AE%80%E5%8D%95%E5%88%86%E6%9E%90%E4%B8%8E%E6%80%BB%E7%BB%93/)

Or this Q&A on Zhihu also has many discussions to refer to: [How many ways are there to write binary search? What are the differences?](https://www.zhihu.com/question/36132386) Among them, my favorite is [this answer](https://www.zhihu.com/question/36132386/answer/97729337):

> Speaking of interviews, the difficulty of this question lies in the final boundary condition, so we don't need to judge that boundary at all. When the interval is reduced to a small extent, such as less than 5 elements, just use sequential search. After all, it is also O(lgN), and the average number of comparisons required for sequential search of the last 5 elements is only two or three times, which is similar to your binary search. I personally recommend writing like this in actual engineering, which can avoid many troublesome bugs and solve problems in the most secure way.

I have also thought about this idea before. Since it is so troublesome to add or subtract 1 or whether to add an equal sign, why not just leave it out? Just change the termination condition and the judgment logic. Using the same example as above: finding the last number less than target.

The basic principle is:

1. Ensure that the answer is definitely in the closed interval [L, R]
2. When there are very few numbers left in this interval, use linear search instead.

This way, we don't have to worry about encountering infinite loops. The following is the code:

``` javascript
// Return the last number < target
function lower_bound(array, target) {
	
  // First, check if there is no answer
  // If the first number is still not < target, there is no answer
  if(array[0]>=target) return -1;
  
  // The end condition is when there are only two numbers left in the interval
  var L = 0, R = array.length-1;
  while((R-L+1)>2) {
    var M = Math.floor((L+R)/2);
    if(array[M]<target){
      L = M;
    } else {
      R = M - 1;
    }
  }
  
  // Use linear search within the answer range
  for(var i=R; i>=L; i--){
  	if(array[i]<target){
  		return i;
  	}
  }	
}
```

Even if the conditions change, such as finding `>=target`, `<target`, etc., as long as the conditions are modified, a similar structure can be used to obtain the answer.

## Conclusion
Actually, I wanted to study binary search in different situations, how to set those conditions, and whether there are any unified rules to refer to. But in the end, I found that the solution given at the end of the article is the most convenient, not only easy to think of, but also easy to write. There is no need to worry about the symbols of <>= and +1-1, and the execution efficiency is also similar.

I am not a professional in algorithms. If there is any mistake in the article, please kindly correct me <(_ _)>

Finally, here is the non-rigorous test and various versions of JavaScript code: https://repl.it/DgDU/1
