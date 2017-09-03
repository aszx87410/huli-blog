---
title: '[Android] viewpager切換頁面，action bar延遲現象'
date: 2015-06-22 17:00
catalog: true
header-img: "/img/header_img/article-bg.png"
tags: [Android]
---
我用Viewpager搭配action bar的tab來做fragment之間的切換
每個Fragment都加上`setHasOptionsMenu(true);`，讓每個fragment都有自己對應的Action Bar
但是卻有個問題，那就是用ViewPager滑到Framgent上的時候，會延遲個一秒才換成新的Action bar
這點看了實在是很不順眼

解法是把action bar切換的地方寫在Activity裡面
``` java
@Override
public void onTabSelected(ActionBar.Tab tab, FragmentTransaction ft) {
    invalidateOptionsMenu();
}
```

``` java
@Override
    public boolean onCreateOptionsMenu(Menu menu) {
        int position = viewPager.getCurrentItem();
        if(position==0) {
            getMenuInflater().inflate(R.menu.friend, menu);
        }else if(position==1){
            getMenuInflater().inflate(R.menu.chat, menu);
        }else{

        }
        return super.onCreateOptionsMenu(menu);
    }
```

這樣就可以流暢的切換action bar了