---
title: '[Android] searchView筆記'
date: 2015-07-20 18:17
catalog: true
header-img: "/img/header_img/article-bg.png"
tags: [Android]
---

searchView就是出現在actionBar上面的那個東西
原本只是個搜尋的icon，點下去之後就會變出editText讓你輸入文字，實在是太神啦
要使用其實就是在menu的layout裡面加一個item
``` xml
<item
        android:id="@+id/action_search"
        android:icon="@drawable/ic_search_white_24dp"
        android:title="@string/search"
        app:actionViewClass="android.support.v7.widget.SearchView"
        app:showAsAction="ifRoom|collapseActionView" />
```

接著講一下我的使用情境跟碰到的問題
我有一個`ActionBarActivity`跟兩個fragment，是當作tab來用，所以我點a可以跳到a fragment，actionbar會出現搜尋框，點下去是搜尋朋友的意思，點b跳到b fragment，搜尋是搜尋訊息的意思。

第一個問題就是我要怎麼實作這個搜尋功能
我在fragment裡面寫下
``` java
final private android.support.v7.widget.SearchView.OnQueryTextListener queryListener = new android.support.v7.widget.SearchView.OnQueryTextListener() {

        @Override
        public boolean onQueryTextChange(String newText) {

            //直接丟給filter
            MessageListMainFragment.this.adapter.getFilter().filter(newText);
            return false;
        }

        @Override
        public boolean onQueryTextSubmit(String query) {
            Log.d(TAG, "submit:"+query);
            return false;
        }
    };
    
@Override
    public void onCreateOptionsMenu(Menu menu, MenuInflater inflater) {
        super.onCreateOptionsMenu(menu, inflater);
        try {
            SearchView searchView = (SearchView) MenuItemCompat.getActionView(menu.findItem(R.id.action_search));
            searchView.setOnQueryTextListener(queryListener);
        }catch(Exception e){

        }
    }
```

接著讓adapter去實作filter就結束了，實在是可喜可賀

第二個問題是我搜尋按下去之後，如果我按back，搜尋框還會在，但我預期的行為是搜尋框會變回搜尋的icon
於是在activity裡面我這樣寫
``` java
@Override
    public boolean onCreateOptionsMenu(Menu menu) {
        int position = viewPager.getCurrentItem();
        if(position==0) {
            getMenuInflater().inflate(R.menu.friend, menu);
        }else if(position==1){
            getMenuInflater().inflate(R.menu.chat, menu);
        }else{
            //直接return
            return super.onCreateOptionsMenu(menu);
        }
        mMenuItem = menu.findItem(R.id.action_search);
        searchView = (SearchView) MenuItemCompat.getActionView(mMenuItem);
        return super.onCreateOptionsMenu(menu);
    }
```

然後覆寫一下back事件
``` java
 @Override
public void onBackPressed() {
    if (searchView!=null && !searchView.isIconified()) {
        MenuItemCompat.collapseActionView(mMenuItem);
        return;
    }
}
```

就可以正確的關閉了

ref:
[How do I close a SearchView programmatically?](http://stackoverflow.com/questions/17506230/how-do-i-close-a-searchview-programmatically)
[How to dismiss/close/collapse SearchView in ActionBar in MainActivity?](http://stackoverflow.com/questions/23928253/how-to-dismiss-close-collapse-searchview-in-actionbar-in-mainactivity)
[Android Actionbar Search widget implementation In ListFragment](http://stackoverflow.com/questions/9556795/android-actionbar-search-widget-implementation-in-listfragment)
[搜索框（SearchView）的功能与用法](http://www.cnblogs.com/wolipengbo/p/3392347.html)
[Android searchView和listview实现搜索](http://blog.csdn.net/yelangjueqi/article/details/8994726)
[Android appcompat API 10 collapse action view](http://stackoverflow.com/questions/22621122/android-appcompat-api-10-collapse-action-view)
