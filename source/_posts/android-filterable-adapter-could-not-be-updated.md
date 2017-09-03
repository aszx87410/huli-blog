---
title: '[Android] Filterable的adapter無法更新'
date: 2015-07-20 18:30
catalog: true
header-img: "/img/header_img/article-bg.png"
tags: [Android]
---

今天實做一個功能的時候碰到問題，我現在有一個listview是顯示一些資料，例如說通訊錄好了
會不定時從server拿新資料回來，所以listview可能會有變動，變動的話就是把新的資料add進list裡面
接著`adapter.notifyDataSetChanged()`，這很稀鬆平常，也確定可以跑

然後我想加入一個新功能，那就是有個editText，上面輸入文字可以同步篩選listview的內容
這我之前的文章有介紹到，就是讓adapter去implement `Filterable`，多加一些function之後就可以了
試過之後的確可以篩選，但是問題來了，那就是沒有辦法更新了
新的資料進來以後看不到相對應的改變

上網google之後只發現這篇：[ListView Not Updating After Filtering](http://stackoverflow.com/questions/3414490/listview-not-updating-after-filtering)

裡面講滿多東西的，後來我就自己在一些地方加log測測看
解法是加一個function，強制把裡面存的list改掉
``` java adapter.java
public void changeList(List<MessageThread> list){
	threads = list;
}
```

在外面call的時候
``` java activity.java

//list是新的資料
MessageListMainFragment.this.adapter.changeList(list);
MessageListMainFragment.this.adapter.getFilter().filter("");
adapter.notifyDataSetChanged();
```

接著對adapter裡面的`performFiltering` function做一點小修改
本來有段code會是
``` java adapter.java
ArrayList<MessageThread> list = new ArrayList<>(original_threads);
result.values = list;
result.count = list.size();
```

改成
``` java adapter.java
// 新增下面這幾行，不然的話list 不會更新
if(threads.size()>0){
    original_threads = threads;
}

ArrayList<MessageThread> list = new ArrayList<>(original_threads);
result.values = list;
result.count = list.size();
```

就可以正確地跑出結果了

附上這個function的完整code給大家參考
``` java adapter.java
@Override
protected FilterResults performFiltering(CharSequence constraint) {
    constraint = constraint.toString();
    FilterResults result = new FilterResults();
    if (original_threads == null) {
        synchronized (this) {
            original_threads = new ArrayList<MessageThread>(threads);
        }
    }
    if(constraint != null && constraint.toString().length() > 0) {
        ArrayList<MessageThread> filteredItems = new ArrayList<>();
        for(int i = 0, l = original_threads.size(); i < l; i++) {
            MessageThread m = original_threads.get(i);

            // 統一轉小寫
            if(m.getName().toLowerCase().contains(constraint.toString().toLowerCase())){
                filteredItems.add(m);
            }
        }
        result.count = filteredItems.size();
        result.values = filteredItems;
    }else{
        synchronized(this) {

            // 新增下面這幾行，不然的話list 不會更新
            if(threads.size()>0){
                original_threads = threads;
            }
            ArrayList<MessageThread> list = new ArrayList<>(original_threads);
            result.values = list;
            result.count = list.size();
        }
    }
    return result;
}
```