---
title: '[Rails] 快速打造一個超級陽春的部落格 '
date: 2014-05-23 14:14
catalog: true
header-img: "/img/header_img/article-bg.png"
tags: [backend,rails]
---
在Coursera上面有一門新墨西哥大學開設的課：[Web 應用程序架構](https://class.coursera.org/webapplications-001/)
裡面先從網路的歷史、架構開始講起，接著談到Ruby還有Rails，然後再介紹基礎的html/css/js/ajax
整個課程我覺得還滿適合新手的，無論是Rails的新手或者是對整個網頁開發不懂的人都很適合，如果英文聽力不太好的話，也提供了英文字幕可以看，如果英文看不懂的，裡面的英文都不難，比較多技術名詞，而且圖也滿多的，再不然的話，就只看code吧XD

這篇文章的內容基本上算是我看完這門課以後動手實作的一些心得筆記，如果有錯誤的話還麻煩大家幫我指正。
最後做出來的成果是一個超級簡單的blog，就是只有發文跟評論兩個功能而已，不過可以從這個小範例裡面學到很多東西。
<!-- more -->

一開始先建立一個新的project
`rails new blog`

切換到/blog底下
`cd blog`

用rails提供的scaffold指令，快速的建造出文章跟評論的架構
`rails generate scaffold post title:string body:text`
`rails generate scaffold comment post_id:integer body:text`
（`rails generate`可用`rails g` 代替）

接著要在資料庫裡面產生這兩個table，所以我們使用
`rake db:migrate`

可以用 `rake routes`來看看url跟controller對應的情形

`rails server` （或是可直接打`rails `）
啟動伺服器來看看目前的狀況

你只要到http://localhost:3000 就可以看到了

咦？怎麼什麼都沒有？
因為首頁還是長一樣沒有更動
所以要到 http://localhost:3000/posts
就可以看到一個文章列表
可以自己試試看發文/修改/刪除

要看到評論的做法也一樣 http://localhost:3000/comments

目前這樣可以看出已經有個雛形，剩下的只要把文章跟評論連在一起（而不是這樣單獨出現）就大功告成了
post跟comment有一個 **many-to-one** 的關係，那就是一篇文章有很多個評論，而一個評論只會對應到一篇文章

打開 `/app/models/post.rb`，加上一行 `has_many :comments`
``` ruby /app/models/post.rb
class Post < ActiveRecord::Base
	has_many :comments
end
```

打開`/app/models/comment.rb`，加上`belongs_to :post`
``` ruby /app/models/comment.rb
class Comment < ActiveRecord::Base
	belongs_to :post
end
```

還有一件事要做，那就是當一篇文章刪除的時候，那篇文章的評論也要被刪除掉
``` ruby /app/models/post.rb
class Post < ActiveRecord::Base
	has_many :comments, dependent: :destroy
end
```

接著要做一點資料驗證，因為不希望會有空白的文章或是評論
``` ruby /app/models/post.rb
class Post < ActiveRecord::Base
	has_many :comments, dependent: :destroy
	validates_presence_of :title
	validates_presence_of :body
end
```

``` ruby /app/models/comment.rb
class Comment < ActiveRecord::Base
	belongs_to :post
	validates_presence_of :post_id
	validates_presence_of :body
end
```

雖然post跟comment現在可以連在一起了，但是在網頁上看到的仍舊是兩個獨立的頁面
所以要去修改view，讓他們可以串起來

在串起來之前，要先改一下routes
把comments放到posts底下

``` ruby /config/routes.rb
Blog::Application.routes.draw do
  

  resources :posts do
    resources :comments
  end
end
```

``` erb /app/views/posts/show.html.erb
<p id="notice"><%= notice %></p>

<p>
  <strong>Title:</strong>
  <%= @post.title %>
</p>

<p>
  <strong>Body:</strong>
  <%= @post.body %>
</p>

<h2>評論</h2>
<div id="comments">
	<% @post.comments.each do |comment| %>
		<%= div_for comment do %>
		<p>
			<strong>發表於 <%= time_ago_in_words(comment.created_at)%> 前</strong></p><br />
			<%= h(comment.body) %>
		</p>
		<% end %>
	<% end %>
</div>

<%= link_to 'Edit', edit_post_path(@post) %> |
<%= link_to 'Back', posts_path %>
```
從上面這段code可以看出rails提供了很多內建函式，像是`div_for`與`time_ago_in_words`

但是除了顯示評論，應該還要讓使用者可以直接在文章底下發表評論，所以要加上一個表單
``` erb /app/views/posts/show.html.erb
<%= form_for([@post, Comment.new]) do |f| %>
	<p>
		<%= f.label :body, "新的回應"%><br />
		<%= f.text_area :body%>
	</p>
	<p><%= f.submit "新增回應" %></p>
<% end %>
```

這樣子會出錯，因為comment的post_id不知道要是多少，所以要去改comment的create方法

``` ruby /app/controllers/comment_controller/rb
  def create
    @post = Post.find(params[:post_id])
    @comment = @post.comments.create(comment_params)

    respond_to do |format|
      if @comment.save
        format.html { redirect_to @post, notice: 'Comment was successfully created.' }
        format.json { render action: 'show', status: :created, location: @comment }
      else
        format.html { render action: 'new' }
        format.json { render json: @comment.errors, status: :unprocessable_entity }
      end
    end
  end
```

然後呢，我們不希望所有人都可以發表文章，所以要做一點身分驗證
加上一行
``` ruby /app/controllers/post_controller.rb
before_action :authenticate, except: [:index, :show]
```
在執行除了index跟show兩個方法以前，先去執行`authenticate`這個方法

接下來就是在下面的地方實際撰寫這個方法的程式碼
``` ruby /app/controllers/post_controller.rb
private
 ...
def authenticate
  authenticate_or_request_with_http_basic do |name, password|
     name == "admin" && password=="secret"
   end
end
```

就可以很方便的利用rails提供的函式，去做簡單的身分驗證

做到這邊，其實這個blog系統就已經完成90%了
或是說，如果只是要求可以用的話，那已經完成了！
剩下的工作只是再增加一點code，讓程式碼跟這個系統都變得更好，也順便可以介紹到更多跟rails有關的東西

我們要把送出評論這個功能用ajax來達成，還要把顯示評論的這個部分抽取出來
先找到我們想要抽出來的程式碼
``` ruby /app/views/posts/show.html.erb
		<%= div_for comment do %>
		<p>
			<strong>發表於 <%= time_ago_in_words(comment.created_at)%> 前</strong></p><br />
			<%= h(comment.body) %>
		</p>
		<% end %>
```

然後要建立一個partial html，用底線開頭讓rails知道他是partial
``` ruby /app/views/comments/_comment.html.rb
		<%= div_for comment do %>
		<p>
			<strong>發表於 <%= time_ago_in_words(comment.created_at)%> 前</strong></p><br />
			<%= h(comment.body) %>
		</p>
		<% end %>
```

再來則是要加入ajax的部份，先在送出評論的表單上面加上`remote: true`
``` ruby /app/views/post/show.html.erb
<%= form_for([@post, Comment.new], remote: true) do |f| %>
	<p>
		<%= f.label :body, "新的回應" %><br />
		<%= f.text_area :body %>
	</p>
	<p><%= f.submit "新增回應" %></p>
<% end %>
```

在comment的controller裡面，必須多指定一種格式
``` ruby /app/controllers/comments_controller.rb
  def create
    @post = Post.find(params[:post_id])
    @comment = @post.comments.create(comment_params)

    respond_to do |format|
      if @comment.save
        format.html { redirect_to @post, notice: 'Comment was successfully created.' }
        format.json { render action: 'show', status: :created, location: @comment }
        format.js #新增這行
      else
        format.html { render action: 'new' }
        format.json { render json: @comment.errors, status: :unprocessable_entity }
      end
    end
  end
```

如果沒有指定，預設會回傳`create.js.erb`回去
所以下一步就是建立這個檔案囉

``` ruby /app/views/comments/create.js.erb
var new_comment = $("<%= escape_javascript(render(:partial => @comment)) %>").hide();
$("#comments").prepend(new_comment);
$("#comment_<%= @comment.id %>").fadeIn("slow");
$("#new_comment")[0].reset();
```

最後呢，我們既然都把顯示comment的地方抽出來了，原本的`show.html.erb`就可以用那個抽取出來的部分了
``` rubty /app/views/posts/show.html.erb
<h2>評論</h2>
<div id="comments">
	<%= render :partial => @post.comments.reverse %>
</div>
```
這個樣子，評論就會按照時間順序倒著排了




