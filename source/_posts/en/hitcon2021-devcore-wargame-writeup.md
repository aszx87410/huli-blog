---
title: HITCON 2021 x DEVCORE Wargame Write-up
catalog: true
date: 2021-11-30 23:08:40
tags: [Security]
categories: [Security]
---

HITCON 2021 DEVCORE organized a wargame, which can be found here: https://hackmd.io/@d3vc0r3/hitcon2021

It was stated that the game can be completed within two hours, so I decided to give it a try. However, due to my lack of experience, I got stuck in one part for a long time. Apart from that, the difficulty level was not high. This article briefly records the process and experience of solving the game.

<!-- more -->

## Solution Notes

Challenge URL (may have been closed): http://web.ctf.devcore.tw/

After entering the website, it was obvious that there was a path traversal vulnerability in `image.php`, which could read any file as long as the path was base64 encoded:

![](/img/devcore-wargame/p1.jpg)

Let's read `/etc/passwd` first:

```
123root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
# find PHP source code and you will get the flag.
```

It was mentioned that the first flag can be obtained as long as the PHP source code is found. I tried some default PHP paths but to no avail. I remembered the [Balsn CTF 2021 WriteUps](https://blog.maple3142.net/2021/11/21/balsn-ctf-2021-writeups/) I read last week, which introduced a magical path `file:///proc/self/cwd`. So I read `/proc/self/cwd/index.php` and successfully obtained the contents of `index.php`!

Continuing to look for other related files based on what the file includes, we can find:

1. error.php
2. image.php
3. include.php
4. index.php
5. lang.php
6. order.php
7. pdf.php
8. print.php
9. qrcode.php
10. rate-limit.php
11. receipt.php
12. submit.php
13. success.php

We successfully obtained the first flag in `include.php`:

``` php
<?php

/*
                  _     ___   ___  _  __                
 __   __ __   __ | |   / _ \ / _ \| |/ / __   __ __   __
 \ \ / / \ \ / / | |  | | | | | | | ' /  \ \ / / \ \ / /
  \ V /   \ V /  | |__| |_| | |_| | . \   \ V /   \ V / 
   \_/     \_/   |_____\___/ \___/|_|\_\   \_/     \_/  
                                                        

   DEVCORE{no.1_path_traverse_to_the_m00n}

 */


define('IMAGE_PATH', '/usr/share/nginx/images/');

define('MYSQL_HOST', 'mysql');
define('MYSQL_USER', 'web_user');
define('MYSQL_PASSWORD', 'n%6GZgt*hH[+p7vJ');
define('MYSQL_DATABASE', 'web');

define('ORDER_STATUS_PICKING', 'PICKING');
define('ORDER_STATUS_PACKING', 'PACKING');
define('ORDER_STATUS_SENDING', 'SENDING');
define('ORDER_STATUS_DELIVERING', 'DELIVERING');
define('ORDER_STATUS_ARRIVED', 'ARRIVED');
define('ORDER_STATUS_FINISH', 'FINISH');

define('DEFAULT_LANGUAGE', 'zh-tw');
define('ALLOWED_LANGUAGE', 'zh-tw');

function session_start_once() {
    if (!isset($_SESSION)) { 
        session_start();
    }
}

session_start_once();


if (!isset($_SESSION['lang'])) {
    $_SESSION['lang'] = DEFAULT_LANGUAGE;
}

require_once('langs/' . $_SESSION['lang'] . '.php');

require_once('qrcode.php');

function base64_urlsafe_encode($input) {
    return strtr(base64_encode($input), '+/', '._');
}

function base64_urlsafe_decode($input) {
    return base64_decode(strtr($input, '._', '+/'));
}


$GLOBALS['_pdo'] = false;

function get_pdo() {
    if ($GLOBALS['_pdo']) {
        return $GLOBALS['_pdo'];
    }
    try {
        $pdo = new PDO(
                    'mysql:host='.MYSQL_HOST.';dbname='.MYSQL_DATABASE.';charset=utf8mb4',
                    MYSQL_USER, MYSQL_PASSWORD,
                    array(
                        PDO::MYSQL_ATTR_INIT_COMMAND => 'SET NAMES \'utf8mb4\' COLLATE \'utf8mb4_unicode_ci\';',
                        PDO::ATTR_TIMEOUT => 2
                    ));
        $GLOBALS['_pdo'] = $pdo;
    } catch (Exception $e) {
        http_response_code(500);
        die("Failed to connect database. Please contact the administrtor.");
    }
    return $pdo;
}

function get_post_param($key, $default=null) {
    if (isset($_POST[$key])) {
        return $_POST[$key];
    } else {
        return $default;
    }
}

function get_get_param($key, $default=null) {
    if (isset($_GET[$key])) {
        return $_GET[$key];
    } else {
        return $default;
    }
}

function get_client_ip() {
    if (!empty($_SERVER['HTTP_CLIENT_IP'])) {
        $ip = $_SERVER['HTTP_CLIENT_IP'];
    } else if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        $ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
    } else {
        $ip = $_SERVER['REMOTE_ADDR'];
    }
    return $ip;
}

function random_str(
    int $length = 64,
    string $keyspace = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
): string {
    if ($length < 1) {
        throw new \RangeException("Length must be a positive integer");
    }
    $pieces = [];
    $max = mb_strlen($keyspace, '8bit') - 1;
    for ($i = 0; $i < $length; ++$i) {
        $pieces []= $keyspace[random_int(0, $max)];
    }
    return implode('', $pieces);
}

function get_sig_hash($data) {
    $pdo = get_pdo();
    $res = $pdo->query("SELECT `value` FROM options WHERE `key` = 'sig_secret' LIMIT 1", PDO::FETCH_ASSOC);
    $row = $res->fetch();
    if (!$row) {
        $secret = random_str(64);
        $pdo->exec("INSERT INTO options VALUES ('sig_secret', '".$secret."'), ('sig_algorithm', 'sha256')");
    } else {
        $secret = $row['value'];
    }
    $res = $pdo->query("SELECT `value` FROM options WHERE `key` = 'sig_algorithm' LIMIT 1", PDO::FETCH_ASSOC);
    $algo = $res->fetch()['value'];
    return hash_hmac($algo, $data, $secret);
}

function get_timezone() {
    $pdo = get_pdo();
    $res = $pdo->query("SELECT `value` FROM options WHERE `key` = 'timezone' LIMIT 1", PDO::FETCH_ASSOC);
    $row = $res->fetch();
    if (!$row) {
        $pdo->exec("INSERT INTO options VALUES ('timezone', 'Asia/Taipei')");
        $timezone = 'Asia/Taipei';
    } else {
        $timezone = $row['value'];
    }
    return $timezone;
}

define('TIMEZONE', get_timezone());
date_default_timezone_set(TIMEZONE);

function endsWith( $haystack, $needle ) {
    $length = strlen( $needle );
    if( !$length ) {
        return true;
    }
    return substr( $haystack, -$length ) === $needle;
}


function order_status_to_text($status) {
    $text_arr = [
        ORDER_STATUS_PICKING => '撿貨',
        ORDER_STATUS_PACKING => '包裝中',
        ORDER_STATUS_SENDING => '等待貨運士取貨',
        ORDER_STATUS_DELIVERING => '配送中',
        ORDER_STATUS_ARRIVED => '貨物已送達',
        ORDER_STATUS_FINISH => '完成'
    ];
    return $text_arr[$status];
}
```

Next, I looked at each file and found that `print.php` had an obvious SQL Injection:

``` php
<?php

require_once('include.php');
require_once('third_party/vendor/autoload.php');

//require_once('rate_limit.php');
// rate limit is not working, use random sleep as a workaround
sleep(random_int(0, 2));

$is_from_print = true;

$id = get_get_param('id', '');
$sig = get_get_param('sig', '');
$sig_hash = get_sig_hash($sig);
$pdo = get_pdo();
$res = $pdo->query("
    SELECT *
    FROM orders 
    WHERE sig_hash = '$sig_hash' AND id = $id
    LIMIT 1
", PDO::FETCH_ASSOC);

try {
    $order = $res->fetch();
} catch (Error $e) {
    $order = [];
}

ob_start();
include('pdf.php');
$html = ob_get_clean();

$mpdf = new \Mpdf\Mpdf([
    'tempDir' => '/tmp',
    'autoScriptToLang' => true,
    'autoLangToFont' => true,
    'mode' => 'utf-8'
]);
$mpdf->SetTitle('收據明細');
$mpdf->SetSubject('收據明細');
$mpdf->SetAuthor(random_str((random_int(1, 256))));
$mpdf->SetCreator(random_str((random_int(1, 256))));
$mpdf->WriteHTML($html);
$mpdf->Output();
```

After manually injecting, the following information was obtained:

```
table: rate_limit
ip,last_visit,visit_times

table: items
id,title,description

table: options
key,value

table: backend_users
id,username,password,description
admin u=479_p5jV:Fsq(2

table: orders
id,name,email,phone,status,sig_hash,order_date,address,note
```

Since only one row of data can be obtained, `GROUP_CONCAT` can be used to dump data, like this: `SELECT 1,GROUP_CONCAT(note),GROUP_CONCAT(name),GROUP_CONCAT(email),5,6,7,8,9 FROM orders
`
The third flag (yes, the third, not the second) and a set of credentials were found in the `backend_users` section of the database, which may be useful later.

According to `include.php`, we got this path: `third_party/vendor/autoload.php`. It was obvious that composer was used, so we could read `/proc/self/cwd/third_party/composer.json` to find out that only one package called `mpdf` was used.

Next, let's search for known vulnerabilities. We found an issue reported by DEVCORE on the official website: [phar:// deserialization and weak randomness of temporary file name may lead to RCE](https://github.com/mpdf/mpdf/issues/1381)

From this issue, we can learn two things:

1. We can write files to `/tmp/mpf/_tempCSSidataX_0.jpeg`
2. We can use `<img src="#1.jpeg" ORIG_SRC="phar://../vendor/mpdf/mpdf/tmp/mpdf/_tempCSSidata1_0.jpeg/a.jpg"></img>` to perform deserialization

However, the problem is that we need to find a gadget that can be used to trigger the attack by deserialization. After installing the same package locally, I directly searched for methods starting with `__` in the `third_party` folder, but only found some useless things. I couldn't think of a POP attack chain.

So I got stuck.

I thought and looked at it repeatedly, except for the possibility of exploiting the phar vulnerability, the only other thing is the part in `include.php` that imports `$_SESSION['lang']`. If we can control `lang`, we can import any file, but the problem is that there is no vulnerability in `lang.php` that can be exploited to control parameters, unless we can directly modify `/tmp/sess_XXX`, otherwise we can't get in.

But the only vulnerability that can write files is in mpdf, but the file name is restricted and cannot be written anywhere, otherwise the two can be combined.

There is also a strange place that I can't figure out. I hacked into a set of backend account passwords in the DB, but there should be a backend, where is it?

Usually, when doing this kind of wargame or CTF, enumeration is not necessary, but because I really have no clue, I had to start searching. I used ffuf to scan any place that I thought might be possible, but I got nothing, so I had no clue and didn't know what to do next.

The wargame started at 9 am on Saturday, and I solved the first two flags at 10 am, and then I got stuck all day. That night, I checked and found that only 6 people had solved it, but there were many NFTs, so I asked in the chat room if there were any plans to release some hints if the solving situation was not as expected. Later, I got a reply asking what kind of information I needed.

Because the solving time was set to be until 6 pm on Sunday (the end of HITCON), I thought I would wait until it was over to ask for hints, which explained my situation (solved 1 and 3 and got stuck). Later, I got a reply saying to observe vulnerability 1 again to see if there is anything like a backend.

So I tried various paths again, and finally tried something I had seen before but had not tried: `/proc/mounts`, the content looks like this:

```
overlay / overlay rw,relatime,lowerdir=/var/lib/docker/overlay2/l/DVIDOZY6PBLWVCFYWII5AAUIJZ:/var/lib/docker/overlay2/l/3CV53MMJRHWIZWOHD5WPBJANGZ:/var/lib/docker/overlay2/l/VIRCM74GAO2ULIS6SHAVLYHI7O:/var/lib/docker/overlay2/l/QC5SROY6OOIX6VQUNGJG3T5GMY:/var/lib/docker/overlay2/l/3Z7BTZXFISPKXE3DEG4OUPAB5G:/var/lib/docker/overlay2/l/GDBX5T35WQSMHIY2USJLX6SPRU:/var/lib/docker/overlay2/l/WHFI4IRDVNIOO6MLKCKKAMYQKB:/var/lib/docker/overlay2/l/JLXT6H6QNKB45UIDZANGKVGLPD:/var/lib/docker/overlay2/l/M756SQ7NRKEJCKLHPB2PRKG5Z2:/var/lib/docker/overlay2/l/OY2PWIL6ISIIORC7LZNWWQ6JKN:/var/lib/docker/overlay2/l/GXC3IEBX7YVRSOMH34OAE6Y5LV:/var/lib/docker/overlay2/l/FNJ3ZWM4WCOCANHBZPBTO47K5B:/var/lib/docker/overlay2/l/NRVSBMR3SAZ3PNE5KXGMUQMODK:/var/lib/docker/overlay2/l/2MARFWCP5GVEAG5IBUMLJTABKL:/var/lib/docker/overlay2/l/F67HXFSPANXFWKRP2R5YJHJRBE:/var/lib/docker/overlay2/l/AKYB2LUEDDQPLGHVXECL72U4MK:/var/lib/docker/overlay2/l/B7CFODJXDKC3HEX5ZJD7NAID5A:/var/lib/docker/overlay2/l/5XQVILRBQTSFRMEKB7YW6UTYLB:/var/lib/docker/overlay2/l/6ZMT3PTB6QFDZ2PJOURGMQZIMJ:/var/lib/docker/overlay2/l/4AUQ72KT7D5WLPX3GCGBI576ZS:/var/lib/docker/overlay2/l/HEF7KMRLHAUNHLXAPU5T4QFJJD:/var/lib/docker/overlay2/l/ZEPQYM2UZQKKXKJS62CP5RIRKN:/var/lib/docker/overlay2/l/4BBAOHRGSZ3TVLTD4ZICVZS7C7:/var/lib/docker/overlay2/l/3K7P7JABJCB4HT5HZRXGBFSSAU:/var/lib/docker/overlay2/l/GUW5ZGQOABGYH7KF5IU5JFHG6E:/var/lib/docker/overlay2/l/RKL5CJMH6X7ORW4XAB5HJ3RJ3C:/var/lib/docker/overlay2/l/ZLWG5Z6C6FD3OQEJCZHJHODTTX:/var/lib/docker/overlay2/l/QLSXNQZKZQQ3YDAFJ675RXRFWL:/var/lib/docker/overlay2/l/KHQSPHLSLWASTCLEBPKWK7AABD:/var/lib/docker/overlay2/l/GCM3GAH2MB2FBUK2NUGCCQ6H6R:/var/lib/docker/overlay2/l/FVHE6ZGSGB26C3JN35T36U575B:/var/lib/docker/overlay2/l/A3B3RQ7O6RTEZTZDFCBNL3R2IG:/var/lib/docker/overlay2/l/VWEM5H2WW7HEKTCLCWBPPEV4RA:/var/lib/docker/overlay2/l/QAYAOZL2DM73CJVN7Y3J7MRXDP:/var/lib/docker/overlay2/l/CGI6OQSFKKJRGSKZASWCHJDJIM,upperdir=/var/lib/docker/overlay2/ea857d9fda05b6fb0c5b7d79544f8d05943163aec8ecce2c8aaede2a93bd0b1b/diff,workdir=/var/lib/docker/overlay2/ea857d9fda05b6fb0c5b7d79544f8d05943163aec8ecce2c8aaede2a93bd0b1b/work 0 0
proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0
tmpfs /dev tmpfs rw,nosuid,size=65536k,mode=755 0 0
devpts /dev/pts devpts rw,nosuid,noexec,relatime,gid=5,mode=620,ptmxmode=666 0 0
sysfs /sys sysfs ro,nosuid,nodev,noexec,relatime 0 0
tmpfs /sys/fs/cgroup tmpfs rw,nosuid,nodev,noexec,relatime,mode=755 0 0
cgroup /sys/fs/cgroup/systemd cgroup ro,nosuid,nodev,noexec,relatime,xattr,name=systemd 0 0
cgroup /sys/fs/cgroup/freezer cgroup ro,nosuid,nodev,noexec,relatime,freezer 0 0
cgroup /sys/fs/cgroup/hugetlb cgroup ro,nosuid,nodev,noexec,relatime,hugetlb 0 0
cgroup /sys/fs/cgroup/cpu,cpuacct cgroup ro,nosuid,nodev,noexec,relatime,cpu,cpuacct 0 0
cgroup /sys/fs/cgroup/perf_event cgroup ro,nosuid,nodev,noexec,relatime,perf_event 0 0
cgroup /sys/fs/cgroup/net_cls,net_prio cgroup ro,nosuid,nodev,noexec,relatime,net_cls,net_prio 0 0
cgroup /sys/fs/cgroup/pids cgroup ro,nosuid,nodev,noexec,relatime,pids 0 0
cgroup /sys/fs/cgroup/rdma cgroup ro,nosuid,nodev,noexec,relatime,rdma 0 0
cgroup /sys/fs/cgroup/blkio cgroup ro,nosuid,nodev,noexec,relatime,blkio 0 0
cgroup /sys/fs/cgroup/devices cgroup ro,nosuid,nodev,noexec,relatime,devices 0 0
cgroup /sys/fs/cgroup/memory cgroup ro,nosuid,nodev,noexec,relatime,memory 0 0
cgroup /sys/fs/cgroup/cpuset cgroup ro,nosuid,nodev,noexec,relatime,cpuset 0 0
mqueue /dev/mqueue mqueue rw,nosuid,nodev,noexec,relatime 0 0
shm /dev/shm tmpfs rw,nosuid,nodev,noexec,relatime,size=65536k 0 0
/dev/sda /etc/hosts ext4 rw,relatime,errors=remount-ro,data=ordered 0 0
/dev/sda /etc/resolv.conf ext4 rw,relatime,errors=remount-ro,data=ordered 0 0
/dev/sda /etc/hostname ext4 rw,relatime,errors=remount-ro,data=ordered 0 0
/dev/sda /usr/share/nginx/frontend ext4 ro,relatime,errors=remount-ro,data=ordered 0 0
/dev/sda /usr/share/nginx/images ext4 rw,relatime,errors=remount-ro,data=ordered 0 0
/dev/sda /usr/share/nginx/b8ck3nd ext4 ro,relatime,errors=remount-ro,data=ordered 0 0
/dev/sda /usr/local/etc/php/php.ini ext4 ro,relatime,errors=remount-ro,data=ordered 0 0
proc /proc/bus proc ro,nosuid,nodev,noexec,relatime 0 0
proc /proc/fs proc ro,nosuid,nodev,noexec,relatime 0 0
proc /proc/irq proc ro,nosuid,nodev,noexec,relatime 0 0
proc /proc/sys proc ro,nosuid,nodev,noexec,relatime 0 0
proc /proc/sysrq-trigger proc ro,nosuid,nodev,noexec,relatime 0 0
tmpfs /proc/acpi tmpfs ro,relatime 0 0
tmpfs /proc/kcore tmpfs rw,nosuid,size=65536k,mode=755 0 0
tmpfs /proc/keys tmpfs rw,nosuid,size=65536k,mode=755 0 0
tmpfs /proc/timer_list tmpfs rw,nosuid,size=65536k,mode=755 0 0
tmpfs /proc/sched_debug tmpfs rw,nosuid,size=65536k,mode=755 0 0
tmpfs /proc/scsi tmpfs ro,relatime 0 0
tmpfs /sys/firmware tmpfs ro,relatime 0 0
```

Inside, you can directly see several important paths:

```
/dev/sda /usr/share/nginx/frontend ext4 ro,relatime,errors=remount-ro,data=ordered 0 0
/dev/sda /usr/share/nginx/images ext4 rw,relatime,errors=remount-ro,data=ordered 0 0
/dev/sda /usr/share/nginx/b8ck3nd ext4 ro,relatime,errors=remount-ro,data=ordered 0 0
/dev/sda /usr/local/etc/php/php.ini ext4 ro,relatime,errors=remount-ro,data=ordered 0 0
```

Yes, I missed this at the beginning, and it took me a whole day to find it.

After finding this, things became easier. When I entered `b8ck3nd/index.php`, I was directly redirected to the homepage. I remembered some utils functions I saw in `include.php` and tried adding `X-Forwarded-For: 127.0.0.1` to bypass it and go to the login page. The login account and password used the one I got from the SQL injection earlier. After successfully logging in, I got the fourth flag.

Then I found an `upload.php` in the backend, which can upload any file:

``` php
<?php

require_once('include.php');

if ($_SERVER['REQUEST_METHOD'] == 'GET') {
    header('Content-Type: text/plain');
    echo 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkZha2UgdG9rZW4gZm9yIGNrZWRpdG9yIiwiaWF0IjoxNTE2MjM5MDIyfQ.6nNLxp10uP65V_NFrs5IWuX2tkk6vGQ-oiwYhHNdHgk';
    exit();
}

if (isset($_FILES['file']) && is_uploaded_file($_FILES['file']['tmp_name'])) {
    header('Content-Type: application/json; charset=utf-8');
    $ext = pathinfo($_FILES['file']['name'], PATHINFO_EXTENSION);
    $filename = random_str(32).'.'.$ext;
    if (isset($_POST['rename'])) {
        $filename = $_POST['rename'];
    }
    if (isset($_POST['folder'])) {
        $folder = $_POST['folder'];
        if (!file_exists(IMAGE_PATH.$folder)) {
            mkdir(IMAGE_PATH.$folder);
        }
        $filename = $folder.'/'.$filename;
    }
    $filepath = IMAGE_PATH . $filename;
    move_uploaded_file($_FILES['file']['tmp_name'], $filepath);
    system("rsync_wrap ".escapeshellarg($filepath));
    $id = base64_urlsafe_encode($filename);
    echo json_encode([
        'default' => '/image.php?id='.$id
    ]);
} else {
    http_response_code(400);
}
```

First, try to upload it to `../../../../../usr/share/nginx/frontend` and see, and then I got the fifth flag:

![](/img/devcore-wargame/p3.png)

But when I tried it, I found that the file was not actually written, and I tried other paths, such as `b8ck3nd`, or I thought it might be written to `/usr/share/nginx/frontend/third_party/vendor` and then triggered the phar vulnerability mentioned earlier (which seems reasonable), but it couldn't be written here either.

Or write it into `langs` and switch languages to import files, but it couldn't be written here either.

After thinking for a while, I tried writing it to `/tmp`, which worked fine, so the answer was obvious. First, write a file `/tmp/test1234.php`, and then write `/tmp/sess_abc`. Because the session file content can be manipulated, you can fill in the desired lang and manipulate the value of `$_SESSION['lang']`, and then use the `include.php` mentioned at the beginning to import the web shell you wrote, and you can get RCE.

After RCE, you can execute `/readflag` in the root directory to read the flag.

So I missed the second flag alone, and I completed all the others, but where is the last one? After getting the shell, I went inside and looked around a bit. I originally thought it might be in the nginx config, but I couldn't find it no matter how I looked (even at the end, I didn't find where the nginx config was).

After about half an hour, the order of the appearance of the flags should be similar to the order of the difficulty of the solutions. Since the first flag is Path Traversal and the third flag is SQL injection, the second flag should appear between the two. So I suddenly had an idea and thought, "It can't be..."

Then go to http://web.ctf.devcore.tw/order.php?id=1&sig[]=1

The second flag appeared in front of me like this:

![](/img/devcore-wargame/p4.png)

## Summary

Finally, let's review the problems encountered this time.

The most serious problem is that the critical file was not found when reading the file, which caused the whole thing to get stuck later.

In the future, when encountering vulnerabilities that can read local files, you should create a dictionary file yourself. Otherwise, you will have to google for a long time to find out which files can be read each time. I will write an article to summarize this later.

The second issue is that I didn't notice the second flag. Actually, when doing SQL injection, if all the data that should be obtained has been obtained, it should be visible. Therefore, in the future, remember to dump the entire database.

Overall, I think it's quite fun. Thanks to DEVCORE's wargame, and finally, because the challenge time was extended a bit, I successfully obtained the challenger NFT issued by DEVCORE!

![](/img/devcore-wargame/p5.png)
