# BUUOJ

## Pwn

### test_your_nc
- 没啥好说的，直接nc连上就看到了flag

### rip
- 发现401186处有函数fun，该函数会直接执行shell
- 因此目的就是劫持程序流到fun函数，利用点是gets函数
- 但是有一个坑点在于，BUUOJ所用Ubuntu18对于64位程序调用system时需要维持**栈平衡**，一旦系统检测到栈帧不平衡，则会getshell失败
    - 所谓栈平衡，其实就是esp的值对齐16byte
    - 然而我们在加上偏移与8字节rbp后，rsp只会和8字节对齐
    - 那么就需要增加payload的长度，但又能使程序流发生改变
- 具体做法：可以在覆盖rbp的地址后增加一retn的地址，此时已经对齐了16字节，但是能不能实现攻击呢？
    - 因为retn相当于pop rip，因此执行到覆盖的这个retn时，rip的值为新retn的地址，然后去执行
    - 执行这个新retn时，又会pop rip，相当于啥也没干平白无故把esp拉高了8字节，而基本逻辑与没有栈平衡是一样的，此时rsp指向了后面的fun函数地址，rip自然就被篡改了

- payload组成
    - payload = b'A' * (0x0F + 0x8) + p64(0x40112A) + p64(0x401186) # 栈平衡
- flag为
    - flag{b764c3c9-c4b1-4849-a027-1c71ee8c9ab9}
> https://blog.csdn.net/qq_42747131/article/details/106121093
http://blog.eonew.cn/archives/958


### warmup_csaw_2016
- 打开ida64，发现函数sub_40060D内部直接会读取flag，结合gets函数，就可以溢出到sub_40060D函数地址，并令其执行
- 因此payload组成就是
    - payload = 'A'*(0x40 + 0x8) + p64(0x40060D)
    - 得到flag为flag{9fc79de1-5fdf-4263-81d5-e47097f4b27f}


- 但同样会由于栈不平衡导致有报错信息，但不影响程序的执行

### pwn1_sctf_2016
- 使用IDA打开后，发现是C++逆向，这个就很难受了
- C++的各种奇怪机制会让代码逻辑看起来很混乱
- ![e3a62ceaa1c7f0dbf635cd1080cba072.png](evernotecid://CCF81846-0ED6-43C2-B4C1-E5FA28B18FC2/appyinxiangcom/28478781/ENResource/p230)

- 发现代码中似乎使用了replace来对I和you进行替换操作，但这里的伪码真的很反人类。后来学习一点C++逆向才知道，string的操作中只有看到operator=这种操作，才算是对结果计算完成并赋值，单纯地调用函数并不代表完整的操作过程
- 因此结合replace和下面这句话来看，基本功能就是把输入中的I换成you
- 而且替换后的句子会重新赋值给栈上数据，从而使其溢出
- 编写payload为
    - payload = 'I' * 0x14 + b'A' * 4 + p32(get_flag_address)
    - flag为flag{5be71f24-be44-4181-bec7-1b7f92e7baf3}

- https://xz.aliyun.com/t/4890
> 其实这道题如果用调试+运行的方法就可以很快看出来代码做了啥，所以拿到binary最好还是先运行起来再说别的（或者说如果分析不下去了，就先跑一跑看看结果）

### ciscn_2019_n_1
- 64位程序，拖入IDA查看
    - ![b203d778628871e26fa57f27c60f2bca.png](evernotecid://CCF81846-0ED6-43C2-B4C1-E5FA28B18FC2/appyinxiangcom/28478781/ENResource/p258)
    - 可知基本逻辑是使用户输入将v2篡改为11.28125
- v2的位置在rbp-4h，用户输入v1的位置在rbp-30h，二者的距离是30-4h，要覆盖的内容为11.28125这个float的64位形式
- 转化方法则使用struct进行格式化：
    - ![c805336e22da997509c02c32939e4a9c.png](evernotecid://CCF81846-0ED6-43C2-B4C1-E5FA28B18FC2/appyinxiangcom/28478781/ENResource/p259)
    - 即先按float转换成中间值，再转成int格式
    - 如果是double，则需要先d再Q（float是先f再I）
- 之后直接发送payload即可
    - ![1966b3a26db3f6670d5fa44ce151850d.png](evernotecid://CCF81846-0ED6-43C2-B4C1-E5FA28B18FC2/appyinxiangcom/28478781/ENResource/p260)
    - 得到flag为flag{d78db36d-9bc8-481b-86c8-0ac938fa3fb0}

### jarvisoj_level0
- 拖入ida64后发现有callsystem这个利用函数
- ![f372b992f8c491ca8b3c2336afc52004.png](evernotecid://CCF81846-0ED6-43C2-B4C1-E5FA28B18FC2/appyinxiangcom/28478781/ENResource/p261)
- 因此目标就是利用read函数，将输出溢出到这个函数地址，令其执行shell
- 缓冲区距离rbp位置为80h，加rbp的8h后，将地址改为0x0400596
    - ![dc97b804d290452075294078f740fe79.png](evernotecid://CCF81846-0ED6-43C2-B4C1-E5FA28B18FC2/appyinxiangcom/28478781/ENResource/p262)
    - 得到flag为flag{a5293c67-519a-4069-9f6a-4cf49d304a79}
- 此题无需考虑栈平衡是因为题目环境为ubuntu16，不存在ubuntu18内核中对于栈平衡的监视

### ciscn_2019_c_1
- 拖入ida64后发现这是一个具有基本交互的小程序，首先动态运行起来
    - ![8b5f965a8bd512d2d4b71f113ec6621d.png](evernotecid://CCF81846-0ED6-43C2-B4C1-E5FA28B18FC2/appyinxiangcom/28478781/ENResource/p263)
    - 用户有两个输入点，v4和s，其中v4是决定程序执行逻辑的，s是由gets进行读取，即真正可溢出的区域
    - 同时发现使用libc，因此该题就是64位栈平衡下的sudoku

- 那么基本逻辑就是先内存泄露出特定函数的地址，然后确定libc的基地址，那么就能得到system的地址，从而打开shell
- 首先这是个64位的栈溢出，因此给putsplt传参时不能简单放置，需要使用寄存器rdi传参。
    - 那么需要找到程序中如pop rdi;ret的gadget
    - 这个gadget在栈上被执行时，rip跳转到pop rdi;ret所在地址，CPU执行这个语句
    - 因此pop rdi;ret地址上方要放入putsgot偏移，即puts的实际参数。由此pop时栈顶就是参数，直接赋给rdi后即可
    - 之后就能用内存泄露的方法打印出puts的实际地址
    - 该步骤shellcode的组成为 padding + address_pop_rdi + address_puts_got + address_puts_plt + resume_addr

> 在64位rop中仅控制栈不行，还得控制寄存器。但是基本思路不变，即被调用的函数不知道外面发生了什么，它只管自己的参数有没有，最后要返回到哪里。本题中参数由rdi负责，因此栈就不用像32位那样布局了。但是记得在调用puts函数后，把要恢复的地址也填上，即puts函数执行完后，会把旧ebp那个位置的地址当作自己的return address，然后返回。


- 接下来就是基址的查找以及shell地址的计算，都比较套路化了
    - 内存泄露：libc版本与基址查找
    - ![55def3940ef34e363fe085bc9d64a643.png](evernotecid://CCF81846-0ED6-43C2-B4C1-E5FA28B18FC2/appyinxiangcom/28478781/ENResource/p265)
    - 查看最后12bit即9c0，得到libc版本和其他偏移如下
    - ![4d295671ad9df080265cacacd1022e79.png](evernotecid://CCF81846-0ED6-43C2-B4C1-E5FA28B18FC2/appyinxiangcom/28478781/ENResource/p266)
- 计算shell的真正地址，即可getshell（记得getshell时要栈平衡）
    - ![7154183dba23fd8837c2d9213d7ea149.png](evernotecid://CCF81846-0ED6-43C2-B4C1-E5FA28B18FC2/appyinxiangcom/28478781/ENResource/p268)
    - flag为flag{222576ab-2a1f-4397-b711-c446413cd15c}
    

### OGeek2019 babyrop
- 拖入ida后发现，首先程序会生成一个随机数
    - ![ade27828281b744e08e2e7f270e1c0f5.png](evernotecid://CCF81846-0ED6-43C2-B4C1-E5FA28B18FC2/appyinxiangcom/28478781/ENResource/p269)
    - 注意这里read并不是read stdin，而是read打开的那个随机数流，因此此处的buf实际上是系统生成的**随机数**
   
- 之后进入sub_804871F函数会真正read stdin，并将用户输入与之前的随机数进行**strncmp**的对比。
    - 对比通过后，会提示用户correct

> 这里就提示我们可能要用00截断绕过开始的验证

- 之后返回一个局部变量，并将其作为sub_80487D0函数的输入。该输入会被直接用作第二次read stdin的缓冲区长度（当然是越长越好了）
    - ![4769b1a70601347b1898d9223a731998.png](evernotecid://CCF81846-0ED6-43C2-B4C1-E5FA28B18FC2/appyinxiangcom/28478781/ENResource/p270)
    - 所以我们希望让参数等于a1，这样就能读 c8个unsigned int（4字节）数据了，这是大于缓冲区距离E7的

- 那么我们目标就明确为覆盖返回值v5。这该咋覆盖呢？不是有我们刚输入的buf么，这俩一个偏移是25，另一个是2c，那么当你输入的buf够长时就会自动把v5给覆盖成你想要的值
    - 因此，为能进入我们真正要攻击的ret2libc部分，先得发送一个payload进入函数sub_80487D0
    - payload：'\x00' + '\xff' * 10
  
- 之后的流程就是熟悉的ret2libc了
- ![e90a67fb7354146e4f7b8945ff33e8cf.png](evernotecid://CCF81846-0ED6-43C2-B4C1-E5FA28B18FC2/appyinxiangcom/28478781/ENResource/p271)
    - ![05c10648a972bf9090e1553ddcf52b68.png](evernotecid://CCF81846-0ED6-43C2-B4C1-E5FA28B18FC2/appyinxiangcom/28478781/ENResource/p272)
    - flag为flag{4d38f252-17cf-462e-b6a5-dd3e036b2e23}
> https://www.yuque.com/hshs/pwnup/rdnqcw

### 第五空间2019决赛 PWN5
- 文件的基本逻辑是，生成随机数，请求用户输入username与passwd，之后将passwd进行atoi并与随机数对比，对比通过即可拿到shell
- 为啥不能用传统方法覆盖随机数呢？因为随机数变量是unk_**804C044**，而缓冲区地址为**ebp-70h**，而且read字节为**0x63u**，这点距离buf是根本overflow不到804C044的，因此传统方法也就失效了
- 利用法宝就是「格式化字符串漏洞」
- 可以看到，程序之间printf了用户的输入，假如用户输入的username中有%s这种**格式化参数**该咋办呢？
- ![fd77ce426295d711357e4975f970519e.png](evernotecid://CCF81846-0ED6-43C2-B4C1-E5FA28B18FC2/appyinxiangcom/28478781/ENResource/p274)
    - 程序会在栈的高部分自动寻找参数，而不care到底这些内容是不是printf的参数
    - ![92e35158188de1a8b4a38b97a13f1d0f.png](evernotecid://CCF81846-0ED6-43C2-B4C1-E5FA28B18FC2/appyinxiangcom/28478781/ENResource/p273)



#### %n

\- 既然如此，是否有一种格式化参数，能将栈上内容或者任意地址的内容改写呢？假如有的话，不就和之前栈溢出覆盖随机数的情况一样了吗！

\- 实际上，的确是有的——**%n**，这个参数可以将已输出字符的个数，写到特定地址中，怎么个写法呢？

\- %10$n，得到栈上第10个参数的地址，将前面printf输出的字符长度，如"asdf%10$n“就是4，写入地址中（！）

\- 注意，由于整个输入用户都能控制，因此要写入啥值，还不是用户说了算吗？

- 这样一来，这道题要做的事就很清楚了，先明确自己输入的格式化字符串（含0x**804C044**）到了args的哪个位置，然后用%4$n这种方法，将0x**804C044**这个地方的值改写成某个我们已知的数，即可通过验证。

#### 确定参数位置

- ![image-20210228174314774](https://i.loli.net/2021/02/28/SxUcwPH1IYOMr4u.png)
  - 可以看到，通过输入若干个%x的方法，能知道我们要输入aaaa的话，这个aaaa会被放在了栈参数区域的哪个地方，本题中就是第10个参数
- 下一步就是用%10$n，将第10个参数的值作为地址，把%10\$n前面字符串的长度作为值写入

#### 写入值

- 如前所述，利用%n这个神奇的参数写入
- ![image-20210228174945444](https://i.loli.net/2021/02/28/3sLq6cH2vnZfoRk.png)
- 这样就是可以往第10个参数的位置所代表的地址内，写入想要的值（当然，写是程序自动计算出是16个byte的值然后写入了）
- 我们最后传入0x10101010 来确保值能都对应上，最后得到flag
- ![image-20210228175204425](https://i.loli.net/2021/02/28/NAvXd2aPEmUF6WT.png)
- flag为flag{1496df7d-8d7f-415f-9b5c-4530514b26ce}

#### pwntools

- 其实在确定了偏移之后，就能用pwntools自带的一些api来实现
- ![008113158968ef0bb914bc9af929a7c1.png](evernotecid://CCF81846-0ED6-43C2-B4C1-E5FA28B18FC2/appyinxiangcom/28478781/ENResource/p275)
-此外，还有一种方法是，改写特定函数的地址为system的地址，并传入shell的地址作为参数，同样能实现getshell

> https://www.jianshu.com/p/0501f4dbaf9e
> https://www.cnblogs.com/0xJDchen/p/5904816.html
> https://www.anquanke.com/post/id/85785
> https://xz.aliyun.com/t/7398

### BJDCTF 2nd r2t3
- checksec 以及 查看ida strings（发现自带shell）
    - ![7759fac772a8506162324b02f13a7d6f.png](evernotecid://CCF81846-0ED6-43C2-B4C1-E5FA28B18FC2/appyinxiangcom/28478781/ENResource/p276)
- 拖入ida，惊喜的发现这不是strlen吗，于是想到可以截断绕过判断然后覆盖dest部分的数据（因为buf部分不够近）
- 然而，strlen、strcpy这些函数都是会00截断的，因此虽然能绕过长度判断，但payload只会被拷贝00前面的部分。
- 这道题正确的解法应为**整数溢出**
    - v3变量被强制规定为unsigned int8，即一字节的无符号数，0-255
    - 因此输入的长度大于255时，会仅保留被截断的部分，如262（0x106）被赋给v3时会变为6，从而绕过验证

- 由于已经自带了shell，剩下的就是编写payload即可
    - payload组成：overflow_padding + shell_addr + int_overflow_padding
    - ![daa42c7f33bac61f161a36d321e2d223.png](evernotecid://CCF81846-0ED6-43C2-B4C1-E5FA28B18FC2/appyinxiangcom/28478781/ENResource/p278)
    
    - 运行得到flag
    - ![10575fa696b86fc115d16ea9104fb5ce.png](evernotecid://CCF81846-0ED6-43C2-B4C1-E5FA28B18FC2/appyinxiangcom/28478781/ENResource/p277)
- flag为flag{9a248756-809a-492e-956c-5f493cec364e}

> https://www.yuque.com/brooke-ygfso/mhpnug/ane99u#ZP3WX
> https://www.codenong.com/cs109848247/


### get_started_3dsctf_2016

- 拖入IDA后查看，发现主函数中除了溢出函数外啥都没哟，但是发现有个get_flag函数可被利用
    - ![997f1013e4486c967ec255c1cdff0366.png](evernotecid://CCF81846-0ED6-43C2-B4C1-E5FA28B18FC2/appyinxiangcom/28478781/ENResource/p279)
    - 分析该函数，发现主要逻辑就是通过if判断（对参数的判断）后，程序会读出flag并回显
    - ![7afb9640dd6d87277a71339a369c17cd.png](evernotecid://CCF81846-0ED6-43C2-B4C1-E5FA28B18FC2/appyinxiangcom/28478781/ENResource/p280)
    
- 因此，本题的核心就是如何覆盖这两个参数；由于溢出函数已知，因此可以直接使用栈溢出的技巧，对a1和a2进行覆盖

#### 但是
- 当你开开心心的写好'A' * (0x38 + 0x4)之后发现这个payload打不进去
- 后来参考了网上的解法发现，这个main里面没用ebp（淦！），即全程都是esp寻址（记性够好奥）
- 因此在栈上，就没有push ebp这一说，因此就不用那多的0x4了

#### 攻击
- 明确上述坑点之后，剩下的流程和传统栈溢出一致了
- ![9d586b2af6ef6ab095f3fcdee24b7a93.png](evernotecid://CCF81846-0ED6-43C2-B4C1-E5FA28B18FC2/appyinxiangcom/28478781/ENResource/p281)

- 但还要注意溢出完resume时，要正常exit，也不要返回到main函数之类的。因为我们要让程序给我们打印输出，并且正常退出，**而远程程序异常结束它是不会给回显的**，因此一定填exit的地址，使程序能够正常结束。
- ![631e39f2a34ac5c310ee9b3ff7e1c949.png](evernotecid://CCF81846-0ED6-43C2-B4C1-E5FA28B18FC2/appyinxiangcom/28478781/ENResource/p282)
    - flag为flag{a745d561-66ac-455b-9560-302b8643499d}

>https://www.codenong.com/cs109528155/
http://liul14n.top/2020/02/25/get-started-3dsctf-2016/
也有做法是，利用程序中的mprotect改变内存段属性，构造ROP链getshell，这感觉有些overkilled了

### ciscn_2019_en_2
- 该题很奇怪，给的二进制文件居然是和之前那道题ciscn_2019_c_1是一样的，而且防护方式也没变；
- 只好用之前的payload先试一下（里面居然连具体函数的偏移都没什么变化）
    - 然后就getshell了（啊这）
    - ![28eb6cf7db7a2d0d3c45be247442d165.png](evernotecid://CCF81846-0ED6-43C2-B4C1-E5FA28B18FC2/appyinxiangcom/28478781/ENResource/p286)
    - flag为flag{6551e765-8ed8-452a-b816-98f85395ed35}


### ciscn_2019_n_8
> 反直觉的一道题

- checksec一看发现保护全开，以为是要用一些没见过的方法
- 然后发现，只要输入数组的第14个元素等于特定值即可

> 这和溢出之类的有啥关系啊？

- 于是直接构造payload为 p32(17) * 14
    - ![a8686f9fe9898ff8da25b226083d45c9.png](evernotecid://CCF81846-0ED6-43C2-B4C1-E5FA28B18FC2/appyinxiangcom/28478781/ENResource/p285)
    - flag为flag{07858ebe-ba37-4f46-9a80-75df25b5d08b}
    - 非常莫名其妙的一道题

### jarvis level2
- 拖入IDA查看，发现二进制文件中有system、并且有read的溢出函数
- 因此，可以考虑直接调用system，而同时发现程序中还有shell的地址，那么就可以直接getshell了
- 但是，记得正确找到system的地址
    - ![48cb587a6a1be0f393fb5ecc11256612.png](evernotecid://CCF81846-0ED6-43C2-B4C1-E5FA28B18FC2/appyinxiangcom/28478781/ENResource/p287)
    - 这张图中system的地址是0x08048320，而不是804A010(got off)，也不是0x0804A038(import addr)
    - 可以使用ELF.symbols自动获取符号地址
- 之后，直接写shellcode即可
    - ![0273933b3823b33958e37dbe90d68091.png](evernotecid://CCF81846-0ED6-43C2-B4C1-E5FA28B18FC2/appyinxiangcom/28478781/ENResource/p288)
    - ![c6691d65a3b79d80ad3d824e61dce62b.png](evernotecid://CCF81846-0ED6-43C2-B4C1-E5FA28B18FC2/appyinxiangcom/28478781/ENResource/p289)
    - flag为flag{f58395a7-bb55-49b6-8ced-0d9df3a5ebb3}

> 当要调用二进制文件中某个已有函数时，不妨用内置API symbols去准确获得地址
> 或者在伪代码界面，查看准确的API地址dizhi
> ![8f90f575a49146fab424e82f584b49df.png](evernotecid://CCF81846-0ED6-43C2-B4C1-E5FA28B18FC2/appyinxiangcom/28478781/ENResource/p290)

### not_the_same_3dsctf_2016
- 拖入IDA后发现，有get_secret函数，该函数的目的就是将flag读入一个特定的bss段上的变量内：
    - ![11f8451c155d65039608b33e1aa26072.png](evernotecid://CCF81846-0ED6-43C2-B4C1-E5FA28B18FC2/appyinxiangcom/28478781/ENResource/p291)

- 虽然程序内存在溢出点（gets），但是没有能直接getshell的地方；然而，二进制文件中有很多可以利用的函数，如read、write等；
    - 因此本题的思路就是用write将那个bss段的变量读出给用户

> 要注意：main函数中又没有ebp，即全程都是esp去进行栈寻址，因此payload中无需那个0x4

- payload组成为 payload2 = padding + p32(get_secret_addr) + p32(write_addr) + p32(0xdeadbeaf) + p32(1) + p32(fl4g_addr) + p32(fl4g_len)
    - 该payload意义即为，先将get_secret_addr作为第一步的return address，write_address作为get_secret的ebp，然后被执行
    - 因此，这样就可以先执行get_secret，再执行write


> 而不用发两次payload分别执行

- 最终get flag：
    - ![e46a9b2ea5197ef785b8e421e857adc1.png](evernotecid://CCF81846-0ED6-43C2-B4C1-E5FA28B18FC2/appyinxiangcom/28478781/ENResource/p292)
    - flag{a4991d7e-5f1b-4aa0-a31a-234620e2876d}

### bjdctf_2020_babystack

- 64位逆向，拖入IDA，发现后门函数可以直接getshell
- 因此，本题要做什么也就很清晰了
- 直接覆盖，并跳转到后门函数：
    - ![c785cdee3baf4fe1c77799c48a0cca51.png](evernotecid://CCF81846-0ED6-43C2-B4C1-E5FA28B18FC2/appyinxiangcom/28478781/ENResource/p293)
    - 然后直接拿到shell
    - ![4ac5fd466d204280d9ca912bd7822869.png](evernotecid://CCF81846-0ED6-43C2-B4C1-E5FA28B18FC2/appyinxiangcom/28478781/ENResource/p294)
    - flag{28d84b72-2f6a-413d-af2e-11a290d04222}


### [BJDCTF 2nd]one_gadget
- checksec看一下，保护全开，妈耶就别想溢出了
- 但是会给出printf的内存地址
    - ![62671a808760e873596315e8427aac21.png](evernotecid://CCF81846-0ED6-43C2-B4C1-E5FA28B18FC2/appyinxiangcom/28478781/ENResource/p295)
    - 因此，可以获取libc的基地址，从而得到任意的gadget地址

- 但是到这里就又尬住了，不让人溢出，还有能用gadget来getshell，这什么鬼？
- 结果发现这道题关键在于你知道有个one_gadget的工具
    - https://github.com/david942j/one_gadget
    - 这工具旨在直接找到能接触到binsh的exec系列函数的
    - **前提是你的二进制文件中得有这么一段gadget**

- 因此，了解工具后，直接得到可用gadget的地址
    - ![05f0fd252fc54032c1437d80cac78197.png](evernotecid://CCF81846-0ED6-43C2-B4C1-E5FA28B18FC2/appyinxiangcom/28478781/ENResource/p296)
    - 给予程序v4的地址，程序会尝试替我们执行它，因此满足了实施攻击的条件
    - ![b0953e0ec067f039aaead2792f05221d.png](evernotecid://CCF81846-0ED6-43C2-B4C1-E5FA28B18FC2/appyinxiangcom/28478781/ENResource/p297)
    
- 因此，只要发送得到的one_gadget的地址，就能getshell
    - ![767a68bd31e8a5e60aa9abcfa801f1c2.png](evernotecid://CCF81846-0ED6-43C2-B4C1-E5FA28B18FC2/appyinxiangcom/28478781/ENResource/p298)
    - flag{f6ecb6c3-7fc0-4b1a-8dd7-a28275cfcf7c}

> https://xz.aliyun.com/t/2720
> https://arttnba3.cn/2020/09/08/CTF-0X00-BUUOJ-PWN/

### HarekazeCTF2019 baby_rop
- 其实很简单的一道题
- checksec-拖入IDA-查看溢出点所在函数是否有ebp 这都常规操作
- 发现程序中直接提供了system以及bin/sh的地址
    - ![fd298b5223f65d843d2b68521cf8eded.png](evernotecid://CCF81846-0ED6-43C2-B4C1-E5FA28B18FC2/appyinxiangcom/28478781/ENResource/p299)
    - 那就直接调用system打开shell即可

> 但是，一定不要32位做的太多，上来就ret、arg什么的；64位里传参不是用栈啊，64位得先pop rdi，然后紧接着放shell地址，再然后调用system

- 所以payload得这么构造：
    - ![effd155b06dbd846cc27176034030de5.png](evernotecid://CCF81846-0ED6-43C2-B4C1-E5FA28B18FC2/appyinxiangcom/28478781/ENResource/p300)
    - 之后拿到shell（flag在home里，不直接在根目录下）
    - ![2e957c9ac01f9cce5299da32a3a3da3b.png](evernotecid://CCF81846-0ED6-43C2-B4C1-E5FA28B18FC2/appyinxiangcom/28478781/ENResource/p301)
    - flag{583f9c33-6f9a-419f-98ab-2dcd166facec}


> 一定别忘了64位的rop方法啊

### jarvis level2-x64

- 跟上面那道题一模一样，再次复习下x64的简单getshell啊
- ![fceacec7988d00fc3e8ea4c58eac2c26.png](evernotecid://CCF81846-0ED6-43C2-B4C1-E5FA28B18FC2/appyinxiangcom/28478781/ENResource/p302)
    - ![450fb8b439e99a68c020772c593512dc.png](evernotecid://CCF81846-0ED6-43C2-B4C1-E5FA28B18FC2/appyinxiangcom/28478781/ENResource/p303)
    - flag{52adfbd2-c490-4056-be90-f29af43f5c67}


### ciscn_2019_n_5

- 一道经典的64位pwn模板题，checksec没有防护，IDA查看发现溢出点gets，并且程序用了libc
- 那么，这就是经典的内存泄pwn题
- 具体流程应该很熟悉了
    - puts + gots得到puts的真实地址
    - 得到libc版本
    - 得到lib基地址
    - 得到真实的system与shell的地址
    - getshell

- 剩下的就是注意栈平衡以payload的编写，这些就是套路化的东西，多练就好
    - ![f46ffb8ee273188dd544f51bf636ea1f.png](evernotecid://CCF81846-0ED6-43C2-B4C1-E5FA28B18FC2/appyinxiangcom/28478781/ENResource/p305)
    - getshell
    - ![b15248923f90dee3517e5a40e480da7b.png](evernotecid://CCF81846-0ED6-43C2-B4C1-E5FA28B18FC2/appyinxiangcom/28478781/ENResource/p304)
    - flag{67c6588c-53bf-46c1-b675-f9d6f0443049


### ciscn_2019_ne_5
- 一道不太一样的溢出题
- IDA的反汇编：进入main后直接F5会发现反编译错误，这是由于程序进行了一些反调试，需要先反编译scanf，再反编译main
    - ![5e9abb5680d626a8d21d5c291e8ee73a.png](evernotecid://CCF81846-0ED6-43C2-B4C1-E5FA28B18FC2/appyinxiangcom/28478781/ENResource/p309)
    - ![e09ad1828b5b510085320f1779c40dd5.png](evernotecid://CCF81846-0ED6-43C2-B4C1-E5FA28B18FC2/appyinxiangcom/28478781/ENResource/p310)
   
- 在得到main逻辑后发现，addlog会将输入放入src中，但是最大长度为128字节，而src离得又太远，所以这里的scanf不能溢出
- 但是，程序中的getflag函数，会将src拷贝到dest中，dest却是一个离栈较近的变量
    - ![e554e98d3fbcbf57398a744fa4a7ef2c.png](evernotecid://CCF81846-0ED6-43C2-B4C1-E5FA28B18FC2/appyinxiangcom/28478781/ENResource/p311)
- 因此，本题利用流程：
    - 输入密码 administrator
    - addlog：输入payload
    - getflag：利用strcpy拷贝我们的payload使得溢出

- 此外，程序提供了system的地址，而shell虽然没有/bin/sh，但是有sh，二者其实是一样的。
    - 因此得到如下payload
    - ![fd7b63b72a96be023cdc1d2daf4217cd.png](evernotecid://CCF81846-0ED6-43C2-B4C1-E5FA28B18FC2/appyinxiangcom/28478781/ENResource/p312)
    - ![76e840792493c772dd0685874967d77d.png](evernotecid://CCF81846-0ED6-43C2-B4C1-E5FA28B18FC2/appyinxiangcom/28478781/ENResource/p313)
    - flag{1fbaab43-2c24-486c-b92b-b36adbc32cd3}

> 三个点：
> IDA反编译错误
> strcpy与溢出过程
> sh地址与bin/sh

### 2018_rop
> 巩固，再巩固！

- 拖入IDA，发现代码逻辑非常简单，就是调用read、write来进行用户交互
    - 发现有read和write可以利用
    - ![a0b26525d87b9708dd3e64035257bd20.png](evernotecid://CCF81846-0ED6-43C2-B4C1-E5FA28B18FC2/appyinxiangcom/28478781/ENResource/p317)
    - ![14773ea3e5d7df17405daf1055cd5803.png](evernotecid://CCF81846-0ED6-43C2-B4C1-E5FA28B18FC2/appyinxiangcom/28478781/ENResource/p403)
- 因此，结合checksec的结果可以发现，有两种方法可以利用
    - 调用read读取shellcode到bss，然后执行shellcode
    - 调用write实现内存泄露

- 此处使用第二种方法。基本过程就不赘述了，直接上代码
    - ![e346b00fa43a45782c97c218bc5cb97e.png](evernotecid://CCF81846-0ED6-43C2-B4C1-E5FA28B18FC2/appyinxiangcom/28478781/ENResource/p319)
    - 其中有几个点要注意下
        - 第一次交互后要recv，只recvline的话，会造成缓冲区中数据，从而脚本会阻塞掉
        - 根据泄露地址找的gadget偏移，可能有多个版本的，实在不行逐一尝试一遍

- 最终getshell
    - ![e346b00fa43a45782c97c218bc5cb97e.png](evernotecid://CCF81846-0ED6-43C2-B4C1-E5FA28B18FC2/appyinxiangcom/28478781/ENResource/p319)
    - flag{fa5c731c-d97e-49d5-a751-384ad91d5bd2}


### 0ctf 2017 baby heap

- 淦 还是8太懂诶
- 基本思路是先泄露出libc的基地址，然后根据这个基地址以及malloc_hook实现对execve的调用，从而getshell
- leak时就需要fastbins的double free的技巧，来实现有限的内存读写从而借助程序本来有的dump与fill功能给出libc的基地址
- ![920132a77643e6cc96d27126c1a514df.png](evernotecid://CCF81846-0ED6-43C2-B4C1-E5FA28B18FC2/appyinxiangcom/28478781/ENResource/p380)
- flag{834b4ed2-0e6a-4610-9660-887083b2d2f8}


### others_shellcode
- 拖入IDA 32查看后，发现居然连交互点都没有，唯一能分析的函数即为getShell
    - ![c7211ab33c24b0c9bb9f79910a4ad0cb.png](evernotecid://CCF81846-0ED6-43C2-B4C1-E5FA28B18FC2/appyinxiangcom/28478781/ENResource/p369)
- 而查看该函数对应的汇编可知，其内部的asm内联汇编就已经替我们调用了execve（eax=11，为对应的系统调用号）
- 因此直接就能getshell（淦）
    - ![93b57439683c74e16c3958c419427f44.png](evernotecid://CCF81846-0ED6-43C2-B4C1-E5FA28B18FC2/appyinxiangcom/28478781/ENResource/p371)
    - ![aac8294f18f228039a8e3587f3d3ab4b.png](evernotecid://CCF81846-0ED6-43C2-B4C1-E5FA28B18FC2/appyinxiangcom/28478781/ENResource/p372)
    - flag{0fdf0419-8b25-4771-8f35-2f8fcab7c637}

### bjdctf_2020_babyrop
- 64位程序，拖入IDA中发现程序比较简单，溢出点即为read buffer；同时程序提示了ret2libc
    - ![89de2692b3e004adc36de7793703d726.png](evernotecid://CCF81846-0ED6-43C2-B4C1-E5FA28B18FC2/appyinxiangcom/28478781/ENResource/p374)
    
    - 因此该题就是一道典型的64位ret2libc


- 基本流程都十分熟悉了，就是泄露地址-还原基址-得到gadget地址-getshell；但有两点需要注意：
    - 64位的参数传递模式是寄存器
    - 溢出得到的地址要找到正确的libc版本

- 实现中有两处需要注意
    - recv时要接收多少字节，接收到哪里？
    - lib database里的版本正不正确（好坑）

- 总之，得到exp如下
    - ![9b694879c018cfdaa56652569bbf01dc.png](evernotecid://CCF81846-0ED6-43C2-B4C1-E5FA28B18FC2/appyinxiangcom/28478781/ENResource/p375)
    - 根据BUUOJ提供的环境库得到地址


- getshell
    - ![266ae97fd791f9a5fb14a0c3e83d5e15.png](evernotecid://CCF81846-0ED6-43C2-B4C1-E5FA28B18FC2/appyinxiangcom/28478781/ENResource/p376)
    - flag{9673be39-6d46-4d71-a37d-ffdb830808fa}

### pwn2_sctf_2016

- file 与checksec发现是32位的可以栈溢出的程序，但拖入IDA后发现有些许不一样
    - ![d3a2e0af7cc875967a8bfab4386ad3b6.png](evernotecid://CCF81846-0ED6-43C2-B4C1-E5FA28B18FC2/appyinxiangcom/28478781/ENResource/p382)
    - ![577763bdd1b6806b6770681f24d92203.png](evernotecid://CCF81846-0ED6-43C2-B4C1-E5FA28B18FC2/appyinxiangcom/28478781/ENResource/p383)
    - 乍一看程序做了输入长度的约束，因此似乎没法溢出了？

- 但神奇的地方在于，getn接收的是**无符号数**，但vuln接收的是**有符号int**。因此如果输入个-1，在getn那里会被解析成一个很大的数，这样就可以溢出了
- 剩余工作就是经典的leak address+ROP了
> 注意libc库 libc库 libc库！
> libc在线网站怎么这么拉了，他么的根本提供不了正确的偏移

- 还有一点是printf第一个参数是format，注意要先给出的format字符串（那个You said）的地址
- ![7e7b8c5a11d4e90482d163388a6352cd.png](evernotecid://CCF81846-0ED6-43C2-B4C1-E5FA28B18FC2/appyinxiangcom/28478781/ENResource/p384)
- 最后getshell
    - ![3d00cf2b10104bf1d523e4dc484933a6.png](evernotecid://CCF81846-0ED6-43C2-B4C1-E5FA28B18FC2/appyinxiangcom/28478781/ENResource/p381)
    - flag{408ca282-6041-4b2f-87f8-f05c4975f178}

### ciscn_2019_s_3

- checksec并拖入IDApro，诶似乎有点不一样，都是用内联汇编写的系统调用，而且有个gadgets
    
- ![55a705d4716f78a94d6539a814e043b0.png](evernotecid://CCF81846-0ED6-43C2-B4C1-E5FA28B18FC2/appyinxiangcom/28478781/ENResource/p395)
    
- 但溢出点可以确定为在read与write时，buf允许输入很长，但距离ebp只有0x10，而write则会把0x30的数据都写出来

  - 直接运行就会段错误

- 这个时候就有两种选择了，因为想栈溢出getshell，那只能想办法ROP，可是**有足够的gadget**吗，以及该怎么**布局栈参数**并**调用read write**呢？而在gadgets函数中，对rax做了不同的赋值（即0xF与0x3B），二者分别对应了sigret与execve两个系统调用，这是不是一个可利用的点呢？

  > https://firmianay.gitbooks.io/ctf-all-in-one/content/doc/9.4_linux_syscall.html

- 查找资料后发现，可以利用系统中断中的信号帧（SignalFrame）机制对栈进行溢出，能实现篡改IP以及某些寄存器值的目的

> https://www.freebuf.com/articles/network/87447.html
> 这篇文章做了详细的描述，总之核心在于触发系统调用sigret时，我们可人为地传入一个精心构造的signal Frame，这个frame结构可对寄存器内容进行修改，因此相当于将这个signal机制作为攻击的跳板，从而达成劫持执行流的目的，也是一招借刀杀人

- 明确攻击的核心原理后，有两个问题需要解决。

#### signal frame要调用谁呢

- 既然可以劫持IP，因此IP的值要被置为调用系统调用的指令地址，即syscall或者call，而本例中是直接通过中断int 80h实现的，因此IP要被赋给int 80h的地址
- 该怎么调用frame的内容呢？
  - 这就是经典栈溢出了，即覆盖为gadgets函数中的为为rax置0xF的指令地址
  - 再接由系统调用以及构造好的frame，即可实现对frame内容的调用

可以看到vuln函数中没有rbp只有rsp，这就意味着覆盖rbp与ret效果一样

#### shell地址如何确定呢

- 程序开始时栈地址在rsi中，输入aaaaaaaa后，可定位出aaaa的地址距离栈多远（偏移）
  - 简单计算后发现是0x118
      - ![3672d9f0dfa9594f523631f782b50b88.png](evernotecid://CCF81846-0ED6-43C2-B4C1-E5FA28B18FC2/appyinxiangcom/28478781/ENResource/p397)
      - ![999d029c5ead4311973a7bf45e2c4892.png](evernotecid://CCF81846-0ED6-43C2-B4C1-E5FA28B18FC2/appyinxiangcom/28478781/ENResource/p396)
- 而打印下栈附近的元素可以发现，在输入内容的0x20处，恰好放着初始时rsi的地址，此时注意到write也恰好是输出0x30长度的元素
    - ![4e934bd852c81409aac5dd6cf7be35b6.png](evernotecid://CCF81846-0ED6-43C2-B4C1-E5FA28B18FC2/appyinxiangcom/28478781/ENResource/p398)

> 那么，只要获取write输出**0x20-0x28这个8个字节输出**，将其地址减去**0x118**，即为输入的shell地址了！

- 确定上述问题后，可写出exp（不过注意后面的frame要变成bytes array才能发送， 此处用的pwntools的flat，很好用；如果str后encode会有编码问题）
    - ![b9fa1f5650dbbb5ef48ed6b6af619d17.png](evernotecid://CCF81846-0ED6-43C2-B4C1-E5FA28B18FC2/appyinxiangcom/28478781/ENResource/p404)
    
    - ![51276a3834447cc0ca7d328b6fe6343d.png](evernotecid://CCF81846-0ED6-43C2-B4C1-E5FA28B18FC2/appyinxiangcom/28478781/ENResource/p399)
    - flag{26182671-2b91-49b6-b84f-f857260035fa}

> https://blog.csdn.net/qq_45691294/article/details/111934990


### HarekazeCTF2019 baby_rop2

- 拖入IDA并checksec后初步判断这道题是：溢出buf通过printf泄露出内存地址，之后计算libc基址实现ROP调用system并getshell
  - ![fc1a5f4caa85088f7a845c4c91f2f85a.png](evernotecid://CCF81846-0ED6-43C2-B4C1-E5FA28B18FC2/appyinxiangcom/28478781/ENResource/p408)
  
- 基本的流程已经非常熟悉了，有以下几点需要注意：
  - 64位需要找pop_rdi的gadget来修改寄存器的值，从而实现函数传参
    - printf不要忘了传format string
    - 多个参数时，要记得哪些寄存器放参数：rdi、rsi
    - 没有合适的gadget，可以多传几个无关紧要的值（如有个pop r15，那就干脆多加个0好了）
  - 多熟悉进程的输入输出
    - 尝试用recvuntil('\x7f')来获取泄露的地址
    - 拿不准主意多recv几次看看结果
    - 如果exp阻塞了，考虑是不是多了个recv
  - 注意最终判定的libc版本是否正确（本题已给出libc）
- 最后就是注意地址的一致性以及是否对应
- ![b9d98dbdbab92275b74ad216ddc697ad.png](evernotecid://CCF81846-0ED6-43C2-B4C1-E5FA28B18FC2/appyinxiangcom/28478781/ENResource/p409)
    - ![47188e810eb944798149e0b20167ddc5.png](evernotecid://CCF81846-0ED6-43C2-B4C1-E5FA28B18FC2/appyinxiangcom/28478781/ENResource/p410)
    - flag{c3a650bc-5dba-4cee-833b-b3afaa234b1f}


### ez_pz_hackover_2016

- checksec 32位没开栈保护，因此可以直接执行shellcode
- 但需要知道栈地址在哪里 以及 溢出点在哪里
  - 第一个问题是为了能跳转到shellcode上，而且程序已经给出了栈上变量s的地址
  - 第二个问题是为了能劫持程序执行流，使其跳转到shellcode上
    - 分析后发现在vuln中是出现栈溢出的问题的
    - 要注意到，我们要覆盖的ret或ebp是vuln的，而非chall的
- 同时可以发现，chall函数的栈空间非常大，因此足够我们写入shellcode
  - ![image-20210409155859899](https://i.loli.net/2021/04/09/M9XU5EgyLvf3cKn.png)
- 那么该如何了解chall栈上的shellcode以及s 与 vuln函数栈上的ret和ebp距离多远呢？
  - pwntools + gdb 动态调试
  - 输入较长字符获得ret距离crashme输入起始的位置：ret_off
  - 输入shellcode获得栈上泄露的地址与shellcode的距离: shellcode_off
  - https://blog.csdn.net/qq_44768749/article/details/108176719
- 因此，就可以直接编写exp了
  - ![image-20210409160202569](https://i.loli.net/2021/04/09/eT32E4FvJrAOuZo.png)
  - ![image-20210409160211523](https://i.loli.net/2021/04/09/vfSuwsW52aDhR6U.png)
  - flag{2a0f43a3-6bb6-423b-89f5-76621573f3f1}

> 值得多做几遍

## RE

### easy re
- 直接拖入IDA 64，即可发现flag
    - ![c7475fceb3836991d4dd3190ee383e65.png](evernotecid://CCF81846-0ED6-43C2-B4C1-E5FA28B18FC2/appyinxiangcom/28478781/ENResource/p373)
    - flag{this_Is_a_EaSyRe}

### reverse 1
- 