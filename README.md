# EverNoteLinkConverter

## What is this？
- 印象笔记虽然支持了Markdown笔记本，但插入图片时，Markdown图片链接会被转化为这样的形式
> evernotecid://CCF81846-0ED6-43C2-B4C1-E5FA28B18FC2/appyinxiangcom/28478781/ENResource/p373

- 因此，这对Markdown笔记的迁移工作会产生很大影响，用印象笔记写的Markdown笔记将因为没有可外部解析的图片链接而变得难以转移和备份（比如要传到github上）
- 然而，印象笔记客户端提供的分享功能可生成一个笔记本的网页链接，该网页会包含笔记中所有内容，并为其中的素材上传至可用的内部图床
- 本repo可提取网页笔记中的图片链接，并替换掉原Markdown中不可用的图片链接，得到的新Markdown就拥有了免费的图床路径，便于迁移和管理

## How can I use it？
> 由于印象笔记是闭源的，所以没法直接在客户端内对Markdown笔记本进行转换，需要Ctrl+A/C将内容拷贝到本地的original.md再进行转换

- Step1. git clone this repo
- Step2. pip3 install -r requirements.txt
- Step3. 在印象笔记客户端中点击共享**旁边**的分享按钮，选择「复制链接」，保存这个链接
- Step4. 拷贝要转换的Markdown到本地，如test.md（记得确认下拷贝内容是完整的，比如tab、>等特殊字符是否会保留，Typora记得切换到源代码模式下再粘贴）
- Step5. ./ImageConverter.py -i your_note_link -f test.md -o new.md -t wait_interval

- 然后在运行目录下应该就能看到转换后的、自带印象笔记图床链接的Markdown了。这下你就可以随意移动它了。

> 上述过程我目前还没想到一个比较好的自动化方案，欢迎交流与指正 🙏🏻

## 2021.4.11
- 印象笔记分享的笔记链接中会有部分图片无法加载，可能是印象笔记服务器的bug之类的，因此在脚本中加了个MISS_PATTERN的判断
- github使用CMAO服务来存储文件中的资源（比如外链中的图片），CMAO只能解析那些返回content-type为image的外链图片，但印象笔记这个链接返回的是一个octect stream
  - 所以转换后的markdown在github也无法显示图片（淦）
  - 但在其他在线平台（比如知乎）等markdown解析器或者本地的typora、vscode等都能正常显示
