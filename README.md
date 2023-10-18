# github-proxy

代理服务。

这只是后端服务，前端页面需要自己完成并通过静态文件导入。

## 使用

你可以直接在 release 中下载对应的服务器架构的可执行二进制文件，下载后可重命名为`gp`：

```bash
mv gp_* gp
```

命令行使用帮助：

```bash
使用指定的静态文件启动 github proxy 代理服务

Usage:
  gp [STATIC_DIR] [flags]

Flags:
  -h, --help          help for gp
      --host string   本服务使用的主机 (default "localhost")
      --port uint     本服务使用的端口 (default 3000)
```

## 编译后端服务

如果 release 中没有你正在使用的平台或者你想使用最新的代码可自行编译本项目。

```bash
go build -ldflags="-s -w" -o gp main.go && upx -9 main
```

- -s: 忽略符号表和调试信息
- -w: 忽略DWARFv3调试信息，使用该选项后将无法使用gdb进行调试

用 upx 压缩能大幅缩小可执行文件体积，如果对程序的体积没有要求，可以不执行此步，因为使用 upx 压缩后在执行时会有一个用时很短的解压过程。

如果你是用 Windows 作为开发平台，应逐行执行以下命令进行交叉编译：

```powershell
$Env:CGO_ENABLED=0
$Env:GOOS='linux'
$Env:GOARCH='amd64'
go build -ldflags="-s -w" -o gp main.go && upx -9 main
```

### upx

下载对应系统的最新 [release](https://github.com/upx/upx/releases/latest) ，放到 PATH 中即可。

### 配置前端页面

如果你不会自己写前端页面可使用我打包的页面，但里面有一张捐赠图片，你可以选择删除或替换。

已打包的前端页面：

https://pan.baidu.com/s/14iEOGT9xSAR1EUXTpoO01g 提取码: xvme

将前端文件解压后放到任意目录(最好叫`static`)中。

### 测试运行

假如你将前端静态文件（是文件，不是目录）保存到了`~/static`目录中，想使用`localhost:8080`地址运行服务，在可执行文件所在的根目录中执行：

```bash
./gp ~/static --host localhost --port 8080
```

> 传入命令行参数会检测静态文件目录的合法性，静态文件目录的根目录中必需有`index.html`文件。

访问`http://localhost:8080`即可访问首页，输入某个 github 的文件链接即可测试下载功能。

### 部署

上线建议使用 caddy，可以基于 docker 容器，也可以直接安装在物理机中。

通过上面的命令运行本服务后，使用 caddy 的反向代理即可。

caddy 配置文件：

```caddy
<域名> # 如 example.com

reverse_proxy localhost:8080
```

## 相关项目

- [gh-proxy](https://github.com/hunshcn/gh-proxy)
