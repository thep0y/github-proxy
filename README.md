# github-proxy

代理服务。

## 编译后端服务

```bash
go build -ldflags="-s -v" -o main main.go && upx -9 main
```

- -s: 忽略符号表和调试信息
- -w: 忽略DWARFv3调试信息，使用该选项后将无法使用gdb进行调试

用 upx 压缩能大幅缩小可执行文件体积，如果对程序的体积没有要求，可以不执行此步，因为使用 upx 压缩后在执行时会有一个用时很短的解压过程。

如果你是用 Windows 作为开发平台，应逐行执行以下命令进行交叉编译：

```powershell
$Env:CGO_ENABLED=0
$Env:GOOS='linux'
$Env:GOARCH='amd64'
go build -ldflags="-s -v" -o main main.go && upx -9 main
```

### upx

下载对应系统的最新 [release](https://github.com/upx/upx/releases/latest) ，放到 PATH 中即可。

### 编译前端页面

克隆同项目的的前端仓库，编译：

```bash
# 根据使用的包管理器选择对应的命令
pnpm run build
yarn build
npm run build
```

将编译好的文件复制到后端根目录的`static`目录中：

```bash
cp -r dist <后端目录>/static
```

### 测试运行

在后端根目录中执行：

```
./main
```

使用了 3000 端口，访问`http://localhost:3000`即可访问首页，输入某个 github 的文件链接即可测试下载功能。

### 部署

上线建议使用 caddy，可以基于 docker 容器，也可以直接安装在物理机中。

需要`static`目录和编译好的`main`文件复制到 caddy 环境中，使用 caddy 的反向代理即可。

caddy 配置文件：

```
<域名> # 如 example.com

reverse_proxy localhost:3000
```

