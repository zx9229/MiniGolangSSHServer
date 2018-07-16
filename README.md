# MiniGolangSSHServer  
因为某些很诡异的需要，我准备维护这么个程序。  
程序定位：  
它是一个单独的可执行程序，再没有其他依赖文件（依赖库、依赖配置文件、等）。  
程序尽量不被别人发现。所以不想让命令行参数那么显眼。  

## 可能有用的项目
程序的第一版源自`GolangSSHServer`。
```
https://github.com/leechristensen/GolangSSHServer
https://github.com/Scalingo/go-ssh-examples/
https://github.com/karfield/ssh2go
https://github.com/gravitational/teleport
```

## 编译说明
你可能需要先设置代理，然后执行
```
go get -u -v github.com/zx9229/MiniGolangSSHServer
```
其他的命令
```
go get -u -v golang.org/x/net
```
编译命令
```
CGO_ENABLED=0 go build -a -installsuffix cgo .
```

## 使用说明  
1. 保存帮助信息到`/tmp/cfg.json`文件。  
```
./MiniGolangSSHServer -h > /tmp/cfg.json  2>&1
```
2. 修改`/tmp/cfg.json`文件，仅保留json字符串。  
3. 修改json字符串到自己想要的配置。  
4. 用base64加密配置，并将加密字符串送给程序。  
* 以命令行参数的方式送进去：  
```
data=$(cat /tmp/cfg.json | base64 | sed ':a;N;s/\n//g;ta')
./MiniGolangSSHServer -base64=$data
```
* 以标准输入的方式送进去：
```
cat /tmp/cfg.json | base64 | sed ':a;N;s/\n//g;ta' | ./MiniGolangSSHServer -cin
```

## 其他说明
当前程序的环境变量有问题，在登录之后，请尽量执行以下命令：
```
HOME=$([ $(whoami) = "root" ] && echo /root || echo /home/$(whoami))
HOME=/home/$(whoami)    # 暂不考虑root用户
source /etc/profile
source ~/.bash_profile
```
