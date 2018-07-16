# MiniGolangSSHServer  
因为某些很诡异的需要，我想使用这么一个程序：  
我需要一个SSH Server。  
它是一个单独的可执行程序，再没有其他依赖文件（依赖库、依赖配置文件、等）。  
我很欣喜的找到了`https://github.com/leechristensen/GolangSSHServer`和`https://github.com/karfield/ssh2go`。  
我决定拷贝`https://github.com/leechristensen/GolangSSHServer`的代码，然后在其基础上改吧改吧。  
于是出现了这个repository。  


## 其他说明
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
```
data=$(cat /tmp/cfg.json | base64 | sed ':a;N;s/\n//g;ta')
./MiniGolangSSHServer -base64=$data
```
