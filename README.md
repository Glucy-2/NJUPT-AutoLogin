# NJUPT-AutoLogin
南京邮电大学校园网自动登录脚本

## 功能特性
- 支持循环登录与单次登录
- 登录失败错误信息判断与提示
- 指定了 No Proxy，可以绕过系统代理（但是无法绕过 TUN（透明代理），透明网关，路由表修改等），防止代理无法连接或分流配置不合理导致无法登录
- 跨平台（Windows，Linux（不支持Termux））
- 支持多个网卡、多个账号
- 有线与无线均支持
- 无线模式下自动连接WiFi

## 使用方法
1. 下载脚本
2. 安装 Python 3.10 或以上版本，并安装依赖库（`netifaces` `pywifi` `Requests` `requests_toolbelt`）：
```sh
python -m pip install -r requirements.txt
```
3. 运行脚本（添加`-h`参数查看可用参数列表和帮助）