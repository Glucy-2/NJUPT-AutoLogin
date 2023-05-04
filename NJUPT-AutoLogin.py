#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import time
import socket
import signal
import pywifi
import logging
import requests
import netifaces
import logging.handlers
from base64 import b64decode
from argparse import ArgumentParser
from configparser import ConfigParser
from urllib.parse import urlparse, unquote, parse_qs
from requests_toolbelt.adapters.source import SourceAddressAdapter


__author__ = "Glucy2 (https://github.com/Glucy-2)"
__version__ = "1.0.1"


class Logger:
    """
    日志类
    """

    logger = logging.getLogger()

    def __init__(self, log_level):
        self.logger = logging.getLogger()
        self.logger.setLevel(log_level)

        handler = logging.handlers.TimedRotatingFileHandler(
            filename="autologin.log", when="midnight", encoding="UTF-8", backupCount=7
        )
        handler.setLevel(log_level)

        formatter = logging.Formatter(
            "[%(asctime)s][%(process)d][%(funcName)s (%(filename)s:%(lineno)d)]: [%(levelname)s]: %(message)s"
        )
        handler.setFormatter(formatter)

        self.logger.addHandler(handler)


class Config:
    """
    配置类
    """

    loop_interval = 300
    redirect_url = "http://6.6.6.6/?isReback=1"
    check_address = "http://connect.rom.miui.com/generate_204"
    login_host = "10.10.244.11"
    login_port = 801
    acc_list = []

    def __init__(self, iface, account, password, isp, time_limited):
        self.iface = iface
        self.account = account
        self.password = password
        self.isp = isp
        self.time_limited = time_limited


class ErrMsg:
    """
    错误信息类
    """

    errs = [
        ["1", "Rpost=2;ret='no errcode'", "AC认证失败", "AC authentication failure"],
        [
            "2",
            "Rpost=2;ret=''",
            "SESSION已过期,请重新登录",
            "The SESSION has been expired, please log in again",
        ],
        [
            "3",
            "Rpost=2;ret='Authentication Fail ErrCode=04'",
            "上网时长/流量已到上限",
            "Online time / flow rate has been to the limit",
        ],
        [
            "4",
            "Rpost=2;ret='Authentication Fail ErrCode=05'",
            "您的账号已停机，造成停机的可能原因：<br/>1、用户欠费停机<br/>2、用户报停<br/>需要了解具体原因，请访问自助服务系统。",
            "Your account has been shut down",
        ],
        [
            "5",
            "Authentication Fail ErrCode=09",
            "本账号费用超支，禁止使用",
            "Online time / flow rate has been to the limit",
        ],
        [
            "6",
            "Rpost=2;ret='Authentication Fail ErrCode=11'",
            "不允许Radius登录",
            "Not allow radius login",
        ],
        [
            "7",
            "Rpost=2;ret='Authentication Fail ErrCode=80'",
            "接入服务器不存在",
            "Access to the server does not exist",
        ],
        [
            "8",
            "Rpost=2;ret='Authentication Fail ErrCode=81'",
            "LDAP认证失败",
            "LDAP Authentication Failure",
        ],
        [
            "9",
            "Rpost=2;ret='Authentication Fail ErrCode=85'",
            "账号正在使用",
            "Accounts are in use",
        ],
        [
            "10",
            "Rpost=2;ret='Authentication Fail ErrCode=86'",
            "绑定IP或MAC失败",
            "IP or MAC Binding Fail",
        ],
        [
            "11",
            "Rpost=2;ret='Authentication Fail ErrCode=88'",
            "IP地址冲突",
            "IP address conflict",
        ],
        [
            "12",
            "Rpost=2;ret='Authentication Fail ErrCode=94'",
            "接入服务器并发超限",
            "Concurrent access to the server overrun",
        ],
        [
            "13",
            "err(2)",
            "请在指定的登录源地址范围内登录",
            "Please Login in at the specified source address range",
        ],
        ["14", "err(3)", "请在指定的IP登录", "Please login at the specified IP"],
        ["15", "err(7)", "请在指定的登录源VLAN范围登录", "Please login in at specified Vlan scope"],
        ["16", "err(10)", "请在指定的Vlan登录", "Please login at the specified Vlan"],
        ["17", "err(11)", "请在指定的MAC登录", "Please login at the specified MAC"],
        [
            "18",
            "err(17)",
            "请在指定的设备端口登录",
            "Please login with the specified equipment port",
        ],
        [
            "19",
            "userid error1",
            "账号不存在或未绑定运营商账号！",
            "Account does not exist or not bind isp account.",
        ],
        ["20", "userid error2", "校园网密码错误", "Password Error"],
        ["21", "userid error3", "密码错误", "Password Error"],
        ["22", "auth error4", "用户使用量超出限制", "Users to use more than limit"],
        ["23", "auth error5", "账号已停机", "This account has been shut down"],
        ["24", "auth error9", "时长流量超支", "Time length or flow overruns"],
        ["25", "auth error80", "本时段禁止上网", "This time on the Internet is prohibited"],
        ["26", "auth error99", "用户名或密码错误", "The user name or password mistake"],
        ["27", "auth error198", "用户名或密码错误", "The user name or password mistake"],
        ["28", "auth error199", "用户名或密码错误", "The user name or password mistake"],
        [
            "29",
            "auth error258",
            "账号只能在指定区域使用",
            "This account can only be used in designated areas",
        ],
        ["30", "auth error", "用户验证失败", "Failed to authenticate user"],
        ["31", "set_onlinet error", "用户数超过限制", "Users more than limit"],
        [
            "32",
            "In use",
            "终端超限，请至<a href='http://10.10.244.240:8080/Self'>自服务</a>选择终端强制离线后重试",
            "Log in more than limit",
        ],
        [
            "33",
            "port err",
            "上课时间不允许上网",
            "Class time is not allowed to access to the Internet",
        ],
        ["34", "can not use static ip", "不允许使用静态IP", "Can not use static ip"],
        [
            "35",
            "[01], 本帐号只能在指定VLANID使用(0.4095)",
            "本帐号只能在指定VLANID使用",
            "This account can only be used in the specified VLANID",
        ],
        [
            "36",
            "Mac, IP, NASip, PORT err(6)",
            "本帐号只能在指定VLANID使用",
            "This account can only be used in the specified VLANID",
        ],
        [
            "37",
            "Rpost=2;ret='wuxian OLno",
            "VLAN范围控制账号的接入数量超出限制",
            "VLAN range control account access limit exceeded",
        ],
        [
            "38",
            "Oppp error: 1",
            "运营商账号密码错误，错误码为：1",
            "Operator account password error, error code: 1",
        ],
        [
            "39",
            "Oppp error: 5",
            "运营商账号在线，错误码为：5",
            "Operator account online, error code: 5",
        ],
        [
            "40",
            "Oppp error: 18",
            "运营商账号密码错误，错误码为：18",
            "Operator account password error, error code: 18",
        ],
        [
            "41",
            "Oppp error: 21",
            "运营商账号在线，错误码为：21",
            "Operator account online, error code: 21",
        ],
        [
            "42",
            "Oppp error: 26",
            "运营商账号被绑定，错误码为：26",
            "Operator account online, error code: 21",
        ],
        [
            "43",
            "Oppp error: 29",
            "运营商账号锁定的用户端口NAS-Port-Id错误，错误码为：29",
            "Operator account online, error code: 21",
        ],
        [
            "44",
            "Oppp error: userid inuse",
            "运营商账号已被使用",
            "Operator account has been used",
        ],
        [
            "45",
            "Oppp error: can't find user",
            "运营商账号无法获取或不存在",
            "Operator account could not be obtained or does not exist",
        ],
        ["46", "bind userid error", "绑定运营商账号失败", "Bind operator account failed"],
        [
            "47",
            "Oppp error: TOO MANY CONNECTIONS",
            "运营商账号在线",
            "Operator account online",
        ],
        [
            "48",
            "Oppp error: Timeout",
            "运营商账号状态异常(欠费等)",
            "Operator account status abnormal(arrears, etc.)",
        ],
        [
            "49",
            "Oppp error: User dial-in so soon",
            "运营商账号刚下线",
            "Operator account just off the assembly line",
        ],
        ["50", "Rad:UserName_Err", "所绑定的运营商账号不存在，请咨询运营商！"],
        ["51", "Rad:Passwd_Err", "所绑定的运营商密码错误，请咨询运营商！"],
        ["52", "Rad:Status_Err", "运营商账号已停机！"],
        ["53", "Rad:Group_Bind_Err", "运营商绑定组信息错误，请至营业厅解决。"],
        ["54", "Rad:Limit Users Err", "运营商终端数量超限!"],
        ["55", "Rad:Date Invalid", "运营商账号过期！"],
        ["56", "Rad:UserName invalid", "绑定的运营商账号有非法字段，请在自服务确认绑定的运营商账号密码信息。"],
        ["57", "Rad:BindAttr_Err", "运营商绑定校验错误，请联系对应运营商解决。"],
    ]


def add_account(interfaces, wireless_interface_guids) -> bool:
    """
    添加账号，传入值为网络接口列表和无线网络接口GUID列表，返回是否继续添加
    """
    print("可用的网络接口：")
    num = 0
    while num < len(interfaces):
        addrs = netifaces.ifaddresses(str(interfaces[num]))
        if netifaces.AF_INET in addrs:
            ip = addrs[netifaces.AF_INET][0]["addr"]
        else:
            ip = "无法获取IP地址"
        type = "无线" if interfaces[num] in wireless_interface_guids else "有线"
        print(f"编号：{num}，类型：{type}，接口：{interfaces[num]}，IP：{ip}")
        num += 1

    num = input("请选择网络接口的编号：")
    iface = interfaces[int(num)]

    account = input("请输入学号：")
    password = input("请输入密码：")
    isp = input("请输入运营商（电信：njxy，移动：cmcc，校园网：其他任意内容）：")
    match input("账号是否限时登录（Y/n）："):
        case "N" | "n":
            time_limited = False
        case _:
            time_limited = True

    Config.acc_list.append(Config(iface, account, password, isp, time_limited))
    match input("是否继续添加账号？（y/N）"):
        case "Y" | "y":
            return True
        case _:
            return False


def read_config():
    config = ConfigParser()
    config.read(filenames="config.ini", encoding="utf-8")
    Config.redirect_url = config["shared"]["redirect_url"]
    Config.check_address = config["shared"]["check_address"]
    Config.login_host = config["shared"]["login_host"]
    try:
        Config.login_port = int(config["shared"]["login_port"])
    except ValueError:
        print(f"配置文件中的 login_port 配置项不正确，将使用默认值 {Config.login_port}")
    logins = config.sections()
    logins.remove("shared")
    for login in logins:
        try:
            Config.acc_list.append(
                Config(
                    config[login]["iface"],
                    config[login]["account"],
                    config[login]["password"],
                    config[login]["isp"],
                    bool(config[login]["time_limited"]),
                )
            )
        except KeyError:
            print(f"配置文件中的 {login} 配置项不完整，已跳过")
        except ValueError:
            print(f"配置文件中的 {login} 配置项不完整，已跳过")


def write_config():
    conf = ConfigParser()
    conf.add_section("shared")
    conf.set("shared", "redirect_url", Config.redirect_url)
    conf.set("shared", "check_address", Config.check_address)
    conf.set("shared", "login_host", Config.login_host)
    conf.set("shared", "login_port", str(Config.login_port))
    num = 0
    for acc in Config.acc_list:
        conf.add_section(str(num))
        conf.set(str(num), "iface", acc.iface)
        conf.set(str(num), "account", acc.account)
        conf.set(str(num), "password", acc.password)
        conf.set(str(num), "isp", acc.isp)
        conf.set(str(num), "time_limited", str(acc.time_limited))

    with open("config.ini", "w") as f:
        conf.write(f)


def configure():
    """
    配置函数
    """
    logger = Logger.logger
    interfaces = netifaces.interfaces()
    wireless_iface_guids = []
    wireless_ifaces = pywifi.PyWiFi().interfaces()
    for iface in wireless_ifaces:
        wireless_iface_guids.append(str(iface._raw_obj["guid"]))

    loop_interval = input(f"请输入登录状态检查循环间隔（秒，不输入则默认{Config.loop_interval}）：")
    if loop_interval:
        Config.loop_interval = int(loop_interval)

    redirect_url = input(f"请输入登录页面重定向URL（不输入则默认{Config.redirect_url}）：")
    if redirect_url:
        Config.redirect_url = redirect_url

    check_address = input(f"请输入检查网络连接的URL（必须返回204，不输入则默认{Config.check_address}）：")
    if check_address:
        Config.check_address = check_address

    while add_account(interfaces, wireless_iface_guids):
        continue

    write_config()
    logger.info("配置文件已保存！")
    match input("是否立即执行登录？（y/N）"):
        case "Y" | "y":
            login()
        case _:
            return


def check_limited_by_time() -> bool:
    """
    检查是否在限时登录时间段内，如果是则返回True，否则返回False
    """
    hr_min = int(time.strftime("%H%M", time.localtime()))
    match time.strftime("%w", time.localtime()):
        case "0":
            # 周日23:30之前
            if hr_min <= 2330:
                return True
            else:
                return False
        case "1" | "2" | "3" | "4":
            # 周一至周四7:00-23:30
            if 700 <= hr_min <= 2330:
                return True
            else:
                return False
        case "5":
            # 周五7:00以后
            if 700 <= hr_min:
                return True
            else:
                return False
        case "6":
            # 周六全天
            return True
        case _:
            return False


def check_internet(s, address) -> bool:
    """
    检查是否能够连接到互联网（设置的地址是否返回204），如果能则返回True，否则返回False
    """
    logger = Logger.logger
    sta_code = s.get(address).status_code
    logger.debug(f"检查网络连接的URL：{address}，返回状态码：{sta_code}")
    return True if sta_code == 204 else False


def connect_wifi(acc, wireless_iface) -> bool:
    """
    连接WiFi，如果成功则返回True，否则返回False
    """
    logger = Logger.logger
    profile = pywifi.Profile()
    match acc.isp:
        case "cmcc":
            profile.ssid = "NJUPT-CMCC"
        case "njxy":
            profile.ssid = "NJUPT-CHINANET"
        case _:
            profile.ssid = "NJUPT"
    logger.debug(f"要连接的WiFi的SSID：{profile.ssid}")
    profile.auth = pywifi.const.AUTH_ALG_OPEN
    done = False
    connect_count = 0
    while not done:
        wireless_iface_status = wireless_iface.status()
        if wireless_iface_status == pywifi.const.IFACE_CONNECTED:
            wireless_iface.disconnect()
            logger.debug(f"无线网卡 {wireless_iface.name()}（{acc.iface}）断开连接！")
        elif wireless_iface_status == pywifi.const.IFACE_CONNECTING:
            logger.debug(
                f"无线网卡 {wireless_iface.name()}（{acc.iface}）正在连接到 {profile.ssid} ！"
            )
        elif wireless_iface_status == pywifi.const.IFACE_DISCONNECTED:
            if connect_count < 3:
                logger.info(f"无线网卡 {wireless_iface.name()}（{acc.iface}）断开连接！")
                wireless_profile = wireless_iface.add_network_profile(profile)
                wireless_iface.connect(wireless_profile)
                connect_count += 1
                logger.debug(
                    f"无线网卡 {wireless_iface.name()}（{acc.iface}）正在连接到 {profile.ssid} ！"
                )
                time.sleep(1)
            else:
                logger.error(f"无线网卡 {wireless_iface.name()}（{acc.iface}）连接失败！")
                done = True
                result = False

    return result


def check_err_msg(err_code):
    err_msg = []
    for msgs in ErrMsg.errs:
        for msg in msgs:
            if msg in err_code or err_code in msg:
                err_msg.append(msgs[2])
    if err_msg == []:
        err_msg = [f"无法识别：{err_code}"]
    return err_msg


def login_account(acc: Config, wireless: bool) -> bool:
    """
    登录账号，如果成功则返回True，否则返回False
    """
    logger = Logger.logger

    if acc.time_limited and not check_limited_by_time():
        logger.info(f"{acc.iface} 上的 {acc.account} 未到登录时间！")
        return False

    if wireless:
        wireless_ifaces = pywifi.PyWiFi().interfaces()
        for iface in wireless_ifaces:
            if str(iface._raw_obj["guid"]) == acc.iface:
                connect_wifi(acc, iface)
                break
        else:
            logger.error(f"找不到 {acc.iface} 无线网卡！")
            return False

    waited_time = 0
    while waited_time < 3:
        logger.debug(f"尝试获取 {acc.iface} 的IP地址……")
        addrs = netifaces.ifaddresses(acc.iface)

        if netifaces.AF_INET in addrs:
            ip = addrs[netifaces.AF_INET][0]["addr"]
        else:
            logger.error(f"找不到 {acc.iface} 的IP地址！该网卡是否已连接？")
            return False
        waited_time += 1

    try:
        s = socket.create_connection(
            (Config.login_host, Config.login_port), source_address=(ip, 0)
        )
        s.close()
    except Exception as e:
        logger.error(f"{acc.iface} 与登录服务器不通：{e}")
        return False

    s = requests.Session()
    s.mount("http://", SourceAddressAdapter(ip))
    s.trust_env = False
    s.proxies = {"all": None, "http": None}

    if check_internet(s, Config.check_address):
        logger.info(f"{acc.iface} 网络正常，无需登录！")
        return True

    # 获取登录URL
    logger.debug(f"从 {Config.redirect_url} 获取登录网页URL...")
    try:
        r = s.get(Config.redirect_url, proxies={"http": None}).text
    except TimeoutError:
        logger.error(f"从 {Config.redirect_url} 获取登录网页URL超时！")
        return False
    login_url_start = r.find("http://")
    login_url_end = r.find('"', login_url_start)
    login_url = r[login_url_start:login_url_end]
    logger.debug(f"登录网页URL：{login_url}")

    # 解析URL
    logger.debug(f"解析登录网页URL...")
    parsed_url = urlparse(login_url)

    # 获取参数字典
    params = parse_qs(parsed_url.query)

    # 获取参数值
    wlanacip = params["wlanacip"][0]
    wlanacname = params["wlanacname"][0]

    url = f"http://{Config.login_host}:{Config.login_port}/eportal/?c=ACSetting&a=Login&protocol=http:&hostname={Config.login_host}&iTermType=1&wlanuserip={ip}&wlanacip={wlanacip}&wlanacname={wlanacname}&mac=00-00-00-00-00-00&ip={ip}&enAdvert=0&queryACIP=0&loginMethod=1"
    logger.debug(f"登录数据发送URL：{url}")

    match acc.isp:
        case "njxy" | "cmcc":
            login = f",0,{acc.account}@{acc.isp}"
        case _:
            login = f",0,{acc.account}"

    login_data = {
        "DDDDD": login,
        "upass": acc.password,
        "R1": 0,
        "R2": 0,
        "R3": 0,
        "R6": 0,
        "para": "00",
        "0MKKey": 123456,
        "buttonClicked": None,
        "redirect_url": None,
        "err_flag": None,
        "username": None,
        "password": None,
        "user": None,
        "cmd": None,
        "Login": None,
        "v6ip": None,
    }
    logger.debug(f"登录数据：{login_data}")

    login_response_url = s.post(url, data=login_data, proxies=None).url

    logger.debug(f"解析登录结果URL...")
    parsed_url = urlparse(login_response_url)

    match parsed_url.path:
        case "/3.htm":
            logger.info(f"{acc.iface} 登录 {login} 成功！")
            check_internet(s, Config.check_address)
            s.close()
            return True
        case "/2.htm":
            s.close()
            logger.debug("解析错误原因...")
            err_code = unquote(b64decode(parse_qs(parsed_url.query)["ErrorMsg"][0]))
            logger.warning(f"{acc.iface} 登录 {login} 失败，可能的原因：{check_err_msg(err_code)}")
            return False
        case _:
            s.close()
            logger.error(f"无法判断 {acc.iface} 登录 {login} 结果！")
            return False


def login():
    logger = Logger.logger
    wireless_iface_guids = []
    wireless_ifaces = pywifi.PyWiFi().interfaces()
    for iface in wireless_ifaces:
        wireless_iface_guids.append(str(iface._raw_obj["guid"]))

    logged_ins = {}
    for acc in Config.acc_list:
        if acc.iface not in logged_ins.keys() or logged_ins[acc.iface] == acc.account:
            wireless = True if acc.iface in wireless_iface_guids else False
            if login_account(acc, wireless):
                logged_ins[acc.iface] = acc.account


def loop():
    logger = Logger.logger
    while True:
        login()
        logger.info(f"等待 {Config.loop_interval} 秒...")
        time.sleep(Config.loop_interval)


def main():
    parser = ArgumentParser()
    parser.description = """
    南京邮电大学校园网自动登录程序
    首次启动时会生成配置文件 config.ini，可根据需要修改
    日志存放在 autologin.log 中，旧的日志自动添加后缀，保留7天
    """
    parser.add_argument("-c", "--configure", action="store_true", help="生成配置文件")
    parser.add_argument("-d", "--debug", action="store_true", help="调试模式（在日志中添加DEBUG等级的信息）")
    parser.add_argument("-n", "--noloop", action="store_true", help="不循环登录（仅登录一次就退出）")
    args = parser.parse_args()

    signal.signal(signal.SIGINT, signal.SIG_DFL)  # 使Ctrl+C可用

    if sys.gettrace() or args.debug:
        Logger(logging.DEBUG)
    else:
        Logger(logging.INFO)

    logger = Logger.logger
    logger.info(f"NJUPT-AutoLogin v{__version__} by {__author__}")

    if args.configure:
        if os.path.isfile("config.ini"):
            read_config()
        configure()
    elif not os.path.isfile("config.ini"):
        configure()
    else:
        read_config()
        if args.noloop:
            login()
        else:
            loop()


if __name__ == "__main__":
    main()
