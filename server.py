import socket
import AdminMethod
import ClientMethod
from Crypto.Cipher import AES
import base64
import time
from os import system

# 管理员名称
adminName = "admin"
# 管理员密码
adminpwd = "pw"
# 连接端口
portForApp = 12345
# 有关的全局变量
BUFSIZE = 1024
# 上线用户表（address 用户名）
online_clients = {}
# 注册用户表（用户名 密码）
register_clients = {}
register_clients[adminName] = adminpwd
# 管理员地址
Adminaddr = ""
# 服务器地址
Serveraddr = "127.0.0.1"

#指令处理函数
def Deal(sock, addr, data):
    global Adminaddr
    parse = data.split(" ")
    hasRetValue = 0
    
    #对管理员身份进行验证
    if parse[0] == "/admin" and len(parse) == 2 and parse[1] == adminpwd:
        if Adminaddr != "":
            s.sendto(("You are logged in somewhere else").encode(), Adminaddr)
            del online_clients[Adminaddr]
        s.sendto(("Admin login success").encode(), addr)
        Adminaddr = addr
        online_clients[addr] = adminName
        return
    
    #处理管理员行为
    if Adminaddr and addr == Adminaddr:
        if parse[0] == '/admin':
            s.sendto(("You are already online").encode(), addr)
            hasRetValue = 1

        if parse[0] == '/listUsers' and len(parse) == 1:
            listUser(addr, sock, online_clients)
            hasRetValue = 1
        
        if parse[0] == '/leave' and len(parse) == 1:
            leave(addr, sock, online_clients)
            Adminaddr = ""
            hasRetValue = 1
            print('%s:%s logout' % addr)
        
        if parse[0].startswith("/@") and parse[1] == "private_message":
            if parse[-1] == "1":
                privateMessage(addr, sock, online_clients, parse[0][2:], data[17+len(parse[0]):-2], True)
            else:
                privateMessage(addr, sock, online_clients, parse[0][2:], data[17+len(parse[0]):-2], False)
            hasRetValue = 1

        if parse[0] == "/msg":
            if parse[-1] == "1":
                publicMessage(addr, sock, online_clients, data[5:-2], True)
            else:
                publicMessage(addr, sock, online_clients, data[5:-2], False)
            hasRetValue = 1
        
        if parse[0] == '/kickout' and len(parse) == 2:
            AdminMethod.kickoutUser(addr, parse[1], sock, online_clients)
            hasRetValue = 1

        if parse[0] == '/deleteUser' and len(parse) == 2:
            AdminMethod.deleteUser(addr, parse[1], sock, register_clients, online_clients)
            hasRetValue = 1
        
        if parse[0] == '/setencode' and len(parse) == 1:
            s.sendto(("encoding mode is set").encode(), addr)
            hasRetValue = 1
        
        if parse[0] == '/unsetencode' and len(parse) == 1:
            s.sendto(("encoding mode is disabled").encode(), addr)
            hasRetValue = 1

        #没有调用任何服务器函数，指令异常
        if hasRetValue == 0:
            s.sendto(("Nothing happen, check the wrong of input").encode(), addr)
        return
    
    # 处理用户行为
    if parse[0] == '/register' and len(parse) == 3:
        ClientMethod.register(addr, sock, register_clients, parse[1], parse[2])
        hasRetValue = 1

    if parse[0] == '/login' and len(parse) == 3:
        ClientMethod.login(addr, sock, register_clients, online_clients, adminName, parse[1], parse[2])
        hasRetValue = 1

    if parse[0] == '/listUsers' and len(parse) == 1:
        listUser(addr, sock, online_clients)
        hasRetValue = 1

    if parse[0] == '/leave' and len(parse) == 1:
        leave(addr, sock, online_clients)
        hasRetValue = 1
        print('%s:%s logout' % addr)
    
    if parse[0] == '/kickout' and len(parse) == 2:
        s.sendto(("this is a privileged command authorized to admin").encode(), addr)
        hasRetValue = 1

    if parse[0] == '/deleteUser' and len(parse) == 2:
        s.sendto(("this is a privileged command authorized to admin").encode(), addr)
        hasRetValue = 1

    if parse[0].startswith("/@") and parse[1] == "private_message":
        if parse[-1] == "1":
            privateMessage(addr, sock, online_clients, parse[0][2:], data[17+len(parse[0]):-2], True)
        else:
            privateMessage(addr, sock, online_clients, parse[0][2:], data[17+len(parse[0]):-2], False)
        hasRetValue = 1

    if parse[0] == "/msg":
        if parse[-1] == "1":
            publicMessage(addr, sock, online_clients, data[5:-2], True)
        else:
            publicMessage(addr, sock, online_clients, data[5:-2], False)
        hasRetValue = 1
    
    if parse[0] == '/setencode' and len(parse) == 1:
        s.sendto(("encoding mode is set").encode(), addr)
        hasRetValue = 1
        
    if parse[0] == '/unsetencode' and len(parse) == 1:
        s.sendto(("encoding mode is disabled").encode(), addr)
        hasRetValue = 1

    #没有调用任何服务器函数，指令异常
    if hasRetValue == 0:
        s.sendto(("Nothing happen, check the wrong of input").encode(), addr)
    return

#列举当前登录的所有用户
def listUser(addr, s, online_clients):
    str = ""
    for v in online_clients.values():
        str = str + v + " "
    s.sendto((str).encode(), addr)
    return

#退出程序
def leave(addr, s, online_clients):
    for userAddr in online_clients.keys():
        if userAddr == addr:
            s.sendto(("You left the room").encode(), userAddr)
        else:
            s.sendto((online_clients[addr] + " left the room").encode(), userAddr)
    del online_clients[addr]
    return

#发送私密消息
def privateMessage(addr, s, online_clients, receiver, message, enc):
    if addr not in online_clients.keys():
        s.sendto(("You are not logged in").encode(), addr)
        return
    if enc == True:   
        for user in online_clients.items():
            if user[1] == receiver:
                s.sendto((online_clients[addr] + "@" + receiver + ": " + message + "$").encode(), user[0])
                s.sendto((online_clients[addr] + "@" + receiver + ": " + message + "$").encode(), addr)
                return
    else:
        for user in online_clients.items():
            if user[1] == receiver:
                s.sendto((online_clients[addr] + "@" + receiver + ": " + message + "#").encode(), user[0])
                s.sendto((online_clients[addr] + "@" + receiver + ": " + message + "#").encode(), addr)
                return
    s.sendto((receiver + " is not online").encode(), addr)
    return

#发送公开消息
def publicMessage(addr, s, online_clients, message, enc):
    if addr not in online_clients.keys():
        s.sendto(("You are not logged in").encode(), addr)
        return
    if enc == True:
        for userAddr in online_clients.keys():
            s.sendto((online_clients[addr] + ": " + message + "$").encode(), userAddr)
    else:
        for userAddr in online_clients.keys():
            s.sendto((online_clients[addr] + ": " + message + "#").encode(), userAddr)        
    return

# 创建UDP套接字
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# 将链接进行绑定
s.bind((Serveraddr, portForApp))
print('Bound UDP on {}……'.format(portForApp))

# 接收客户端消息
while True:
    print('waiting for connection...')
    data, addr = s.recvfrom(BUFSIZE)
    print('Received from %s:%s.'%addr)
    currentclient = addr
    system("echo {t} {addr} {command}>> server.log".format(t = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()), addr=addr, command=data.decode()))
    Deal(s,addr,data.decode())