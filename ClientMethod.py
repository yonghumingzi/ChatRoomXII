#注册
def register(addr, s, register_clients, username, password):
    if username == "" or password == "":
        s.sendto(("username and password should not be empty").encode(), addr)
        return
    if username in register_clients.keys():
        s.sendto(("username exits, please use another one").encode(), addr)
        return
    s.sendto((username + " registered successfully").encode(), addr)
    register_clients[username] = password
    return

#登录
def login(addr, s, register_clients, online_clients, adminName, username, password):
    if username == adminName:
        s.sendto(("If you are admin, please login in by /admin").encode(), addr)
        return
    if username not in register_clients.keys():
        s.sendto(("login failed, please retry").encode(), addr)
        return
    if password != register_clients[username]:
        s.sendto(("login failed, please retry").encode(), addr)
        return
    address = ""
    for user in online_clients.items():
        if username == user[1]:
            address = user[0]
            s.sendto(("You are logged in somewhere else").encode(), address)
        else:
            s.sendto((username + " logged in").encode(), user[0])
    if address != "":
        del online_clients[address]
    s.sendto(("login success").encode(), addr)
    online_clients[addr] = username
    return