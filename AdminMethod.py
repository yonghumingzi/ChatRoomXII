#踢出用户
def kickoutUser(addr,username,s,online_clients):
    if username in online_clients.values():
        for user in online_clients.items():
            if user[1] == username:
                address = user[0]
                s.sendto(("You have been kicked out by admin").encode(), address)
            else:
                s.sendto((username + " has been kicked out by admin").encode(), user[0])
        del online_clients[address]
        return
    s.sendto((username + " is not online").encode(), addr)
    return

# 删除用户
def deleteUser(addr, username, s, register_clients, online_clients):
    address = ""
    if username in register_clients.keys():
        for user in online_clients.items():
            if user[1] ==  username:
                address = user[0]
                s.sendto(("Your account has been deleted by admin").encode(), address)
            else:
                s.sendto((username + " has been deleted").encode(), user[0])
        if address != "":
            del online_clients[address]
        del register_clients[username] 
        return  
    s.sendto((username + " does not exist").encode(), addr)
    return

        