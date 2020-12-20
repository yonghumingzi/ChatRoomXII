from tkinter import *
from tkinter import messagebox
from socket import *
from threading import *
from  tkinter  import ttk
from tkinter.scrolledtext import *
from Crypto.Cipher import AES
import time 
import base64
import re

#AES密钥
KEY = 'KH2J9-PC326-T44D4-39H6V-TVPBY'

isLogin = False

def add_to_16(value):
    while len(value) % 16 != 0:
        value += '\0'
    return str.encode(value)

def encrypt_oracle(key, text):
    aes = AES.new(add_to_16(key), AES.MODE_ECB)
    encrypt_aes = aes.encrypt(add_to_16(text))
    encrypted_text = str(base64.encodebytes(encrypt_aes), encoding='utf-8')
    return encrypted_text[:-1]

def decrypt_oralce(key, cipher):
    aes = AES.new(add_to_16(key), AES.MODE_ECB)
    base64_decrypted = base64.decodebytes(cipher.encode(encoding='utf-8'))
    decrypted_text = str(aes.decrypt(base64_decrypted),encoding='utf-8').replace('\0','') 
    return decrypted_text

cipherPattern = re.compile("\: (.*?)\$")

#客户端接受函数
class Receive():
    def __init__(self, server, gettext, privatemessage, publicmessage, cipher, exitbutton, registerButton, loginButton):
        while 1:
            try:
                text = server.recv(1024)
                if not text: break
                gettext.configure(state='normal')
                content = text.decode()
                if self.loginMessage(content):
                    privatemessage['state'] = NORMAL
                    publicmessage['state'] = NORMAL
                    cipher['state'] = NORMAL
                    exitbutton['state'] = NORMAL
                    registerButton['state'] = DISABLED
                    loginButton['state'] = DISABLED
                elif self.logoutMessage(content):
                    privatemessage['state'] = DISABLED
                    publicmessage['state'] = DISABLED
                    cipher['state'] = DISABLED
                    exitbutton['state'] = DISABLED
                    registerButton['state'] = NORMAL
                    loginButton['state'] = NORMAL
                #加密模式
                if content[-1] == "$":
                    cipher = cipherPattern.findall(content)[0]
                    plain = decrypt_oralce(KEY, cipher)
                    content = content.replace(cipher, plain)[:-1]
                #明文传输模式
                elif content[-1] == "#":
                    content = content[:-1]
                mytime = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
                gettext.insert(END,'%s\n' % mytime)
                gettext.insert(END,'  %s\n' % content)
                gettext.configure(state='disabled')
                gettext.see(END)
            except:
                break
    
    def loginMessage(self, content):
        if "login success" in content:
            return True
        return False
    
    def logoutMessage(self, content):
        if content in ["Your account has been deleted by admin", "You have been kicked out by admin", "You left the room", "You are not logged in"]:
            return True
        return False

class App(Thread):
    client = socket(AF_INET, SOCK_DGRAM)
    client.connect(('127.0.0.1', 12345))

    def __init__(self, master):
        def close_room():
            master.destroy()
            master.quit()
            exit()
        
        Thread.__init__(self)
        master.protocol("WM_DELETE_WINDOW", close_room)
        frame = Frame(master)
        frame.pack()
        self.login_info = ""
        self.register_info = ""
        self.gettext = ScrolledText(frame, height=20, width=100 )
        self.gettext.pack()
        self.gettext.insert(END,'Welcome to UDP Chat Room\n')
        self.gettext.configure(state='disabled')
        sframe = Frame(frame)
        sframe.pack(anchor='w')
        
        self.pro = Label(sframe, text="Input>>")
        self.command = StringVar()
        
        #组合下拉框
        self.textEnter = ttk.Combobox(sframe,width=55,textvariable = self.command)
        self.textEnter['values'] = ("/admin ", "/listUsers", "/kickout ", "/deleteUser ")
        self.textEnter.bind(sequence="<Return>", func=self.Send)  # <Return>：回车键事件
        self.pro.pack(side=LEFT)
        self.textEnter.pack(side=LEFT)

        #注册按钮
        self.registerButton = Button(root, text = "Register", command = self.register)

        #登录按钮
        self.loginButton = Button(root, text = "Login", command = self.login)

        #公开信息按钮
        self.publicmessage = Button(root, text = "Public MS",command = self.publicMessage)

        #退出按钮
        self.exit = Button(root, text = "exit",command = self.leaveRoom)

        #加密按钮
        self.ifCipher = BooleanVar()
        self.cipher = Checkbutton(root, text = "encode", variable = self.ifCipher, command = self.encodeFunc)

        self.tag = Label(sframe, text="Only To>>")
        
        #目标用户栏
        self.aimuser = Entry(sframe, width=20)
        self.aimuser.bind(sequence="<Return>", func=self.privateMessage)
        self.aimuser.pack(side=RIGHT)
        self.tag.pack(side=RIGHT)
        
        #私密信息按钮
        self.privatemessage = Button(root, text="Private MS", command=self.privateMessage)

        self.cipher.pack(side=RIGHT, ipadx = 10, padx = 20)
        self.exit.pack(side=RIGHT, ipadx = 10, padx = 20)
        self.privatemessage.pack(side=RIGHT, ipadx = 10, padx = 20)
        self.publicmessage.pack(side=RIGHT, ipadx=10, padx=10)
        self.registerButton.pack(side=RIGHT, ipadx = 10, padx = 20)
        self.loginButton.pack(side=RIGHT, ipadx = 10, padx = 20)

        self.privatemessage['state'] = DISABLED
        self.publicmessage['state'] = DISABLED
        self.cipher['state'] = DISABLED
        self.exit['state'] = DISABLED

    def encodeFunc(self):
        if self.ifCipher.get() == True:
            self.client.send(("/setencode").encode())
        else:
            self.client.send(("/unsetencode").encode())
        return
    
    def register(self):
        self.getRegisterInput()
        if self.register_info != "":
            self.client.send(("/register " + self.register_info).encode())
            self.register_info = ""
            return
        return

    # 注册框
    def getRegisterInput(self):
        def return_callback():
            username = entry1.get()
            password = entry2.get()
            password_repeat = entry3.get()
            if username == "" or password == "":
                messagebox.showinfo('message', 'Neither username nor password should be empty')
            if password != password_repeat:
                messagebox.showinfo('message', 'The password does not match the re-typed one')
            else:
                self.register_info = " ".join((username,password))
                root.quit()

        def close_callback():
            root.quit()

        root = Tk(className="register")
        root.wm_attributes('-topmost', 1)
        screenwidth, screenheight = root.maxsize()
        width = 300
        height = 180
        size = '%dx%d+%d+%d' % (width, height, (screenwidth - width)/2, (screenheight - height)/2)
        root.geometry(size)
        root.resizable(0, 0) 
        lable1 = Label(root)
        lable1['text'] = "username: "
        entry1 = Entry(root)
        lable2 = Label(root)
        lable2['text'] = "password: "
        entry2 = Entry(root, show='*')
        lable3 = Label(root)
        lable3['text'] = "re-type password: "
        entry3 = Entry(root, show='*')
        loginButton = Button(root, text="register", width = 10, command = return_callback)
        lable1.pack()
        entry1.pack()
        lable2.pack()
        entry2.pack()
        lable3.pack()
        entry3.pack()
        entry1.focus_set()
        loginButton.pack()
        root.protocol("WM_DELETE_WINDOW", close_callback)
        root.mainloop()
        root.destroy()

    def login(self):
        self.getLoginInput()
        if self.login_info != "":
            self.client.send(("/login " + self.login_info).encode())
            self.login_info = ""
            return
        return
        
    # 登录框
    def getLoginInput(self):
        def return_callback():
            username = entry1.get()
            password = entry2.get()
            if username == "" or password == "":
                messagebox.showinfo('message', 'Neither username nor password should be empty')
            else:
                self.login_info = " ".join((username,password))
                root.quit()

        def close_callback():
            root.quit()

        root = Tk(className="login")
        root.wm_attributes('-topmost', 1)
        screenwidth, screenheight = root.maxsize()
        width = 300
        height = 140
        size = '%dx%d+%d+%d' % (width, height, (screenwidth - width)/2, (screenheight - height)/2)
        root.geometry(size)
        root.resizable(0, 0)
        lable1 = Label(root)
        lable1['text'] = "username: "
        entry1 = Entry(root)
        lable2 = Label(root)
        lable2['text'] = "password: "
        entry2 = Entry(root, show='*')
        loginButton = Button(root, text="login", width = 10, command = return_callback)
        lable1.pack()
        entry1.pack()
        lable2.pack()
        entry2.pack()
        entry1.focus_set()
        loginButton.pack()
        root.protocol("WM_DELETE_WINDOW", close_callback)
        root.mainloop()
        root.destroy()

    #发送私密消息函数
    def privateMessage(self):
        self.gettext.configure(state='normal')
        message = self.textEnter.get()
        aimuser = self.aimuser.get()
        if message == "": message = " "
        self.textEnter.delete(0, END)
        if self.ifCipher.get() == True:
            self.client.send(("/@" + aimuser+" private_message " + encrypt_oracle(KEY, message) + " 1").encode())
        else:
            self.client.send(("/@" + aimuser+" private_message " + message + " 0").encode())
        self.textEnter.focus_set()
        self.gettext.configure(state='disabled')
        self.gettext.see(END)
        return
    
    #发送公开消息函数
    def publicMessage(self):
        self.gettext.configure(state='normal')
        message = self.textEnter.get()
        if message == "": message = " "
        self.textEnter.delete(0, END)
        if self.ifCipher.get() == True:
            self.client.send(("/msg " + encrypt_oracle(KEY, message) + " 1").encode())
        else:
            self.client.send(("/msg " + message + " 0").encode())
        self.textEnter.focus_set()
        self.gettext.configure(state='disabled')
        self.gettext.see(END)
        return
    
    # 退出
    def leaveRoom(self):
        self.client.send(("/leave").encode())
        return
  
    #发送消息函数
    def Send(self, args):
        text = self.textEnter.get()
        aimuser = self.aimuser.get()
        #识别是否是指令
        if not text.startswith("/"):
            #判断目标用户栏是否为空
            if aimuser == "":
                self.publicMessage()
            else:
                self.privateMessage()
        else:
            self.gettext.configure(state='normal')
            if text=="": text=" "
            self.gettext.insert(END,'C >> %s\n'%text)
            self.textEnter.delete(0,END)
            self.client.send(text.encode())
            self.textEnter.focus_set()
            self.gettext.configure(state='disabled')
            self.gettext.see(END)
    
    def run(self):
        Receive(self.client, self.gettext, self.privatemessage, self.publicmessage, self.cipher, self.exit, self.registerButton, self.loginButton)

root = Tk()
root.title('UDP Chat Room')
app = App(root).start()
root.mainloop()

