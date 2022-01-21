from __future__ import print_function
import ida_kernwin
import ida_lines
import random
from ast import literal_eval
from array import *

apis = []
print_to = []
risk = ""
current_api = -1
mal_found = 0

api_list = [["Registry","RegCreateKeyA", "RegCreateKeyExA", "RegDeleteValueA", "RegOpenKeyA","RegSetValueExA"],
["Downloader","URLDownloadToFileA","ShellExecuteA","WinExec","URLDownloadToFileW"],
["C&C Connection","InternetOpenA","InternetConnectA","HttpOpenRequestA","HttpAddRequestHeadersA","HTTPSendRequestA","InternetReadFile"],
["Keylogger","GetAsyncKeyState","GetKeyState","SetWindowsHookExA"],
["Network Traffic Monitor","WSASocket","socket","bind","WSAIoctl","ioctlsocket"],
["Dropper","FindResourceA","LoadResource","SizeofResource","LockResource"],
["Process Hollowing","CreateProcessA","NtUnmapViewOfSection","VirtualAllocEx","WriteProcessMemory","ResumeThread"],
["AntiDebugger/VM detection","GetTickCount","CountClipboardFormats","GetForeGroundWindow","IsDebuggerPresent"],
["API Hooking, User-Space Function","GetProcAddress","VirtualProtect","ReadProcessMemory","WriteProcessMemory"],
["Process Blacklist", "TerminateProcess","OpenProcess","CreateToolhelp32Snapshot","Process32NextW","Process32FirstW","CloseHandle"]]

api_len = len(api_list)

def print_api(self,prefix,bg):
    global current_api
    global api_list
    global mal_found
    bg = rand_color()
    current_api += 1
    ret1 = api_check(api_list[current_api])
    a = ' '.join([str(a) for a in print_to])
    if ret1 != 0:  
        self.AddLine("      ", fgcolor=prefix, bgcolor=bg)
        self.AddLine(ret1 + ":", fgcolor=prefix, bgcolor=bg)
        self.AddLine("  Potential Risk: %" + str(risk), fgcolor=prefix, bgcolor=bg)
        self.AddLine("      " + a, fgcolor=prefix, bgcolor=bg)
        mal_found += 1

def rand_color():
    #bg = ["0x"+''.join([random.choice('0123456789ABCDEF') for j in range(6)]) for i in range(1)]
    #bg = ["0x"+''.join([random.choice('ABCF') for j in range(6)]) for i in range(1)]
    bg = ["0x"+''.join([random.choice('CFA') for j in range(6)]) for i in range(1)]
    bg = ''.join(bg)
    bg = literal_eval(bg)
    #print(bg)
    return bg

def api_check(api):
    global apis
    global print_to
    global risk
    
    risk = ""
    print_to.clear()
    
    for var1 in apis:
        for var2 in api:
            if var1 == var2:
                print_to.append(var2)
    
    aplen = len(api) - 1
    prlen = len(print_to)
    
    
    if aplen != 0 and prlen != 0:
        cr1 = int(100 / aplen)
        cr2 = cr1 * aplen
        cr3 = str(cr1 * prlen)
    
        risk = cr3
      
    if prlen > 0:
        return api[0]
    else:
        return 0

def print_title(self,prefix,bg):
    mstr1 = "   _____ _        _   _        ____       _                 _                                   _           _     "
    mstr2 = "  / ____| |      | | (_)      |  _ \     | |               (_)                /\               | |         (_)    "
    mstr3 = " | (___ | |_ __ _| |_ _  ___  | |_) | ___| |__   __ ___   ___  ___  _ __     /  \   _ __   __ _| |_   _ ___ _ ___ "
    mstr4 = "  \___ \| __/ _` | __| |/ __| |  _ < / _ \ '_ \ / _` \ \ / / |/ _ \| '__|   / /\ \ | '_ \ / _` | | | | / __| / __|"
    mstr5 = "  ____) | || (_| | |_| | (__  | |_) |  __/ | | | (_| |\ V /| | (_) | |     / ____ \| | | | (_| | | |_| \__ \ \__ \\"
    mstr6 = " |_____/ \__\__,_|\__|_|\___| |____/ \___|_| |_|\__,_| \_/ |_|\___/|_|    /_/    \_\_| |_|\__,_|_|\__, |___/_|___/"
    mstr7 = "                                                                                                   __/ |          "
    mstr8 = "                                                                                                  |___/           "
    mstr9 = ""
    
    self.AddLine("Static Behavior Analysis From Malicious APIs - Beta", fgcolor=prefix, bgcolor=bg)
    self.AddLine("Supports: C/C++", fgcolor=prefix, bgcolor=bg)
    self.AddLine(mstr1, fgcolor=prefix, bgcolor=bg)
    self.AddLine(mstr2, fgcolor=prefix, bgcolor=bg)               
    self.AddLine(mstr3, fgcolor=prefix, bgcolor=bg)                
    self.AddLine(mstr4, fgcolor=prefix, bgcolor=bg)   
    self.AddLine(mstr5, fgcolor=prefix, bgcolor=bg)
    self.AddLine(mstr6, fgcolor=prefix, bgcolor=bg)
    self.AddLine(mstr7, fgcolor=prefix, bgcolor=bg)
    self.AddLine(mstr8, fgcolor=prefix, bgcolor=bg)
    self.AddLine(mstr9, fgcolor=prefix, bgcolor=bg)


def get_imports():
    global fixed_imports
    global apis
    current = ""
 
    def callback(ea, name, ord):
        apis.append(name)
        return True
 
    nimps = idaapi.get_import_module_qty()
    for i in range(0, nimps):
        current = idaapi.get_import_module_name(i)
        idaapi.enum_import_names(i, callback)
    
get_imports()


class mycv_t(ida_kernwin.simplecustviewer_t):
    def Create(self, sn=None, use_colors=True):
        title = "Static Behavior Analysis"

        self.use_colors = use_colors

        if not ida_kernwin.simplecustviewer_t.Create(self, title):
            return False

        prefix = ida_lines.COLOR_DNAME   
        bg = 0xFFFFFF    
        print_title(self,prefix,bg)
            
        for i in range(0,api_len):
            print_api(self,prefix,bg)          
        
        if mal_found == 0:
            self.AddLine("Malicious APIs not found!. Executable may be using API Hashing technique or etc.", fgcolor=prefix, bgcolor=bg)

        return True

    def OnClick(self, shift):
        return True

    def OnDblClick(self, shift):
        return True

    def OnCursorPosChanged(self):
        return True
        
    def OnClose(self):
        return True
        
    def OnKeydown(self, vkey, shift):
        return True

    def OnHint(self, lineno):
        return self

    def Show(self, *args):
        ok = ida_kernwin.simplecustviewer_t.Show(self, *args) 
        return ok

try:
    mycv
    #print("Already created!")
    mycv.Close()
    del mycv
except:
    pass

def show_win():
    x = mycv_t()
    if not x.Create():
        #print("Failed to create!")
        return None
    x.Show()
    tcc = x.GetWidget()
    return x

mycv = show_win()
if not mycv:
    del mycv

