from tksheet import Sheet
import tkinter as tk
import tkinter.ttk as ttk
from tkinter import filedialog
from ttkthemes import ThemedTk
import tkinter.font as tkFont
import subprocess
import threading
import pandas as pd


class ViewLogs:
    def __init__(self, btm_right, outpath):
        self.btm_right = btm_right
        self.outpath = outpath
        for widgets in self.btm_right.winfo_children():
            widgets.destroy()
        self.btm_right.grid_columnconfigure(0, weight=0)
        self.btm_right.grid_rowconfigure(0, weight=0)
        self.frame = ttk.Frame(self.btm_right)

        self.label1 = ttk.Label(self.btm_right, text="Network and Host Exploit Mitigation")
        font = (tkFont.Font(self.label1['font'])).actual()
        font['weight'] = 'bold'
        self.label1.config(font=font)
        self.label2 = ttk.Label(self.btm_right, text="Protects against Web, network trhreats, and zero-day exploits")
        self.menua = ttk.Menubutton(self.btm_right, text="View Logs")
        self.menua.menu = tk.Menu(self.menua, tearoff=0)
        self.menua["menu"] = self.menua.menu
        self.menua.menu.add_command(label="Traffic Log", command=lambda: readcsv(self.btm_right, self.outpath + '\Symantec_Network_and_Host_Exploit_Mitigation_Traffic_Log.csv', 0))
        self.menua.menu.add_command(label="Packet Log", command=lambda: readcsv(self.btm_right, self.outpath + '\Symantec_Network_and_Host_Exploit_Mitigation_Packet_Log.csv', 0))

        self.label3 = ttk.Label(self.btm_right, text="Client Management")
        font = (tkFont.Font(self.label3['font'])).actual()
        font['weight'] = 'bold'
        self.label3.config(font=font)
        self.label4 = ttk.Label(self.btm_right, text="Provides functionality to manage this client")
        self.menub = ttk.Menubutton(self.btm_right, text="View Logs")
        self.menub.menu = tk.Menu(self.menub, tearoff=0)
        self.menub["menu"] = self.menub.menu
        self.menub.menu.add_command(label="Control Log", command=lambda: readcsv(self.btm_right, self.outpath + '\Symantec_Client_Management_Control_Log.csv', 0))
        self.menub.menu.add_command(label="Security Log", command=lambda: readcsv(self.btm_right, self.outpath + '\Symantec_Client_Management_Security_Log.csv', 0))
        self.menub.menu.add_command(label="System Log", command=lambda: readcsv(self.btm_right, self.outpath + '\Symantec_Client_Management_System_Log.csv', 0))
        self.menub.menu.add_command(label="Tamper Protect Log", command=lambda: readcsv(self.btm_right, self.outpath + '\Symantec_Client_Management_Tamper_Protect_Log.csv', 0))

        self.label1.grid(row=0, column=0, sticky="ew")
        self.menua.grid(row=0, column=1, sticky="ew")
        self.label2.grid(row=1, column=0, sticky="ew")
        self.label3.grid(row=2, column=0, sticky="ew")
        self.menub.grid(row=2, column=1, sticky="ew")
        self.label4.grid(row=3, column=0, sticky="ew")


class Status:
    def __init__(self, btm_right):
        self.btm_right = btm_right
        for widgets in self.btm_right.winfo_children():
            widgets.destroy()
        self.btm_right.grid_columnconfigure(0, weight=0)
        self.btm_right.grid_rowconfigure(0, weight=0)
        self.frame = ttk.Frame(self.btm_right)

        self.btn = tk.Button(self.btm_right, text="Test1", command=lambda: readcsv(self.btm_right, 'Symantec_Timeline.csv', 0))
        self.btn2 = tk.Button(self.btm_right, text="Test2", command=lambda: readcsv(self.btm_right, 'settings.csv', 0))
        self.btn3 = tk.Button(self.btm_right, text="Test3", command=lambda: readcsv(self.btm_right, 'settings.csv', 0))

        self.btn.grid(row=0, column=0, sticky="ew")
        self.btn2.grid(row=1, column=0, sticky="ew")
        self.btn3.grid(row=2, column=0, sticky="ew")


class readcsv:
    def __init__(self, master, log, tl):
        if tl == 0:
            self.master = tk.Toplevel(master)
        else:
            self.master = master
            for widgets in self.master.winfo_children():
                widgets.destroy()
        self.log = log
        self.master.grid_columnconfigure(0, weight=1)
        self.master.grid_rowconfigure(0, weight=1)
        self.frame = ttk.Frame(self.master)
        self.frame.grid_columnconfigure(0, weight=1)
        self.frame.grid_rowconfigure(0, weight=1)

        self.sheet = Sheet(self.frame,
                           data=pd.read_csv(log, keep_default_na=False, dtype=str, header=0).values.tolist(),
                           headers=pd.read_csv(log, keep_default_na=False, dtype=str, header=0).columns.tolist(),
                           header_font=("Calibri", 11, "bold"))

        self.sheet.enable_bindings()
        self.frame.grid(row=0, column=0, sticky="nswe")
        self.sheet.grid(row=0, column=0, sticky="nswe")
        self.sheet.enable_bindings(("single_select",
                                    "drag_select",
                                    "select_all",
                                    "column_select",
                                    "row_select",
                                    "column_width_resize",
                                    "double_click_column_resize",
                                    "arrowkeys",
                                    "row_height_resize",
                                    "double_click_row_resize",
                                    "right_click_popup_menu",
                                    "rc_select"
                                    ))
        self.sheet.disable_bindings(("delete",
                                     "cut",
                                     "edit_cell",
                                     "rc_insert_column",
                                     "rc_delete_column",
                                     "rc_insert_row",
                                     "rc_delete_row"))
        self.frame.grid(row=0, column=0, sticky="nswe")
        self.sheet.grid(row=0, column=0, sticky="nswe")


class Post_process:
    def __init__(self, root, outpath):
        self.root = root
        self.outpath = outpath
        for widgets in self.root.winfo_children():
            if str(widgets) == ".!menu" or str(widgets) == ".!sizegrip":
                pass
            else:
                widgets.destroy()
        self.top_frame = ttk.Frame(self.root, width=450, height=50, padding=3)
        self.btm_frame = ttk.Frame(self.root)
        self.top_frame.grid(row=0, sticky="ew")
        self.btm_frame.grid(row=1, rowspan=1, sticky="nsew")
        # create the bottom frame widgets
        self.btm_frame.grid_rowconfigure(0, weight=1)
        self.btm_frame.grid_columnconfigure(1, weight=1)

        self.btn = ttk.Button(self.top_frame, text="Help", command=lambda: ViewLogs(self.btm_right))

        self.btm_left = ttk.Frame(self.btm_frame, width=100, height=300, padding=10)
        self.btm_right = ttk.Frame(self.btm_frame, width=350, height=300, padding=10)

        self.btm_left.grid(row=0, column=0, sticky="ns")
        self.btm_right.grid(row=0, column=1, sticky="nsew")

        self.btn1 = ttk.Button(self.btm_left, text="Status", command=lambda: Status(self.btm_right))
        self.btn2 = ttk.Button(self.btm_left, text="Scan for Threats", command=lambda: None)
        self.btn3 = ttk.Button(self.btm_left, text="View Settings", command=lambda: readcsv(self.btm_right, self.outpath + '\settings.csv', 1))
        self.btn4 = ttk.Button(self.btm_left, text="View Quarantine", command=lambda: readcsv(self.btm_right, self.outpath + '\quarantine.csv', 1))
        self.btn5 = ttk.Button(self.btm_left, text="View Logs", command=lambda: ViewLogs(self.btm_right, self.outpath))

        self.btn.grid(row=0, column=2, sticky="e")
        self.btn1.grid(row=0, column=0, sticky="ew", pady=1)
        self.btn2.grid(row=1, column=0, sticky="ew", pady=1)
        self.btn3.grid(row=2, column=0, sticky="ew", pady=1)
        self.btn4.grid(row=3, column=0, sticky="ew", pady=1)
        self.btn5.grid(row=4, column=0, sticky="ew", pady=1)


class Pre_process:
    def __init__(self, root):
        self.root = root

        # create all of the main containers
        self.top_frame = ttk.Frame(self.root, padding=10)
        self.center_frame = ttk.Frame(self.root, padding=10)
        self.left_frame = ttk.Frame(self.center_frame)
        self.right_frame = ttk.Frame(self.center_frame)
        self.bottom_frame = ttk.LabelFrame(self.root, text="Current command line", padding=10)
        self.top_frame.grid(row=0, column=0, sticky="ew")
        self.center_frame.grid(row=1, column=0, sticky="nsew")
        self.left_frame.grid(row=0, column=0, sticky="ns")
        self.right_frame.grid(row=0, column=1, sticky="nsew")
        self.bottom_frame.grid(row=2, column=0, sticky="ew")

        self.center_frame.grid_rowconfigure(0, weight=1)
        self.center_frame.grid_columnconfigure(1, weight=1)
        self.right_frame.grid_rowconfigure(0, weight=1)
        self.right_frame.grid_columnconfigure(0, weight=1)

        self.v = tk.StringVar(value="-d")
        self.kapemode = tk.StringVar(value="")
        self.output = tk.StringVar(value="")
        self.path = tk.StringVar(value="c:/")
        self.path.trace_add('write', self.check_expression)
        self.outpath = tk.StringVar(value="")
        self.outpath.trace_add('write', self.check_expression)
        self.append = tk.StringVar(value="")
        self.tvalue = tk.IntVar()
        self.tz = tk.StringVar(value=' ')
        self.tzdata = tk.StringVar()
        self.tzdata.trace_add('write', self.check_expression)
        self.logging = tk.StringVar()
        self.verbose = tk.StringVar()
        self.e = tk.StringVar()
        self.qd = tk.StringVar()
        self.hd = tk.StringVar()
        self.hf = tk.StringVar()
        self.eb = tk.StringVar()
        self.cmd = tk.StringVar()

        self.lbl1 = ttk.Label(self.top_frame,
                              text="Directory/Folder Input:")

        self.rbtn1 = ttk.Radiobutton(self.top_frame,
                                     text="Directory",
                                     variable=self.v,
                                     value="-d",
                                     command=self.check_expression)

        self.rbtn2 = ttk.Radiobutton(self.top_frame,
                                     text="File",
                                     variable=self.v,
                                     value="-f",
                                     command=self.check_expression)

        self.ent1 = ttk.Entry(self.top_frame,
                              width=25,
                              textvariable=self.path)

        self.btn1 = ttk.Button(self.top_frame,
                               text='...',
                               width=3,
                               command=lambda: self.callback())

        self.cbx1 = ttk.Checkbutton(self.top_frame,
                                    text="Kape Mode",
                                    offvalue="",
                                    onvalue="-k",
                                    var=self.kapemode,
                                    command=self.check_expression)

        self.lbl2 = ttk.Label(self.top_frame,
                              text="Output:")

        self.cbx2 = ttk.Checkbutton(self.top_frame,
                                    text="Output Directory",
                                    offvalue="",
                                    onvalue="-o",
                                    var=self.output,
                                    command=lambda:[self.check_expression(), self.outcheck()])

        self.ent2 = ttk.Entry(self.top_frame,
                              width=25,
                              textvariable=self.outpath,
                              state='disabled')

        self.btn2 = ttk.Button(self.top_frame,
                               text='...',
                               width=3,
                               state='disabled',
                               command=lambda: self.callback2())

        self.cbx3 = ttk.Checkbutton(self.top_frame,
                                    text="Append",
                                    offvalue="",
                                    onvalue="-a",
                                    var=self.append,
                                    command=self.check_expression)

        self.lbl3 = ttk.Label(self.left_frame,
                              text="Time Zone")

        self.cbx4 = ttk.Checkbutton(self.left_frame,
                                    offvalue=0,
                                    onvalue=1,
                                    var=self.tvalue,
                                    command=self.tcheck)

        self.rbtn3 = ttk.Radiobutton(self.left_frame,
                                     variable=self.tz,
                                     value="-tz",
                                     state='disabled',
                                     command=self.check_expression)

        self.ent3 = ttk.Entry(self.left_frame,
                              width=25,
                              state='disabled',
                              textvariable=self.tzdata)

        self.rbtn4 = ttk.Radiobutton(self.left_frame,
                                     text="registrationInfo.xml",
                                     variable=self.tz,
                                     value="-r",
                                     state='disabled',
                                     command=self.check_expression)

        self.lbl4 = ttk.Label(self.left_frame,
                              text="Logging")

        self.cbx5 = ttk.Checkbutton(self.left_frame,
                                    text="Enabled",
                                    offvalue="",
                                    onvalue="-l",
                                    var=self.logging,
                                    command=self.check_expression)

        self.cbx6 = ttk.Checkbutton(self.left_frame,
                                    text="Verbose",
                                    offvalue="",
                                    onvalue="-v",
                                    var=self.verbose,
                                    command=self.check_expression)

        self.lbl5 = ttk.Label(self.left_frame,
                              text="VBN Options")

        self.cbx7 = ttk.Checkbutton(self.left_frame,
                                    text="Extract",
                                    offvalue="",
                                    onvalue="-e",
                                    var=self.e,
                                    command=self.check_expression)

        self.cbx8 = ttk.Checkbutton(self.left_frame,
                                    text="Quarantine Dump",
                                    offvalue="",
                                    onvalue="-qd",
                                    var=self.qd,
                                    command=self.check_expression)

        self.cbx9 = ttk.Checkbutton(self.left_frame,
                                    text="Hex Dump",
                                    offvalue="",
                                    onvalue="-hd",
                                    var=self.hd,
                                    command=self.check_expression)

        self.cbx10 = ttk.Checkbutton(self.left_frame,
                                     text="Hash File",
                                     offvalue="",
                                     onvalue="-hf",
                                     var=self.hf,
                                     command=self.check_expression)

        self.lbl6 = ttk.Label(self.left_frame,
                              text="ccSubSDK",)

        self.cbx11 = ttk.Checkbutton(self.left_frame,
                                     text="Extract Blob",
                                     offvalue="",
                                     onvalue="-eb",
                                     var=self.eb,
                                     command=self.check_expression)

        self.scrollb = ttk.Scrollbar(self.right_frame)

        self.outputtext2 = tk.Text(self.right_frame,
                                   yscrollcommand=self.scrollb.set,
                                   state='disabled')

        self.scrollb.config(command=self.outputtext2.yview)

        self.outputtext = tk.Text(self.bottom_frame, height=2)
        self.check_expression()

        self.var = tk.IntVar()

        self.button = ttk.Button(self.bottom_frame,
                                 text="Click Me",
                                 width=8,
                                 command=lambda: Post_process(root, self.outpath.get()))

        self.button2 = ttk.Button(self.bottom_frame,
                                  text="run",
                                  width=3,
                                  command=lambda: threading.Thread(target=self.execute).start())

        self.sg = ttk.Sizegrip(self.root)

        # layout the widgets in the main frame
        self.lbl1.grid(row=0, column=0, columnspan=5, sticky="w")
        self.lbl2.grid(row=0, column=5, columnspan=4, sticky="w", padx=5)
        self.rbtn1.grid(row=1, column=0)
        self.rbtn2.grid(row=1, column=1, padx=5)
        self.ent1.grid(row=1, column=2, padx=5)
        self.btn1.grid(row=1, column=3, padx=5)
        self.cbx1.grid(row=1, column=4, padx=5)
        self.cbx2.grid(row=1, column=5, padx=5)
        self.ent2.grid(row=1, column=6, padx=5)
        self.btn2.grid(row=1, column=7, padx=5)
        self.cbx3.grid(row=1, column=8)
        self.lbl3.grid(row=0, column=0, sticky="w")
        self.cbx4.grid(row=0, column=1, sticky="w")
        self.rbtn3.grid(row=1, column=0, sticky="w")
        self.rbtn4.grid(row=1, column=1, sticky="w")
        self.ent3.grid(row=2, column=0, columnspan=2, sticky="w")
        self.lbl4.grid(row=3, column=0, sticky="w")
        self.cbx5.grid(row=4, column=0, sticky="w")
        self.cbx6.grid(row=4, column=1, sticky="w")
        self.lbl5.grid(row=5, column=0, sticky="w")
        self.cbx7.grid(row=6, column=0, sticky="w")
        self.cbx8.grid(row=6, column=1, sticky="w")
        self.cbx9.grid(row=7, column=0, sticky="w")
        self.cbx10.grid(row=7, column=1, sticky="w")
        self.lbl6.grid(row=8, column=0, sticky="w")
        self.cbx11.grid(row=9, column=0, sticky="w")
        self.outputtext2.grid(row=0, column=0, columnspan=6, rowspan=10, sticky="nsew")
        self.scrollb.grid(row=0, column=6, rowspan=10, sticky="nsew")
        self.outputtext.grid(row=0, column=0, sticky="nsew")
        self.button.grid(row=1, sticky="w")
        self.button2.grid(row=2, sticky="w")
        self.sg.grid(row=2, sticky='se')

    def check_expression(self, *args):
        # Your code that checks the expression
        self.outputtext.config(state=tk.NORMAL)
        varContent = self.v.get()  # get what's written in the inputentry entry widget
        pathContent = self.path.get()
        # Optional arguments
        opt = ''
        if len(self.output.get()) > 1:
            opt += f' {self.output.get()}'
        if len(self.outpath.get()) > 0:
            opt += f' "{self.outpath.get()}"'
        if len(self.kapemode.get()) > 1:
            opt += f' {self.kapemode.get()}'
        if len(self.append.get()) > 1:
            opt += f' {self.append.get()}'
        if len(self.logging.get()) > 1:
            opt += f' {self.logging.get()}'
        if len(self.verbose.get()) > 1:
            opt += f' {self.verbose.get()}'
        if len(self.e.get()) > 1:
            opt += f' {self.e.get()}'
        if len(self.qd.get()) > 1:
            opt += f' {self.qd.get()}'
        if len(self.hd.get()) > 1:
            opt += f' {self.hd.get()}'
        if len(self.hf.get()) > 1:
            opt += f' {self.hf.get()}'
        if len(self.eb.get()) > 1:
            opt += f' {self.eb.get()}'
        if len(self.tz.get()) > 1:
            opt += f' {self.tz.get()}'
        if len(self.tzdata.get()) > 0:
            opt += f' {self.tzdata.get()}'
        self.outputtext.delete(1.0, tk.END)  # clear the outputtext text widget
        self.outputtext.insert(tk.END, (f'{varContent} "{pathContent}"{opt}').replace('/', '\\'))
        self.outputtext.config(state=tk.DISABLED)
        self.cmd.set(f'{varContent} "{pathContent}"{opt}')

    def callback(self):
        if self.v.get() == "-d":
            _ = filedialog.askdirectory(initialdir='C:/', title='Select Directory')
        else:
            _ = filedialog.askopenfilename(initialdir='C:/', title='Select File')
        self.path.set(_)
        self.check_expression()

    def callback2(self):
        if self.output.get() == "-o":
            _ = filedialog.askdirectory(initialdir='C:/', title='Select Directory')
        else:
            _ = ''
        self.outpath.set(_)
        self.check_expression()

    def outcheck(self):
        if self.output.get() == "-o":
            self.ent2.configure(state='normal')
            self.btn2.configure(state='normal')
            self.outpath.set('.')
        else:
            self.ent2.configure(state='disable')
            self.btn2.configure(state='disable')
            self.outpath.set('')
        self.check_expression()

    def tcheck(self):
        if self.tvalue.get() == 1:
            self.rbtn3.configure(state='normal')
            self.rbtn4.configure(state='normal')
            self.ent3.configure(state='normal')
        else:
            self.rbtn3.configure(state='disable')
            self.rbtn4.configure(state='disable')
            self.ent3.configure(state='disable')
            self.tz.set(' ')
            self.tzdata.set(' ')
        self.check_expression()

    def execute(self):
        for widgets in self.top_frame.winfo_children():
            widgets.configure(state='disable')
        for widgets in self.left_frame.winfo_children():
            widgets.configure(state='disable')
        for widgets in self.bottom_frame.winfo_children():
            widgets.configure(state='disable')
        self.outputtext2.config(state=tk.NORMAL)
        self.outputtext2.delete('1.0', tk.END)
        cmdlist = "py.exe -3 -u SEPparser.py " + self.cmd.get()
        proc = subprocess.Popen(cmdlist, stdout=subprocess.PIPE)
        while True:
            line = proc.stdout.readline()
            print(line)
            if not line:
                break
            self.outputtext2.insert(tk.END, line)
            self.outputtext2.see(tk.END)
            self.outputtext2.update_idletasks()
        self.outputtext2.config(state=tk.DISABLED)
        for widgets in self.top_frame.winfo_children():
            widgets.configure(state='normal')
        for widgets in self.left_frame.winfo_children():
            widgets.configure(state='normal')
        for widgets in self.bottom_frame.winfo_children():
            widgets.configure(state='normal')

    def on_enter(self, e):
        e.widget['selectcolor'] = 'grey'

    def on_leave(self, e):
        e.widget['selectcolor'] = 'white'


def main():
    def menu_theme():
        print('yes')
        s = ttk.Style()
        bg = s.lookup('TFrame', 'background')
        fg = s.lookup('TFrame', 'foreground')
        print(bg, fg)
        menubar.config(background=bg)
        tool_menu.config(bg=bg)

    root = ThemedTk()
    root.title('SEPparser GUI')
    root.minsize(745, 400)

    # layout all of the main containers
    root.grid_rowconfigure(1, weight=1)
    root.grid_columnconfigure(0, weight=1)

    menubar = tk.Menu(root)
    root.config(menu=menubar)

    tool_menu = tk.Menu(menubar, tearoff=0)

    submenu = tk.Menu(tool_menu, tearoff=0)

    for theme_name in sorted(root.get_themes()):
        submenu.add_command(label=theme_name, command=lambda t = theme_name:root.set_theme(t))

    tool_menu.add_cascade(label="Skins", menu=submenu)
    menubar.add_cascade(label="Tools", menu=tool_menu)

    # create all of the main containers
    Pre_process(root)

    root.mainloop()


if __name__ == '__main__':
    main()
