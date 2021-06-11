import os
import re
import json
from tksheet import Sheet
import tkinter as tk
import tkinter.ttk as ttk
from tkinter import filedialog
from ttkthemes import ThemedTk
import tkinter.font as tkFont
import subprocess
import threading
import pandas as pd

if os.path.isfile('SEPgui.settings'):
    with open("SEPgui.settings", "r") as jsonfile:
        data = json.load(jsonfile)
        jsonfile.close()
else:
    data = json.loads('{"theme": "vista", "directory": "", "file": "", "output": ""}')


class ViewLogs:
    def __init__(self, btm_right, outpath):
        self.btm_right = btm_right
        self.outpath = outpath

        for widgets in self.btm_right.winfo_children():
            widgets.destroy()

        self.btm_right.grid_columnconfigure(0, weight=0)
        self.btm_right.grid_rowconfigure(0, weight=0)
        self.top = ttk.Frame(self.btm_right, relief='groove', padding=10)
        self.middle = ttk.Frame(self.btm_right, relief='groove', padding=10)
        self.bottom = ttk.Frame(self.btm_right, relief='groove', padding=10)

        self.top.grid_columnconfigure(0, weight=1)
        self.middle.grid_columnconfigure(0, weight=1)
        self.bottom.grid_columnconfigure(0, weight=1)

        self.top.grid(row=0, column=0, sticky="ew")
        self.middle.grid(row=1, column=0, sticky="ew")
        self.bottom.grid(row=2, column=0, sticky="ew")

        self.label1 = ttk.Label(self.top,
                                text="ccSubSDK Database")

        font = (tkFont.Font(self.label1['font'])).actual()
        font['weight'] = 'bold'
        self.label1.config(font=font)

        self.label2 = ttk.Label(self.top,
                                text="The detection information that clients send includes information about antivirus \ndetections, intrusion prevention, SONAR, and file reputation detections")

        self.menua = ttk.Menubutton(self.top,
                                    text="View Logs")

        self.menua.menu = tk.Menu(self.menua,
                                  tearoff=0)

        self.menua["menu"] = self.menua.menu

        for f in os.listdir(self.outpath + '\ccSubSDK'):
            if "csv" in f:
                self.menua.menu.add_command(label=f,
                                            command=lambda f=f: readcsv(self.btm_right, self.outpath + '\ccSubSDK\\' + f, 0))

        self.label3 = ttk.Label(self.middle,
                                text="Network and Host Exploit Mitigation")

        font = (tkFont.Font(self.label3['font'])).actual()
        font['weight'] = 'bold'
        self.label3.config(font=font)

        self.label4 = ttk.Label(self.middle,
                                text="Protects against Web, network trhreats, and zero-day exploits")

        self.menub = ttk.Menubutton(self.middle,
                                    text="View Logs")

        self.menub.menu = tk.Menu(self.menub,
                                  tearoff=0)

        self.menub["menu"] = self.menub.menu

        self.menub.menu.add_command(label="Traffic Log",
                                    command=lambda: readcsv(self.btm_right, self.outpath + '\Symantec_Network_and_Host_Exploit_Mitigation_Traffic_Log.csv', 0))

        self.menub.menu.add_command(label="Packet Log",
                                    command=lambda: readcsv(self.btm_right, self.outpath + '\Symantec_Network_and_Host_Exploit_Mitigation_Packet_Log.csv', 0))

        self.menub.menu.add_command(label="View Packets",
                                    command=lambda: None)

        self.label5 = ttk.Label(self.bottom,
                                text="Client Management")

        font = (tkFont.Font(self.label5['font'])).actual()
        font['weight'] = 'bold'
        self.label5.config(font=font)

        self.label6 = ttk.Label(self.bottom,
                                text="Provides functionality to manage this client")

        self.menuc = ttk.Menubutton(self.bottom,
                                    text="View Logs")

        self.menuc.menu = tk.Menu(self.menuc,
                                  tearoff=0)

        self.menuc["menu"] = self.menuc.menu

        self.menuc.menu.add_command(label="Control Log",
                                    command=lambda: readcsv(self.btm_right, self.outpath + '\Symantec_Client_Management_Control_Log.csv', 0))

        self.menuc.menu.add_command(label="Security Log",
                                    command=lambda: readcsv(self.btm_right, self.outpath + '\Symantec_Client_Management_Security_Log.csv', 0))

        self.menuc.menu.add_command(label="System Log",
                                    command=lambda: readcsv(self.btm_right, self.outpath + '\Symantec_Client_Management_System_Log.csv', 0))

        self.menuc.menu.add_command(label="Tamper Protection Log",
                                    command=lambda: readcsv(self.btm_right, self.outpath + '\Symantec_Client_Management_Tamper_Protect_Log.csv', 0))

        self.label1.grid(row=0, column=0, sticky="ew")
        self.menua.grid(row=0, column=1, sticky="e", padx=(10, 0))
        self.label2.grid(row=1, column=0, sticky="ew")
        self.label3.grid(row=0, column=0, sticky="ew")
        self.menub.grid(row=0, column=1, sticky="e", padx=(10, 0))
        self.label4.grid(row=1, column=0, sticky="ew")
        self.label5.grid(row=0, column=0, sticky="ew")
        self.menuc.grid(row=0, column=1, sticky="e", padx=(10, 0))
        self.label6.grid(row=1, column=0, sticky="ew")


class readcsv:
    def __init__(self, master, log, tl):
        if tl == 0:
            self.master = tk.Toplevel(master)
            self.outer_frame = ttk.Frame(self.master)
            self.outer_frame.grid_columnconfigure(0, weight=1)
            self.outer_frame.grid_rowconfigure(0, weight=1)
            self.outer_frame.grid(row=0, column=0, sticky="nswe")
            self.frame = ttk.Frame(self.outer_frame, relief='groove', padding=5)
            self.separatorl = ttk.Separator(self.frame, orient='vertical')
            self.separatorr = ttk.Separator(self.frame, orient='vertical')
            self.separatort = ttk.Separator(self.frame, orient='horizontal')
            self.separatorb = ttk.Separator(self.frame, orient='horizontal')
            self.frame.grid_columnconfigure(1, weight=1)
            self.frame.grid_rowconfigure(1, weight=1)
        else:
            self.master = master
            for widgets in self.master.winfo_children():
                widgets.destroy()
            self.frame = ttk.Frame(self.master, relief='groove', padding=1)
            self.frame.grid_columnconfigure(0, weight=1)
            self.frame.grid_rowconfigure(0, weight=1)

        self.log = log
        self.master.grid_columnconfigure(0, weight=1)
        self.master.grid_rowconfigure(0, weight=1)
        self.sg = ttk.Sizegrip(self.frame)

        self.sheet = Sheet(self.frame,
                           data=pd.read_csv(log,
                                            keep_default_na=False,
                                            dtype=str,
                                            header=0,
                                            encoding='latin1').values.tolist(),
                           headers=pd.read_csv(log,
                                               keep_default_na=False,
                                               dtype=str,
                                               header=0,
                                               encoding='latin1').columns.tolist(),
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

        self.sheet.popup_menu_add_command("Hide This Column", self.hide_column, table_menu=False, index_menu=False, header_menu=True)
        self.sheet.popup_menu_add_command("UnHide This Column", self.unhide_column, table_menu=False, index_menu=False, header_menu=True)
        self.sheet.bind("<Double-Button-1>", self.view_cell)

        self.frame.grid(row=0, column=0, sticky="nswe")
        self.sheet.grid(row=0, column=0, sticky="nswe")

        if tl == 0:
            self.separatort.grid(row=0, column=0, columnspan=3, padx=(7, 0), pady=(7, 0), sticky="ew")
            self.separatorl.grid(row=1, column=0, sticky="ns", padx=(7, 0))
            self.sheet.grid(row=1, column=1, sticky="nswe")
            self.separatorr.grid(row=1, column=2, sticky="ns")
            self.separatorb.grid(row=2, column=0, columnspan=3, padx=(7, 0), sticky="ew")
            self.frame.grid(padx=5, pady=5)
            self.sg.grid(row=3, column=3, sticky='se')

    def hide_column(self, event=None):
        currently_displayed = self.sheet.display_columns()
        exclude = set(currently_displayed[c] for c in self.sheet.get_selected_columns())
        indexes = [c for c in currently_displayed if c not in exclude]
        self.sheet.display_columns(indexes=indexes, enable=True, refresh=True)

    def unhide_column(self, event=None):
        show_columns = [*range(0, self.sheet.total_columns(), 1)]
        self.sheet.display_columns(indexes=show_columns, enable=True, refresh=True)

    def view_cell(self, event=None):
        region = self.sheet.identify_region(event)
        if region == "table":
            r, c = self.sheet.get_currently_selected()
            text = self.sheet.get_cell_data(r, c)
            cell_contents(self.master, text)


class cell_contents:
    def __init__(self, root, text):
        self.root = tk.Toplevel(root)
        self.text = text
        self.root.title('Cell contents')
        s = ttk.Scrollbar(self.root)
        t = tk.Text(self.root, yscrollcommand=s.set)
        s.config(command=t.yview)
        t.grid(row=0, column=0, sticky="nsew")
        s.grid(row=0, column=1, sticky="nsew")
        t.insert(tk.END, self.text)
        t.config(state=tk.DISABLED)


class Post_process:
    def __init__(self, root, outpath):
        self.root = root
        self.outpath = outpath

        for widgets in self.root.winfo_children():
            if str(widgets) == ".!menu":
                pass
            else:
                widgets.destroy()

        self.outer_frame = ttk.Frame(self.root)
        self.main_frame = ttk.Frame(self.outer_frame, relief='groove', padding=5)
        self.top_frame = ttk.Frame(self.main_frame)
        self.btm_frame = ttk.Frame(self.main_frame)
        self.outer_frame.grid(row=0, column=0, sticky="nsew")
        self.main_frame.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)
        self.top_frame.grid(row=0, sticky="ew")
        self.btm_frame.grid(row=1, sticky="nsew")

        self.outer_frame.grid_rowconfigure(0, weight=1)
        self.outer_frame.grid_columnconfigure(0, weight=1)
        self.main_frame.grid_rowconfigure(0, weight=0)
        self.main_frame.grid_rowconfigure(1, weight=1)
        self.main_frame.grid_columnconfigure(0, weight=1)
        self.top_frame.grid_rowconfigure(0, minsize=40, weight=0)
        self.top_frame.grid_columnconfigure(1, weight=1)
        self.btm_frame.grid_rowconfigure(0, weight=1)
        self.btm_frame.grid_columnconfigure(1, weight=1)

        self.btm_left = ttk.Frame(self.btm_frame)
        self.btm_right = ttk.Frame(self.btm_frame, padding=10)

        self.btm_left.grid(row=0, column=0, sticky="ns")
        self.btm_right.grid(row=0, column=1, sticky="nsew", pady=(0, 10))

        self.btm_left.grid_rowconfigure(0, weight=0)
        self.btm_left.grid_rowconfigure(1, weight=0)
        self.btm_left.grid_rowconfigure(2, weight=0)
        self.btm_left.grid_rowconfigure(3, weight=0)
        self.btm_left.grid_rowconfigure(4, weight=1)
        self.btm_left.grid_columnconfigure(1, weight=1)

        self.label = ttk.Label(self.top_frame, text="")
        font = (tkFont.Font(self.label['font'])).actual()
        font['weight'] = 'bold'
        self.label.config(font=font)

        self.separatorx = ttk.Separator(self.btm_left, orient='vertical')
        self.separatory = ttk.Separator(self.top_frame, orient='horizontal')

        self.btn1 = ttk.Button(self.btm_left,
                               text="Timeline",
                               command=lambda: [readcsv(self.btm_right, self.outpath + '\Symantec_Timeline.csv', 1), self.onclick(self.btn1['text'])])

        self.btn2 = ttk.Button(self.btm_left,
                               text="View Settings",
                               command=lambda: [readcsv(self.btm_right, self.outpath + '\settings.csv', 1), self.onclick(self.btn2['text'])])

        self.btn3 = ttk.Button(self.btm_left,
                               text="View Quarantine",
                               command=lambda: [readcsv(self.btm_right, self.outpath + '\quarantine.csv', 1), self.onclick(self.btn3['text'])])

        self.btn4 = ttk.Button(self.btm_left,
                               text="View Logs",
                               command=lambda: [ViewLogs(self.btm_right, self.outpath), self.onclick(self.btn4['text'])])

        self.sg = ttk.Sizegrip(self.main_frame)

        self.label.grid(row=0, column=1, sticky="sw", padx=5)
        self.separatory.grid(row=1, column=1, sticky="ew")
        self.btn1.grid(row=0, column=0, sticky="ew", padx=(0, 5), pady=(10, 1))
        self.btn2.grid(row=1, column=0, sticky="ew", padx=(0, 5), pady=1)
        self.btn3.grid(row=2, column=0, sticky="ew", padx=(0, 5), pady=1)
        self.btn4.grid(row=3, column=0, sticky="ew", padx=(0, 5), pady=1)
        self.separatorx.grid(row=0, column=1, rowspan=5, sticky="ns")
        self.sg.grid(row=1, sticky='se')

        self.btn4.bind('<<ThemeChanged>>', self.row_width)
        self.row_width()

    def row_width(self, *args):
        self.btm_frame.update()
        x = self.btm_left.bbox(0, 0)[2]
        self.top_frame.grid_columnconfigure(0, minsize=x, weight=0)

    def onclick(self, t):
        self.label.config(text=t)


class Pre_process:
    def __init__(self, root):
        self.root = root

        self.outer_frame = ttk.Frame(self.root)
        self.main_frame = ttk.Frame(self.outer_frame, relief='groove', padding=5)
        self.top_frame = ttk.Frame(self.main_frame)
        self.top_inner = ttk.Frame(self.top_frame)
        self.tleft_frame = ttk.LabelFrame(self.top_inner, text="Directory/Folder Input", padding=5)
        self.tright_frame = ttk.LabelFrame(self.top_inner, text="Output Options", padding=5)
        self.center_frame = ttk.Frame(self.main_frame, padding=10)
        self.cleft_frame = ttk.LabelFrame(self.center_frame, text="Other Options", padding=5)
        self.cright_frame = ttk.LabelFrame(self.center_frame, text="SEPparser Output", padding=5)
        self.bottom_frame = ttk.Frame(self.main_frame)
        self.inner_frame = ttk.LabelFrame(self.bottom_frame, text="Current command line")
        self.outer_frame.grid(row=0, column=0, sticky="nsew")
        self.main_frame.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)
        self.outer_frame.grid_rowconfigure(0, weight=1)
        self.outer_frame.grid_columnconfigure(0, weight=1)
        self.main_frame.grid_rowconfigure(0, weight=1)
        self.main_frame.grid_columnconfigure(0, weight=1)

        self.top_frame.grid(row=0, column=0, sticky="ew")
        self.top_inner.grid(row=0, column=0, sticky="ew", padx=15, pady=(15, 0))
        self.tleft_frame.grid(row=0, column=0, sticky="ew")
        self.tright_frame.grid(row=0, column=1, sticky="ew", padx=10)
        self.center_frame.grid(row=1, column=0, sticky="nsew")
        self.cleft_frame.grid(row=0, column=0, sticky="ns", padx=5)
        self.cright_frame.grid(row=0, column=1, sticky="nsew", padx=5)
        self.bottom_frame.grid(row=2, column=0, sticky="ew")
        self.inner_frame.grid(row=0, column=0, sticky="ew", padx=15, pady=(0, 15))

        self.center_frame.grid_rowconfigure(0, weight=1)
        self.center_frame.grid_columnconfigure(1, weight=1)
        self.cright_frame.grid_rowconfigure(0, weight=1)
        self.cright_frame.grid_columnconfigure(0, weight=1)
        self.bottom_frame.grid_rowconfigure(0, weight=1)
        self.bottom_frame.grid_columnconfigure(0, weight=1)
        self.inner_frame.grid_rowconfigure(0, weight=1)
        self.inner_frame.grid_columnconfigure(0, weight=1)

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

        self.rbtn1 = ttk.Radiobutton(self.tleft_frame,
                                     text="Directory",
                                     variable=self.v,
                                     value="-d",
                                     command=self.check_expression)

        self.rbtn2 = ttk.Radiobutton(self.tleft_frame,
                                     text="File",
                                     variable=self.v,
                                     value="-f",
                                     command=self.check_expression)

        self.ent1 = ttk.Combobox(self.tleft_frame,
                                 width=38,
                                 textvariable=self.path)

#        self.ent1['values'] = sorted(data['directory'].split('|'))

        self.btn1 = ttk.Button(self.tleft_frame,
                               text='...',
                               width=3,
                               command=lambda: self.callback())

        self.cbx1 = ttk.Checkbutton(self.tleft_frame,
                                    text="Kape Mode",
                                    offvalue="",
                                    onvalue="-k",
                                    var=self.kapemode,
                                    command=self.check_expression)

        self.cbx2 = ttk.Checkbutton(self.tright_frame,
                                    text="Output Directory",
                                    offvalue="",
                                    onvalue="-o",
                                    var=self.output,
                                    command=lambda: [self.check_expression(),
                                                     self.outcheck()])

        self.ent2 = ttk.Combobox(self.tright_frame,
                                 width=38,
                                 textvariable=self.outpath,
                                 state='disabled')

        self.ent2['values'] = sorted(data['output'].split('|'))

        self.btn2 = ttk.Button(self.tright_frame,
                               text='...',
                               width=3,
                               state='disabled',
                               command=lambda: self.callback2())

        self.cbx3 = ttk.Checkbutton(self.tright_frame,
                                    text="Append",
                                    offvalue="",
                                    onvalue="-a",
                                    var=self.append,
                                    command=self.check_expression)

        self.lbl1 = ttk.Label(self.cleft_frame,
                              text="Time Zone",
                              relief='groove',
                              padding=3)

        self.cbx4 = ttk.Checkbutton(self.cleft_frame,
                                    offvalue=0,
                                    onvalue=1,
                                    var=self.tvalue,
                                    takefocus=False,
                                    command=self.tcheck)

        self.rbtn3 = ttk.Radiobutton(self.cleft_frame,
                                     text="Offset",
                                     variable=self.tz,
                                     value="-tz",
                                     state='disabled',
                                     command=self.check_expression)

        self.ent3 = ttk.Entry(self.cleft_frame,
                              width=25,
                              state='disabled',
                              textvariable=self.tzdata)

        self.btn = ttk.Button(self.cleft_frame,
                              text='...',
                              width=3,
                              state='disabled',
                              command=lambda: self.callback3())

        self.rbtn4 = ttk.Radiobutton(self.cleft_frame,
                                     text="registrationInfo.xml",
                                     variable=self.tz,
                                     value="-r",
                                     state='disabled',
                                     command=self.check_expression)

        self.lbl2 = ttk.Label(self.cleft_frame,
                              text=" Logging",
                              relief='groove',
                              padding=3)

        self.cbx5 = ttk.Checkbutton(self.cleft_frame,
                                    text="Enabled",
                                    offvalue="",
                                    onvalue="-l",
                                    var=self.logging,
                                    command=self.check_expression)

        self.cbx6 = ttk.Checkbutton(self.cleft_frame,
                                    text="Verbose",
                                    offvalue="",
                                    onvalue="-v",
                                    var=self.verbose,
                                    command=self.check_expression)

        self.lbl3 = ttk.Label(self.cleft_frame,
                              text=" VBN Options",
                              relief='groove',
                              padding=3)

        self.cbx7 = ttk.Checkbutton(self.cleft_frame,
                                    text="Extract",
                                    offvalue="",
                                    onvalue="-e",
                                    var=self.e,
                                    command=self.check_expression)

        self.cbx8 = ttk.Checkbutton(self.cleft_frame,
                                    text="Quarantine Dump",
                                    offvalue="",
                                    onvalue="-qd",
                                    var=self.qd,
                                    command=self.check_expression)

        self.cbx9 = ttk.Checkbutton(self.cleft_frame,
                                    text="Hex Dump",
                                    offvalue="",
                                    onvalue="-hd",
                                    state='disabled',
                                    var=self.hd,
                                    command=self.check_expression)

        self.cbx10 = ttk.Checkbutton(self.cleft_frame,
                                     text="Hash File",
                                     offvalue="",
                                     onvalue="-hf",
                                     var=self.hf,
                                     command=self.check_expression)

        self.lbl4 = ttk.Label(self.cleft_frame,
                              text=" ccSubSDK",
                              relief='groove',
                              padding=3)

        self.cbx11 = ttk.Checkbutton(self.cleft_frame,
                                     text="Extract Blob",
                                     offvalue="",
                                     onvalue="-eb",
                                     var=self.eb,
                                     command=self.check_expression)

        self.scrollb = ttk.Scrollbar(self.cright_frame)

        self.outputtext2 = tk.Text(self.cright_frame,
                                   bg='black',
                                   fg='light grey',
                                   yscrollcommand=self.scrollb.set,
                                   font=('Consolas', 12, 'normal'),
                                   state='disabled')

        self.outputtext2.tag_configure(b'\x1b[1;31m', foreground="red")
        self.outputtext2.tag_configure(b'\x1b[1;32m', foreground="green")
        self.outputtext2.tag_configure(b'\x1b[1;33m', foreground="yellow")
        self.outputtext2.tag_configure(b'\x1b[1;93m', foreground="yellow",
                                       font=('Consolas', 12, 'bold'))
        self.outputtext2.tag_configure(b'\x1b[1;92m', foreground="green",
                                       font=('Consolas', 12, 'bold'))
        self.outputtext2.tag_configure(b'\x1b[1;35m', foreground="purple")
        self.outputtext2.tag_configure(b'\x1b[1;36m', foreground="cyan")

        self.scrollb.config(command=self.outputtext2.yview)

        self.scrollb1 = ttk.Scrollbar(self.inner_frame)

        self.outputtext = tk.Text(self.inner_frame,
                                  height=2,
                                  yscrollcommand=self.scrollb1.set)

        self.scrollb1.config(command=self.outputtext.yview)

        self.check_expression()

        self.var = tk.IntVar()

        self.button = ttk.Button(self.top_inner,
                                 text="View Reports",
                                 width=12,
#                                 state='disabled',
                                 command=lambda: Post_process(root,
                                                              self.outpath.get()))

        self.button2 = ttk.Button(self.inner_frame,
                                  text="Execute",
                                  width=7,
                                  command=lambda: [threading.Thread(target=self.execute).start(), self.updtent2(), self.updtent1()])

        self.button3 = ttk.Button(self.inner_frame,
                                  text="Copy Command",
                                  width=15,
                                  command=lambda: self.copy_command())

        self.sg = ttk.Sizegrip(self.main_frame)

        self.rbtn1.grid(row=0, column=0)
        self.rbtn2.grid(row=0, column=1, padx=5)
        self.ent1.grid(row=0, column=2, padx=(0, 5))
        self.btn1.grid(row=0, column=3, padx=(0, 5))
        self.cbx1.grid(row=0, column=4)
        self.cbx2.grid(row=0, column=0)
        self.ent2.grid(row=0, column=1, padx=5)
        self.btn2.grid(row=0, column=2, padx=(0, 5))
        self.cbx3.grid(row=0, column=3)
        self.button.grid(row=0, column=2, sticky="nsew", pady=(7, 0))
        self.lbl1.grid(row=0, column=0, columnspan=2, sticky="nsew")
        self.cbx4.grid(row=0, column=1, sticky="w")
        self.rbtn3.grid(row=1, column=0, sticky="w", pady=5)
        self.rbtn4.grid(row=1, column=1, sticky="w", pady=5)
        self.ent3.grid(row=2, column=0, sticky="w", padx=(0, 5), pady=(0, 10))
        self.btn.grid(row=2, column=1, sticky="w", pady=(0, 10))
        self.lbl2.grid(row=3, column=0, columnspan=2, sticky="nsew", pady=5)
        self.cbx5.grid(row=4, column=0, sticky="w", padx=(5, 0), pady=(0, 5))
        self.cbx6.grid(row=4, column=1, sticky="w", pady=(0, 5))
        self.lbl3.grid(row=5, column=0, columnspan=2, sticky="nsew", pady=5)
        self.cbx7.grid(row=6, column=0, sticky="w", padx=5, pady=(0, 5))
        self.cbx8.grid(row=6, column=1, sticky="w")
        self.cbx9.grid(row=7, column=0, sticky="w", padx=5, pady=(0, 5))
        self.cbx10.grid(row=7, column=1, sticky="w")
        self.lbl4.grid(row=8, column=0, columnspan=2, sticky="nsew", pady=5)
        self.cbx11.grid(row=9, column=0, sticky="w", padx=5)
        self.outputtext2.grid(row=0, column=0, columnspan=6, rowspan=10, sticky="nsew")
        self.scrollb.grid(row=0, column=6, rowspan=10, sticky="nsew")
        self.outputtext.grid(row=0, column=0, sticky="nsew", padx=(5, 0), pady=5)
        self.scrollb1.grid(row=0, column=1, sticky="nsew", padx=(0, 5), pady=5)
        self.button3.grid(row=1, sticky="w", padx=5, pady=5)
        self.button2.grid(row=1, columnspan=2, sticky="e", padx=5, pady=5)
        self.sg.grid(row=2, sticky='se')

    def check_expression(self, *args):
        self.outputtext.config(state=tk.NORMAL)
        varContent = self.v.get()

        if varContent == "-d":
            self.ent1['values'] = sorted(data['directory'].split('|'))
            self.cbx9.configure(state='disable')
            self.hd.set("")
        else:
            self.ent1['values'] = sorted(data['file'].split('|'))
            self.cbx9.configure(state='normal')

        pathContent = self.path.get()
        # Optional arguments
        opt = ''
        if len(self.kapemode.get()) > 1:
            opt += f' {self.kapemode.get()}'
        if len(self.append.get()) > 1:
            opt += f' {self.append.get()}'
        if len(self.logging.get()) > 1:
            opt += f' {self.logging.get()}'
        if len(self.verbose.get()) > 1:
            opt += f' {self.verbose.get()}'
        if len(self.hd.get()) > 1:
            opt += f' {self.hd.get()}'
        if self.hd.get() == "-hd":
            self.cbx1.configure(state='disable')
            self.cbx2.configure(state='disable')
            self.cbx3.configure(state='disable')
            self.lbl1.configure(state='disable')
            self.cbx4.configure(state='disable')
            self.cbx7.configure(state='disable')
            self.cbx8.configure(state='disable')
            self.cbx10.configure(state='disable')
            self.lbl4.configure(state='disable')
            self.cbx11.configure(state='disable')
            self.ent2.configure(state='disable')
            self.btn2.configure(state='disable')
            self.rbtn3.configure(state='disable')
            self.rbtn4.configure(state='disable')
            self.ent3.configure(state='disable')
            self.kapemode.set("")
            self.append.set("")
            self.e.set("")
            self.qd.set("")
            self.hf.set("")
            self.eb.set("")
            self.output.set("")
            self.outpath.set('')
            self.tvalue.set(0)
            self.tz.set(' ')
            self.tzdata.set(' ')
        else:
            self.cbx1.configure(state='normal')
            self.cbx2.configure(state='normal')
            self.cbx3.configure(state='normal')
            self.lbl1.configure(state='normal')
            self.cbx4.configure(state='normal')
            self.cbx7.configure(state='normal')
            self.cbx8.configure(state='normal')
            self.cbx10.configure(state='normal')
            self.cbx11.configure(state='normal')
            self.lbl4.configure(state='normal')
        if len(self.e.get()) > 1:
            opt += f' {self.e.get()}'
        if len(self.qd.get()) > 1:
            opt += f' {self.qd.get()}'
        if len(self.hf.get()) > 1:
            opt += f' {self.hf.get()}'
        if len(self.eb.get()) > 1:
            opt += f' {self.eb.get()}'
        if len(self.output.get()) > 1:
            opt += f' {self.output.get()}'
        if len(self.outpath.get()) > 0:
            opt += f' "{self.outpath.get()}"'
        if len(self.tz.get()) > 1:
            opt += f' {self.tz.get()}'
            if self.tz.get() == '-r':
                self.btn.configure(state='normal')
            else:
                self.btn.configure(state='disable')
        if len(self.tzdata.get()) > 0:
            opt += f' {self.tzdata.get()}'
        self.outputtext.delete(1.0, tk.END)  # clear the outputtext text widget
        self.outputtext.insert(tk.END, (f'SEPparser.exe {varContent} "{pathContent}"{opt}').replace('/', '\\'))
        self.outputtext.config(state=tk.DISABLED)
        self.cmd.set(f'{varContent} "{pathContent}"{opt}')

    def callback(self):
        if self.v.get() == "-d":
            _ = filedialog.askdirectory(initialdir='C:/',
                                        title='Select Directory')
        else:
            _ = filedialog.askopenfilename(initialdir='C:/',
                                           title='Select File')
        self.path.set(_)
        self.check_expression()

    def callback2(self):
        if self.output.get() == "-o":
            _ = filedialog.askdirectory(initialdir='C:/',
                                        title='Select Directory')
        else:
            _ = ''
        self.outpath.set(_)
        self.check_expression()

    def callback3(self):
        _ = filedialog.askopenfilename(initialdir='C:/',
                                       title='Select File',
                                       initialfile='registrationInfo.xml',
                                       filetypes=[("Text files", "*.xml")])
        self.tzdata.set(_)
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
        self.button.configure(state='disable')
        for widgets in self.tleft_frame.winfo_children():
            widgets.configure(state='disable')
        for widgets in self.tright_frame.winfo_children():
            widgets.configure(state='disable')
        for widgets in self.cleft_frame.winfo_children():
            widgets.configure(state='disable')
        for widgets in self.inner_frame.winfo_children():
            if str(widgets) == ".!frame.!frame.!frame3.!labelframe.!scrollbar":
                pass
            else:
                widgets.configure(state='disable')
        self.outputtext2.config(state=tk.NORMAL)
        self.outputtext2.delete('1.0', tk.END)
        cmdlist = "py.exe -3 -u SEPparser.py " + self.cmd.get()
        proc = subprocess.Popen(cmdlist, stdout=subprocess.PIPE)
        ansi_escape = re.compile(b'(\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~]))')
        while True:
            line = ansi_escape.split(proc.stdout.readline())
            line = [x for x in line if b'' != x]
            s = len(line)
            if s == 1:
                self.outputtext2.insert(tk.END, "\r\n")
                self.outputtext2.see(tk.END)
#                self.outputtext2.update_idletasks()
                continue

            if s % 2 != 0:
                s = s - 1

            for i in range(0, s, 2):
                tag = line[i]
                w = line[i+1]

                self.outputtext2.insert(tk.END, w, tag)
                self.outputtext2.see(tk.END)
#                self.outputtext2.update_idletasks()

            if not line:
                break

        self.outputtext2.config(state=tk.DISABLED)

        for widgets in self.tleft_frame.winfo_children():
            widgets.configure(state='normal')

        for widgets in self.cleft_frame.winfo_children():
            widgets.configure(state='normal')

        for widgets in self.inner_frame.winfo_children():
            if str(widgets) == ".!frame.!frame.!frame3.!labelframe.!scrollbar":
                pass
            else:
                widgets.configure(state='normal')

        self.button.configure(state='normal')
        self.cbx2.configure(state='normal')
        self.cbx3.configure(state='normal')

        if self.output.get() == "-o":
            self.ent2.configure(state='normal')
            self.btn2.configure(state='normal')

        self.tcheck()

    def copy_command(self):
        cmd = self.outputtext.get('1.0', tk.END)
        print(cmd)
        self.root.clipboard_append(cmd[:-1])

    def updtent2(self):
        if self.outpath.get() not in data['output'].split('|'):
            data['output'] = f"{self.outpath.get()}|{data['output']}"
            self.ent2['values'] = sorted(data['output'].split('|'))

    def updtent1(self):
        if self.v.get() == "-d":
            if self.path.get() not in data['directory'].split('|'):
                data['directory'] = f"{self.path.get()}|{data['directory']}"
                self.ent1['values'] = sorted(data['directory'].split('|'))
        else:
            if self.path.get() not in data['file'].split('|'):
                data['file'] = f"{self.path.get()}|{data['file']}"
                self.ent1['values'] = sorted(data['file'].split('|'))


class quit:
    def __init__(self, root):
        self.win = tk.Toplevel(root)
        self.win.attributes("-toolwindow", 1)
        self.win.title("Please confirm")
        self.win.grab_set()
        self.win.protocol("WM_DELETE_WINDOW", self.__callback)

        x = root.winfo_x()
        y = root.winfo_y()
        w = root.winfo_width()
        h = root.winfo_height()
        self.win.geometry("+%d+%d" % (x + w/2, y + h/2))

        self.frame = ttk.Frame(self.win)
        self.inner_frame = ttk.Frame(self.frame, relief='groove', padding=5)
        self.frame.grid(row=0, column=0)
        self.inner_frame.grid(row=0, column=0, padx=5, pady=5)

        self.label = ttk.Label(self.inner_frame, text="Are you sure you want to exit?", padding=5)
        self.yes = ttk.Button(self.inner_frame, text="Yes", command=lambda: self.btn1(root))
        self.no = ttk.Button(self.inner_frame, text="No", command=self.btn2)

        self.label.grid(row=0, column=0, columnspan=2)
        self.yes.grid(row=1, column=0, padx=(5, 0), pady=5)
        self.no.grid(row=1, column=1, padx=(0, 5), pady=5)

    def btn1(self, root):
        data['theme'] = ttk.Style().theme_use()
        with open("SEPgui.settings", "w") as jsonfile:
            json.dump(data, jsonfile)
        root.destroy()

    def btn2(self):
        self.win.destroy()

    def __callback(self):
        return


def main():
    def menu_theme():
        s = ttk.Style()
        bg = s.lookup('TFrame', 'background')
        menubar.config(background=bg)
        tool_menu.config(bg=bg)

    root = ThemedTk()
    ttk.Style().theme_use(data['theme'])
    root.title('SEPparser GUI')
    root.minsize(745, 400)
    root.protocol("WM_DELETE_WINDOW", lambda: quit(root))

    root.grid_rowconfigure(0, weight=1)
    root.grid_columnconfigure(0, weight=1)

    menubar = tk.Menu(root)
    root.config(menu=menubar)

    file_menu = tk.Menu(menubar, tearoff=0)
    tool_menu = tk.Menu(menubar, tearoff=0)
    help_menu = tk.Menu(menubar, tearoff=0)
    submenu = tk.Menu(tool_menu, tearoff=0)
    pro_menu = tk.Menu(file_menu, tearoff=0)

    for theme_name in sorted(root.get_themes()):
        submenu.add_command(label=theme_name,
                            command=lambda t=theme_name: [submenu.entryconfig(submenu.index(ttk.Style().theme_use()), background=''),
                                                          root.set_theme(t),
                                                          submenu.entryconfig(submenu.index(ttk.Style().theme_use()), background='grey')])
    file_menu.add_cascade(label="Project", menu=pro_menu)
    file_menu.add_separator()
    file_menu.add_command(label="Exit", command=lambda: quit(root))
    pro_menu.add_command(label="Load")
    pro_menu.add_command(label="Save")
    pro_menu.add_command(label="Save As")
    help_menu.add_command(label="About")
    tool_menu.add_cascade(label="Skins", menu=submenu)
    menubar.add_cascade(label="File", menu=file_menu)
    menubar.add_cascade(label="Tools", menu=tool_menu)
    menubar.add_cascade(label="Help", menu=help_menu)
    submenu.entryconfig(submenu.index(ttk.Style().theme_use()), background='grey')

    Pre_process(root)

    root.mainloop()


if __name__ == '__main__':
    main()
