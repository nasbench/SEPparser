from tksheet import Sheet
from tkinter import *
from tkinter import filedialog
import subprocess
import threading
import pandas as pd


class ViewLogs:
    def __init__(self, btm_right):
        self.btm_right = btm_right
        for widgets in self.btm_right.winfo_children():
            widgets.destroy()
        self.btm_right.grid_columnconfigure(0, weight=1)
        self.btm_right.grid_rowconfigure(0, weight=1)
        self.frame = Frame(self.btm_right)

        self.btn = Button(self.btm_right, text="Symantec Client Management Control Log", command=lambda: readcsv(self.btm_right, 'Symantec_Client_Management_Control_Log.csv', 0))
        self.btn2 = Button(self.btm_right, text="Symantec Client Management Security Logs", command=lambda: readcsv(self.btm_right, 'Symantec_Client_Management_Security_Log.csv', 0))
        self.btn3 = Button(self.btm_right, text="Symantec Client Management System Log", command=lambda: readcsv(self.btm_right, 'Symantec_Client_Management_System_Log.csv', 0))
        self.btn4 = Button(self.btm_right, text="Symantec Client Management Tamper Protect Log", command=lambda: readcsv(self.btm_right, 'Symantec_Client_Management_Tamper_Protect_Log.csv', 0))
        self.btn5 = Button(self.btm_right, text="Symantec Network and Host Exploit Mitigation Packet Log", command=lambda: readcsv(self.btm_right, 'Symantec_Network_and_Host_Exploit_Mitigation_Packet_Log.csv', 0))
        self.btn6 = Button(self.btm_right, text="Symantec Network and Host Exploit Mitigation Traffic Log", command=lambda: readcsv(self.btm_right, 'Symantec_Network_and_Host_Exploit_Mitigation_Traffic_Log.csv', 0))
        self.btn7 = Button(self.btm_right, text="View Timeline", command=lambda: readcsv(self.btm_right, 'Symantec_Timeline.csv', 0))
        self.btn.grid(row=0, column=0, sticky="ew")
        self.btn2.grid(row=1, column=0, sticky="ew")
        self.btn3.grid(row=2, column=0, sticky="ew")
        self.btn4.grid(row=3, column=0, sticky="ew")
        self.btn5.grid(row=4, column=0, sticky="ew")
        self.btn6.grid(row=5, column=0, sticky="ew")
        self.btn7.grid(row=6, column=0, sticky="ew")


class Status:
    def __init__(self, btm_right):
        self.btm_right = btm_right
        for widgets in self.btm_right.winfo_children():
            widgets.destroy()
        self.btm_right.grid_columnconfigure(0, weight=1)
        self.btm_right.grid_rowconfigure(0, weight=1)
        self.frame = Frame(self.btm_right)

        self.btn = Button(self.btm_right, text="Test1", command=lambda: readcsv(self.btm_right, 'Symantec_Timeline.csv', 0))
        self.btn2 = Button(self.btm_right, text="Test2", command=lambda: readcsv(self.btm_right, 'settings.csv', 0))
        self.btn3 = Button(self.btm_right, text="Test3", command=lambda: readcsv(self.btm_right, 'settings.csv', 0))

        self.btn.grid(row=0, column=0, sticky="ew")
        self.btn2.grid(row=1, column=0, sticky="ew")
        self.btn3.grid(row=2, column=0, sticky="ew")


class readcsv:
    def __init__(self, master, log, tl):
        if tl == 0:
            self.master = Toplevel(master)
        else:
            self.master = master
            for widgets in self.master.winfo_children():
                widgets.destroy()
        self.log = log
        self.master.grid_columnconfigure(0, weight=1)
        self.master.grid_rowconfigure(0, weight=1)
        self.frame = Frame(self.master)
        self.frame.grid_columnconfigure(0, weight=1)
        self.frame.grid_rowconfigure(0, weight=1)

        self.sheet = Sheet(self.frame,
                           data=pd.read_csv(log, keep_default_na=False, dtype=str, header=0).values.tolist(),
                           headers=pd.read_csv(log, keep_default_na=False, dtype=str, header=0).columns.tolist())

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
    def __init__(self, root):
        self.root = root
        for widgets in self.root.winfo_children():
            widgets.destroy()
        self.top_frame = Frame(self.root, bg='cyan', width=450, height=50, pady=3)
        self.btm_frame = Frame(self.root, bg='gray2')
        self.top_frame.grid(row=0, sticky="ew")
        self.btm_frame.grid(row=1, sticky="nsew")
        # create the bottom frame widgets
        self.btm_frame.grid_rowconfigure(0, weight=1)
        self.btm_frame.grid_columnconfigure(1, weight=1)

        self.btn = Button(self.top_frame, text="Help", command=lambda: ViewLogs(self.btm_right))

        self.btm_left = Frame(self.btm_frame, bg='blue', width=100, height=300)
        self.btm_right = Frame(self.btm_frame, bg='yellow', width=350, height=300)

        self.btm_left.grid(row=0, column=0, sticky="ns")
        self.btm_right.grid(row=0, column=1, sticky="nsew")

        self.btn1 = Button(self.btm_left, text="Status", command=lambda: Status(self.btm_right))
        self.btn2 = Button(self.btm_left, text="Scan for Threats", command=lambda: None)
        self.btn3 = Button(self.btm_left, text="View Settings", command=lambda: readcsv(self.btm_right, 'settings.csv', 1))
        self.btn4 = Button(self.btm_left, text="View Quarantine", command=lambda: readcsv(self.btm_right, 'quarantine.csv', 1))
        self.btn5 = Button(self.btm_left, text="View Logs", command=lambda: ViewLogs(self.btm_right))

        self.btn.grid(row=0, column=2, sticky="e")
        self.btn1.grid(row=0, column=0, sticky="ew")
        self.btn2.grid(row=1, column=0, sticky="ew")
        self.btn3.grid(row=2, column=0, sticky="ew")
        self.btn4.grid(row=3, column=0, sticky="ew")
        self.btn5.grid(row=4, column=0, sticky="ew")


class Pre_process:
    def __init__(self, root):
        self.root = root
        for widgets in self.root.winfo_children():
            widgets.destroy()

        # create all of the main containers
        self.top_frame = Frame(self.root, bg='cyan')
        self.center_frame = Frame(self.root, bg='green')
        self.left_frame = Frame(self.center_frame, bg='green')
        self.right_frame = Frame(self.center_frame, bg='yellow')
        self.bottom_frame = Frame(self.root, bg='blue')   
        self.top_frame.grid(row=0, column=0, sticky="ew")
        self.center_frame.grid(row=1, column=0, sticky="nsew")
        self.left_frame.grid(row=0, column=0, sticky="ns")
        self.right_frame.grid(row=0, column=1, sticky="nsew")
        self.bottom_frame.grid(row=2, column=0, sticky="ew")

        self.center_frame.grid_rowconfigure(0, weight=1)
        self.center_frame.grid_columnconfigure(1, weight=1)
        self.right_frame.grid_rowconfigure(0, weight=1)
        self.right_frame.grid_columnconfigure(0, weight=1)

        self.v = StringVar(value="-d")
        self.kapemode = StringVar(value="")
        self.output = StringVar(value="")
        self.path = StringVar(value="c:/")
        self.path.trace_add('write', self.check_expression)
        self.outpath = StringVar(value="")
        self.outpath.trace_add('write', self.check_expression)
        self.append = StringVar(value="")
        self.tvalue = IntVar()
        self.tz = StringVar(value=' ')
        self.tzdata = StringVar()
        self.tzdata.trace_add('write', self.check_expression)
        self.logging = StringVar()
        self.verbose = StringVar()
        self.e = StringVar()
        self.qd = StringVar()
        self.hd = StringVar()
        self.hf = StringVar()
        self.eb = StringVar()
        self.cmd = StringVar()

        self.lbl1 = Label(self.top_frame,
                          text="Directory/Folder Input:")

        self.rbtn1 = Radiobutton(self.top_frame,
                                 text="Directory",
                                 justify=LEFT,
                                 variable=self.v,
                                 value="-d",
                                 command=self.check_expression)

        self.rbtn2 = Radiobutton(self.top_frame,
                                 text="File",
                                 justify=LEFT,
                                 variable=self.v,
                                 value="-f",
                                 command=self.check_expression)

        self.ent1 = Entry(self.top_frame,
                          width=25,
                          textvariable=self.path)

        self.btn1 = Button(self.top_frame, text='...', command=lambda: self.callback())

        self.cbx1 = Checkbutton(self.top_frame,
                                text="Kape Mode",
                                offvalue="",
                                onvalue="-k",
                                var=self.kapemode,
                                command=self.check_expression)

        self.lbl2 = Label(self.top_frame,
                          text="Output:")

        self.cbx2 = Checkbutton(self.top_frame,
                                text="Output Directory",
                                offvalue="",
                                onvalue="-o",
                                var=self.output,
                                command=lambda:[self.check_expression(), self.outcheck()])

        self.ent2 = Entry(self.top_frame,
                          width=25,
                          textvariable=self.outpath,
                          state='disabled')

        self.btn2 = Button(self.top_frame,
                           text='...',
                           state='disabled',
                           command=lambda: self.callback2())

        self.cbx3 = Checkbutton(self.top_frame,
                                text="Append",
                                offvalue="",
                                onvalue="-a",
                                var=self.append,
                                command=self.check_expression)

        self.lbl3 = Label(self.left_frame,
                          text="Time Zone")

        self.cbx4 = Checkbutton(self.left_frame,
                                offvalue=0,
                                onvalue=1,
                                var=self.tvalue,
                                command=self.tcheck)

        self.rbtn3 = Radiobutton(self.left_frame,
                                 text="Offset",
                                 justify=LEFT,
                                 variable=self.tz,
                                 value="-tz",
                                 state='disabled',
                                 command=self.check_expression)

        self.ent3 = Entry(self.left_frame,
                          width=25,
                          state='disabled',
                          textvariable=self.tzdata)

        self.rbtn4 = Radiobutton(self.left_frame,
                                 text="registrationInfo.xml",
                                 justify=LEFT,
                                 variable=self.tz,
                                 value="-r",
                                 state='disabled',
                                 command=self.check_expression)

        self.lbl4 = Label(self.left_frame,
                          text="Logging")

        self.cbx5 = Checkbutton(self.left_frame,
                                text="Enabled",
                                offvalue="",
                                onvalue="-l",
                                var=self.logging,
                                command=self.check_expression)

        self.cbx6 = Checkbutton(self.left_frame,
                                text="Verbose",
                                offvalue="",
                                onvalue="-v",
                                var=self.verbose,
                                command=self.check_expression)

        self.lbl5 = Label(self.left_frame,
                          text="VBN Options")

        self.cbx7 = Checkbutton(self.left_frame,
                                text="Extract",
                                offvalue="",
                                onvalue="-e",
                                var=self.e,
                                command=self.check_expression)

        self.cbx8 = Checkbutton(self.left_frame,
                                text="Quarantine Dump",
                                offvalue="",
                                onvalue="-qd",
                                var=self.qd,
                                command=self.check_expression)

        self.cbx9 = Checkbutton(self.left_frame,
                                text="Hex Dump",
                                offvalue="",
                                onvalue="-hd",
                                var=self.hd,
                                command=self.check_expression)

        self.cbx10 = Checkbutton(self.left_frame,
                                 text="Hash File",
                                 offvalue="",
                                 onvalue="-hf",
                                 var=self.hf,
                                 command=self.check_expression)

        self.lbl6 = Label(self.left_frame,
                          text="ccSubSDK",)

        self.cbx11 = Checkbutton(self.left_frame,
                                 text="Extract Blob",
                                 offvalue="",
                                 onvalue="-eb",
                                 var=self.eb,
                                 command=self.check_expression)

        self.outputtext2 = Text(self.right_frame)

        self.lbl7 = Label(self.bottom_frame,
                          text="Current command line")

        self.outputtext = Text(self.bottom_frame, height=2)
        self.check_expression()

        self.var = IntVar()
        self.button = Button(self.bottom_frame, text="Click Me", command=lambda: Post_process(root))
        self.button2 = Button(self.bottom_frame, text="run", command=lambda: threading.Thread(target=self.execute).start())

        # layout the widgets in the main frame
        self.lbl1.grid(row=0, column=0, columnspan=5, sticky="w")
        self.lbl2.grid(row=0, column=5, columnspan=4, sticky="w")
        self.rbtn1.grid(row=1, column=0)
        self.rbtn2.grid(row=1, column=1)
        self.ent1.grid(row=1, column=2)
        self.btn1.grid(row=1, column=3)
        self.cbx1.grid(row=1, column=4)
        self.cbx2.grid(row=1, column=5)
        self.ent2.grid(row=1, column=6)
        self.btn2.grid(row=1, column=7)
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
        self.lbl7.grid(row=0, column=0, sticky="w")
        self.outputtext.grid(row=1, column=0)
        self.button.grid(row=2)
        self.button2.grid(row=3)

    def check_expression(self, *args):
        # Your code that checks the expression
        self.outputtext.config(state=NORMAL)
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
        if len(self.tz.get()) > 1:
            opt += f' {self.tz.get()}'
        if len(self.tzdata.get()) > 1:
            opt += f' {self.tzdata.get()}'
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
        self.outputtext.delete(1.0, END)  # clear the outputtext text widget
        self.outputtext.insert(END, f'{varContent} "{pathContent}"{opt}')
        self.outputtext.config(state=DISABLED)
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
        self.outputtext2.delete('1.0', END)
        cmdlist = "py.exe -3 -u SEPparser2.py " + self.cmd.get()
        proc = subprocess.Popen(cmdlist, stdout=subprocess.PIPE)
        while True:
            line = proc.stdout.readline()
            if not line:
                break
            self.outputtext2.insert(END, line)
            self.outputtext2.see(END)
            self.outputtext2.update_idletasks()

def main():
    root = Tk()
    root.title('SEPparser GUI')
    root.geometry('{}x{}'.format(460, 350))

    # layout all of the main containers
    root.grid_rowconfigure(1, weight=1)
    root.grid_columnconfigure(0, weight=1)

    # create all of the main containers
    Pre_process(root)

    root.mainloop()


if __name__ == '__main__':
    main()