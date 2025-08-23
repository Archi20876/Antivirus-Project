from tkinter import *
from tkinter import filedialog
import subprocess
from PIL import Image, ImageTk
import threading
import os
import joblib
import numpy as np
import math
model = joblib.load("malware_model.pkl")
global process_rtm
process_rtm = None

root = Tk()

root.title("żbikAV")
root.geometry("1440x900")
root.resizable(0,0)
root.configure(bg="#262626")

file_path = ""

# Set proper absolute path for your engine binaries
ENGINE_PATH = "/home/archita/antivirus_project/engine"   # Engine path
ENGINE_RTM_PATH = "/home/archita/antivirus_project/RTM"  # RTM

def open_file():
    global file_path
    file_path = filedialog.askopenfilename()
    if file_path:
        file_label.config(text="Chosen path: " + file_path)
    else:
        file_label.config(text="No path selected")

def open_directory():
    global file_path
    file_path = filedialog.askdirectory()
    if file_path:
        file_label.config(text="Chosen path: " + file_path)
    else:
        file_label.config(text="No path selected")

def execute_engine(file_path, output_text):
    if file_path:
        file_label.config(text=file_path)
        process = subprocess.Popen([ENGINE_PATH, file_path], stdout=subprocess.PIPE, universal_newlines=True)
        while True:
            output_line = process.stdout.readline()
            if output_line == '' and process.poll() is not None:
                break
            if output_line:
                output_text.insert(END, output_line)
                output_text.see(END)
        process.stdout.close()
        process.wait()

        # ✅ Outer try block properly indented
        try:
            features = extract_features_single_file(file_path)
            prediction = model.predict([features])[0]
            if prediction == 1:
                output_text.insert(END, "\n⚠️ [ML] Warning: File is classified as MALICIOUS.\n")
            else:
                output_text.insert(END, "\n✅ [ML] Safe: File is classified as BENIGN.\n")

            # ➕ ML-YARA rule check
            rules_flagged = ml_yara_rules(features)
            if rules_flagged:
                output_text.insert(END, f"\n[ML-YARA] Suspicious Rules Triggered: {', '.join(rules_flagged)}\n")

            # ➕ Confidence score
            try:
                prob = model.predict_proba([features])[0][1]
                output_text.insert(END, f"\n[Confidence] Probability of being malicious: {prob:.2f}\n")
            except:
                output_text.insert(END, "\n[Confidence] Score not available.\n")

            # ➕ Logging
            from datetime import datetime
            with open("ml_yara_log.txt", "a") as log:
                log.write(f"{file_path} -- Rules: {', '.join(rules_flagged)} -- Time: {datetime.now()}\n")

        except Exception as e:
            output_text.insert(END, f"\n[ML] Feature extraction/prediction failed: {e}\n")

    else:
        file_label.config(text="No path selected")

def ml_yara_rules(features):
    entropy, size, *byte_hist = features
    triggered = []

    if entropy > 7.5:
        triggered.append("High Entropy")
    if size > 1_000_000:
        triggered.append("Large File Size")
    if max(byte_hist) > 0.1:
        triggered.append("Suspicious Byte Pattern")
    return triggered

def calculate_entropy(data):
    if not data:
        return 0
    byte_counts = [0]*256
    for byte in data:
        byte_counts[byte] += 1
    entropy = 0
    for count in byte_counts:
        if count == 0:
            continue
        p = count / len(data)
        entropy -= p * math.log2(p)
    return entropy

def extract_features_single_file(file_path):
    with open(file_path, 'rb') as f:
        content = f.read()

    entropy = calculate_entropy(content)
    size = len(content)

    byte_hist = [0]*256
    for byte in content:
        byte_hist[byte] += 1
    byte_hist = [x/size for x in byte_hist]  # Normalize histogram

    return [entropy, size] + byte_hist
       

def execute_engine_rtm(file_path, output_text):
    if file_path:
        global process_rtm
        file_label.config(text=file_path)
        process_rtm = subprocess.Popen([ENGINE_RTM_PATH, file_path], stdout=subprocess.PIPE, universal_newlines=True)
        def read_output():
            while True:
                output_line = process_rtm.stdout.readline()
                if output_line == '' and process_rtm.poll() is not None:
                    break
                if output_line:
                    output_text_rtm.insert(END, output_line)
                    output_text_rtm.see(END)
            process_rtm.stdout.close()
        output_reader = threading.Thread(target=read_output)
        output_reader.daemon = True
        output_reader.start()
    else:
        file_label.config(text="No path selected")

def toggle_win():
    menu = Frame(root,width=350,height=900,bg="#12c4c0")
    menu.place(x=0,y=0)

    home_button = Button(menu, text="Home", command=show_root, width=40, height=3, fg="#262626", bg="#0f9d9a", activebackground="#12c4c0", activeforeground="#262626", border=2)
    home_button.place(x=0, y=80)

    File_button = Button(menu, text="File Upload",  command=show_file_upload_page, width=40, height=3, fg="#262626", bg="#0f9d9a", activebackground="#12c4c0", activeforeground="#262626", border=2)
    File_button.place(x=0, y=140)

    Dir_button = Button(menu, text="Directory Upload",  command=show_directory_upload_page, width=40, height=3, fg="#262626", bg="#0f9d9a", activebackground="#12c4c0", activeforeground="#262626", border=2)
    Dir_button.place(x=0, y=200)

    rlmonitor_button = Button(menu, text="Real-Time Monitoring",  command=show_rtm_page, width=40, height=3, fg="#262626", bg="#0f9d9a", activebackground="#12c4c0", activeforeground="#262626", border=2)
    rlmonitor_button.place(x=0, y=260)

    def dele():
        File_button.destroy()
        Dir_button.destroy()
        rlmonitor_button.destroy()
        menu.destroy()
    
    global menu_close
    tmp_pic = Image.open("images/menu_close.png")
    resized_tmp_pic = tmp_pic.resize((50, 50), Image.LANCZOS)
    menu_close = ImageTk.PhotoImage(resized_tmp_pic)
    Button(menu, image=menu_close, command=dele, border=0, activebackground="#12c4c0",bg='#12c4c0').place(x=5,y=10)

def show_root():
    rtm_notif_on_root.pack()
    file_upload_page.pack_forget()
    directory_upload_page.pack_forget()
    rtm_page.pack_forget()

def show_file_upload_page():
    file_upload_page.pack()
    directory_upload_page.pack_forget()
    rtm_page.pack_forget()
    rtm_notif_on_root.pack_forget()

def show_directory_upload_page():
    file_upload_page.pack_forget()
    directory_upload_page.pack()
    rtm_page.pack_forget()
    rtm_notif_on_root.pack_forget()

def show_rtm_page():
    file_upload_page.pack_forget()
    directory_upload_page.pack_forget()
    rtm_page.pack()
    rtm_notif_on_root.pack_forget()

def toggle_switch():
    global process_rtm
    if switch_var.get() == 1:
        switch_button.config(text="Enabled", fg="#12c4c0")
        # Extract all directory entries
        directories = directory_listbox.get(0, 'end')
        if not directories:
            output_text_rtm.insert(END, "[!] No directories selected for monitoring.\n")
            return
        
        # Create a list: [ENGINE_RTM_PATH, dir1, dir2, ...]
        args = [ENGINE_RTM_PATH] + [d.strip(';') for d in directories]

        process_rtm = subprocess.Popen(args, stdout=subprocess.PIPE, universal_newlines=True)

        def read_output():
            while True:
                output_line = process_rtm.stdout.readline()
                if output_line == '' and process_rtm.poll() is not None:
                    break
                if output_line:
                    output_text_rtm.insert(END, output_line)
                    output_text_rtm.see(END)
            process_rtm.stdout.close()
        
        output_reader = threading.Thread(target=read_output)
        output_reader.daemon = True
        output_reader.start()

    else:
        switch_button.config(text="Disabled", fg="Black")
        if process_rtm is not None:
            process_rtm.kill()

def add_item():
    rtm_dir_path = directory_entry.get()
    if rtm_dir_path:
        directory_listbox.insert(END, rtm_dir_path + ";")
        directory_entry.delete(0, END)

def delete_item():
    selected_indices = directory_listbox.curselection()
    for index in selected_indices[::-1]:
        directory_listbox.delete(index)

def clear_rtm_output():
    output_text_rtm.delete(1.0, END)


# Menu button image
tmp_pic = Image.open("images/menu_open.png")
resized_tmp_pic = tmp_pic.resize((50, 50), Image.LANCZOS)
menu_open = ImageTk.PhotoImage(resized_tmp_pic)
Button(root,image=menu_open, command=toggle_win, border=0, activebackground="#262626",bg='#262626').place(x=5,y=10)

# Pages
file_upload_page = Frame(root, bg="#262626")
rtm_notif_on_root = Frame(root, bg="#262626")
directory_upload_page = Frame(root, bg="#262626")
rtm_page = Frame(root, bg="#262626")

# Home page
my_label = Label(root, text="Best AV in the world", font=("Helvetica", 50, "bold"), bg="#262626", fg="white")
my_label.pack(pady=10)
rtm_notif_on_root.pack()

my_label_rtm = Label(rtm_notif_on_root, text="Real-Time Monitoring logs", font=("Helvetica", 30, "bold"), bg="#262626", fg="#12c4c0")
my_label_rtm.pack(pady=20)

output_text_rtm = Text(rtm_notif_on_root, width=70, height=10, wrap='word', font=("Helvetica", 14), border=10, bg="#262626", fg="white")
output_text_rtm.pack(pady=10)

clear_button = Button(rtm_notif_on_root, text="Clear", command=clear_rtm_output, border=0, width=20, height=3)
clear_button.pack()

# File upload page
my_label = Label(file_upload_page, text="File Scanner", font=("Helvetica", 40, "bold"), bg="#262626", fg="#12c4c0")
my_label.pack(pady=10)

file_label = Label(file_upload_page, text="", font=("Helvetica", 13, "bold"), bg="#262626", fg="white")
file_label.pack(pady=10)

upload_image = Image.open("images/upload_image.png")
upload_image_resized = upload_image.resize((200, 170), Image.LANCZOS)
upload_image_tk = ImageTk.PhotoImage(upload_image_resized)

image_button = Label(file_upload_page, image=upload_image_tk)
image_button.pack(pady=10)

image_button.bind("<Button-1>", lambda event: open_file())

my_button = Button(file_upload_page, text="Upload", command=lambda: execute_engine(file_path, output_text_file), width=28, height=2)
my_button.pack(pady=20)

my_label = Label(file_upload_page, text="Scan results", font=("Helvetica", 30, "bold"), bg="#262626", fg="#12c4c0")
my_label.pack(pady=20)

output_text_file = Text(file_upload_page, width=70, height=10, wrap='word', font=("Helvetica", 14), border=10, bg="#262626", fg="white")
output_text_file.pack(pady=10)

# Directory upload page
my_label = Label(directory_upload_page, text="Directory Scanner", font=("Helvetica", 40, "bold"), bg="#262626", fg="#12c4c0")
my_label.pack(pady=10)

file_label = Label(directory_upload_page, text="", font=("Helvetica", 12, "bold"), bg="#262626", fg="white")
file_label.pack(pady=10)

image_button = Label(directory_upload_page, image=upload_image_tk)
image_button.pack(pady=10)

image_button.bind("<Button-1>", lambda event: open_directory())

my_button = Button(directory_upload_page, text="Upload", command=lambda: execute_engine(file_path, output_text_file), width=28, height=2)
my_button.pack(pady=10)

my_label = Label(directory_upload_page, text="Scan results", font=("Helvetica", 30, "bold"), bg="#262626", fg="#12c4c0")
my_label.pack(pady=20)

output_text_directory = Text(directory_upload_page, width=70, height=10, wrap='word', font=("Helvetica", 14), border=10, bg="#262626", fg="white")
output_text_directory.pack(pady=10)

# RTM page
my_label = Label(rtm_page, text="Real-Time Monitoring", font=("Helvetica", 40, "bold"), bg="#262626", fg="#12c4c0")
my_label.pack(pady=10)

switch_var = IntVar()
switch_button = Checkbutton(rtm_page, text="Disabled", variable=switch_var, command=toggle_switch, border=0, font=("Helvetica", 24, "bold"), width=40, indicatoron=False)
switch_button.pack()

my_label = Label(rtm_page, text="Paste directory path here:", font=("Helvetica", 15, "bold"), bg="#262626", fg="White")
my_label.pack(pady=30)

directory_entry = Entry(rtm_page, width=100, bg="#787a79", border=0, font=("Helvetica", 10))
directory_entry.pack()

directory_listbox = Listbox(rtm_page, border=0, width=70, height=10, bg="#787a79", font=("Helvetica", 15))
directory_listbox.pack(pady=30)

button_frame = Frame(rtm_page,bg="#262626")
button_frame.pack()

add_button = Button(button_frame, text="Add", command=add_item, border=0, width=20, height=3)
add_button.pack(side=LEFT)

delete_button = Button(button_frame, text="Delete", command=delete_item, border=0, width=20, height=3)
delete_button.pack(side=LEFT, padx=10)

root.mainloop()
