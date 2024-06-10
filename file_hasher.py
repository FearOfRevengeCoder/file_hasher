import os
import hashlib
import tkinter as tk
from tkinter import filedialog
from tkinter import ttk

def get_file_hash(file_path, hash_type):
    if hash_type == 'md5':
        hasher = hashlib.md5()
    elif hash_type == 'sha-1':
        hasher = hashlib.sha1()
    elif hash_type == 'sha-256':
        hasher = hashlib.sha256()
    else:
        raise ValueError(f"Неподдерживаемый тип хеша: {hash_type}")

    with open(file_path, 'rb') as f:
        buf = f.read()
        hasher.update(buf)
    return hasher.hexdigest()

def on_folder_select():
    folder_path = filedialog.askdirectory()
    if folder_path:
        file_list = [f for f in os.listdir(folder_path) if os.path.isfile(os.path.join(folder_path, f))]
        if exe_only_var.get():
            file_list = [f for f in file_list if f.endswith('.exe')]
        result_text.delete('1.0', tk.END)
        hash_type = hash_var.get()
        for f in file_list:
            file_path = os.path.join(folder_path, f)
            file_hash = get_file_hash(file_path, hash_type)
            result_text.insert(tk.END, f"{f} - {file_hash}\n")

root = tk.Tk()
root.title('File Hasher')
root.geometry('600x400')


style = ttk.Style(root)
style.theme_use('clam')

main_frame = ttk.Frame(root, padding="10")
main_frame.pack(fill=tk.BOTH, expand=True)

title_label = ttk.Label(main_frame, text="Узнать хеш файлов", font=("TkDefaultFont", 16, "bold"))
title_label.pack(pady=(0, 10))

description_label = ttk.Label(main_frame, text="Выберите папку, содержащую файлы, для которых нужно вычислить хеш.", wraplength=350)
description_label.pack(pady=10)

separator = ttk.Separator(main_frame, orient='horizontal')
separator.pack(fill='x', pady=10)

hash_frame = ttk.Frame(main_frame)
hash_frame.pack(pady=10, fill=tk.BOTH, expand=True)

hash_var = tk.StringVar()
hash_var.set('sha-256')
hash_options = ['md5', 'sha-1', 'sha-256']
ttk.Label(hash_frame, text="Выберите тип хеша:").pack(side=tk.LEFT)
hash_combobox = ttk.Combobox(hash_frame, textvariable=hash_var, values=hash_options)
hash_combobox.pack(side=tk.LEFT, padx=10)

exe_only_var = tk.BooleanVar()
exe_only_checkbox = ttk.Checkbutton(hash_frame, text="Только .exe файлы", variable=exe_only_var)
exe_only_checkbox.pack(side=tk.LEFT, padx=10)

select_folder_button = ttk.Button(main_frame, text='Выбрать папку', command=on_folder_select, style='TButton')
select_folder_button.pack(pady=20)

result_frame = ttk.Frame(main_frame)
result_frame.pack(pady=10, fill=tk.BOTH, expand=True)

result_label = ttk.Label(result_frame, text="Результаты:")
result_label.pack(pady=10)

result_text = tk.Text(result_frame, height=10, width=50)
result_text.pack(pady=10, fill=tk.BOTH, expand=True)

# Добавление стиля для кнопки
style.configure('TButton', font=('Helvetica', 12), foreground='black', background='#7F4CAF')

root.mainloop()
