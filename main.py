import os
import pandas as pd
import hashlib
import tkinter as tk
from tkinter import filedialog, messagebox

file_path= None
phones = None
numbers = None
hashes = None



def salting(phones, numbers):
    for phone in phones:
        salt = int(phone) - int(numbers[0])
        if salt < 0:
            continue
        i = 1
        while (str(int(numbers[i]) + salt)) in phones:
            i += 1
            if i == 2:
                return salt
    return 0
def find_salt():
    global phones, numbers
    salt = salting(phones, numbers)
    messagebox.showinfo("Готово", f"Значение соли: {salt}")

def load_file_1():
    global file_path, numbers, hashes
    file_path = filedialog.askopenfilename()
    df = pd.read_excel(file_path)
    hashes = df["Номер телефона"].astype(str)
    numbers = [number[:-2] for number in df["Unnamed: 2"].astype(str).tolist()][:5]


def load_file_2():
    global file_path,phones
    file_path= filedialog.askopenfilename()
    with open(file_path) as r:
        phones = [line.strip()[-11:] for line in r.readlines()]

def load_file_3():
    global file_path,hashes
    file_path= filedialog.askopenfilename()
    with open(file_path) as r:
        hashes = [line.strip() for line in r.readlines()]

def load_file_4():
    global file_path,phones
    file_path= filedialog.askopenfilename()
    with open(file_path) as r:
        phones = [line.strip() for line in r.readlines()]


def deidentify(algorithm):
    global file_path, phones, numbers,hashes
    alg_index = {'md5': '0', 'sha1': '100', 'sha256': '1400', 'sha512': '1700'}


    if algorithm=='md5':
        with open(fr'{algorithm}.txt', 'w') as f:
            for HASH in hashes:
                f.write(HASH + "\n")
    #Запуск hashcat
    os.remove('hashcat.potfile')
    os.system(f"hashcat -a 3 -m {alg_index[algorithm]} -o output_{algorithm}.txt {algorithm}.txt ?d?d?d?d?d?d?d?d?d?d?d")

    # Чтение расшифрованных номеров из файла
    with open(fr'C:\hashcat\output_{algorithm}.txt') as r:
        phones = [line.strip()[-11:] for line in r.readlines()]

    with open(f'phones_{algorithm}.txt', 'w') as file:
        for phone in phones:
            file.write(phone + '\n')
    messagebox.showinfo("Готово", f"Таблица успешно расшифрована. Данные сохранены в файле 'phones_{algorithm}.txt'.")


def encrypt(algorythm):
    global file_path
    salt='115'
    with open(fr'{file_path}') as r:
        phones = [line.strip()[-11:] for line in r.readlines()]
    if algorythm=='sha1':
        phones_sha1 = [hashlib.sha1((phone+salt).encode()).hexdigest() for phone in phones]
        with open('sha1.txt','w') as f:
            for HASH in phones_sha1:
                f.write(HASH + '\n')
        button_deidentify_sha1['state']=tk.NORMAL
    if algorythm=='sha256':
        phones_sha256 = [hashlib.sha256((phone+salt).encode()).hexdigest() for phone in phones]
        with open('sha256.txt','w') as f:
            for HASH in phones_sha256:
                f.write(HASH + '\n')
        button_deidentify_sha256['state']=tk.NORMAL
    if algorythm=='sha512':
        phones_sha512 = [hashlib.sha1((phone+salt).encode()).hexdigest() for phone in phones]
        with open('sha512.txt','w') as f:
            for HASH in phones_sha512:
                f.write(HASH + '\n')




# Интерфейс Tkinter
root = tk.Tk()
root.title("Деобезличивание данных")


button_load_1 = tk.Button(root, text="Загрузить", command=load_file_1)
button_deidentify_md5= tk.Button(root, text="Деобезличить MD-5", command=lambda: deidentify("md5"))
button_compute_salt = tk.Button(root, text="Вычислить соль", command=find_salt)

button_load_2=tk.Button(root,text = "Загрузить",command=load_file_2)
button_encrypt_sha1 = tk.Button(root,text = "Зашифровать SHA-1",command=lambda: encrypt("sha1"))
button_encrypt_sha256 = tk.Button(root,text = "Зашифровать SHA-256",command=lambda: encrypt("sha256"))
button_encrypt_sha512 = tk.Button(root,text = "Зашифровать SHA-512",command=lambda: encrypt("sha512"))
button_deidentify_sha1= tk.Button(root, text="Деобезличить SHA-1", command=lambda: deidentify("sha1"))
button_deidentify_sha256= tk.Button(root, text="Деобезличить SHA-256", command=lambda: deidentify("sha256"))
button_deidentify_sha512= tk.Button(root, text="Деобезличить SHA-512", command=lambda: deidentify("sha512"))
button_load_3=tk.Button(root,text = "Загрузить",command=load_file_3)
button_load_4=tk.Button(root,text = "Загрузить",command=load_file_4)

button_load_1.grid(row=1, column=0, padx=10, pady=5, sticky="w")
button_deidentify_md5.grid(row=2, column=0, padx=10, pady=5, sticky="w")
button_compute_salt.grid(row=4, column=0, padx=10, pady=5, sticky="w")
button_load_2.grid(row=1, column=2, padx=10, pady=5, sticky="w")
button_encrypt_sha1.grid(row=2, column=2, padx=10, pady=5, sticky="w")
button_encrypt_sha256.grid(row=3, column=2, padx=10, pady=5, sticky="w")
button_encrypt_sha512.grid(row=4, column=2, padx=10, pady=5, sticky="w")
button_deidentify_sha1.grid(row = 2, column=3,padx=10,pady=5,sticky="w")
button_deidentify_sha256.grid(row = 3, column=3,padx=10,pady=5,sticky="w")
button_deidentify_sha512.grid(row = 4, column=3,padx=10,pady=5,sticky="w")
button_load_3.grid(row=1, column=3, padx=10, pady=5, sticky="w")
button_load_4.grid(row=3, column=0, padx=10, pady=5, sticky="w")


root.mainloop()
