import os
import pandas as pd
import hashlib
import tkinter as tk
from tkinter import filedialog, messagebox

file_path = None
phones = None
numbers = None
is_file_loaded = False


def salting(phones, numbers):
    for phone in phones:
        salt = int(phone) - int(numbers[0])
        if salt < 0:
            continue
        i = 1
        while (str(int(numbers[i]) + salt)) in phones:
            i += 1
            if i == 5:
                return salt
    return 0
def find_salt():
    global phones, numbers
    salt = salting(phones, numbers)
    messagebox.showinfo("Готово", f"Значение соли: {salt}")

def load_file():
    global file_path, is_file_loaded
    file_path = filedialog.askopenfilename()
    if file_path:
        is_file_loaded = True
        button_sha1["state"] = tk.NORMAL
        button_sha256["state"] = tk.NORMAL
        button_sha512["state"] = tk.NORMAL
        button_md5["state"] = tk.NORMAL


def hashing(algorithm):
    global file_path, phones, numbers
    df = pd.read_excel(file_path)
    hashes = df["Номер телефона"].astype(str)  # Преобразование в строки
    numbers = [number[:-2] for number in df["Unnamed: 2"].astype(str).tolist()][:5]
    alg_index = {'md5': '0', 'sha1': '100', 'sha256': '1400', 'sha512': '1700'}

    # Хеширование с использованием выбранного алгоритма
    if algorithm == 'md5':
        hashes = [hashlib.md5(h.encode()).hexdigest() for h in hashes]
    elif algorithm == 'sha1':
        hashes = [hashlib.sha1(h.encode()).hexdigest() for h in hashes]
    elif algorithm == 'sha256':
        hashes = [hashlib.sha256(h.encode()).hexdigest() for h in hashes]
    else:
        hashes = [hashlib.sha512(h.encode()).hexdigest() for h in hashes]

    with open(f'{algorithm}.txt', 'w') as f:
        for HASH in hashes:
            f.write(HASH + "\n")

    # Запуск hashcat
    os.system(
        f"hashcat -a 3 -m {alg_index[algorithm]} -o output_{algorithm}.txt {algorithm}.txt ?d?d?d?d?d?d?d?d?d?d?d")

    # Чтение расшифрованных номеров из файла
    with open(fr'C:\hashcat\output_{algorithm}.txt') as r:
        phones = [line.strip()[-11:] for line in r.readlines()]

    with open('phones.txt', 'w') as file:
        for phone in phones:
            file.write(phone + '\n')
    messagebox.showinfo("Готово", "Таблица успешно расшифрована. Данные сохранены в файле 'phones.txt'.")



# Интерфейс Tkinter
root = tk.Tk()
root.title("Деобезличивание данных")


button_load = tk.Button(root, text="Загрузить", command=load_file)
button_sha1 = tk.Button(root, text="Деобезличить SHA-1", command=lambda: hashing('sha1'), state=tk.DISABLED)
button_sha256 = tk.Button(root, text="Деобезличить SHA-256", command=lambda: hashing('sha256'),
                                     state=tk.DISABLED)
button_sha512 = tk.Button(root, text="Деобезличить SHA-512", command=lambda: hashing('sha512'),
                                     state=tk.DISABLED)
button_md5 = tk.Button(root, text="Деобезличить MD-5", command=lambda: hashing('md5'), state=tk.DISABLED)
button_compute_salt = tk.Button(root, text="Вычислить соль", command=find_salt)

button_load.grid(row=1, column=0, padx=10, pady=5, sticky="w")
button_md5.grid(row=2, column=0, padx=10, pady=5, sticky="w")
button_sha1.grid(row=3, column=0, padx=10, pady=5, sticky="w")
button_sha256.grid(row=4, column=0, padx=10, pady=5, sticky="w")
button_sha512.grid(row=5, column=0, padx=10, pady=5, sticky="w")
button_compute_salt.grid(row=6, column=0, padx=10, pady=5, sticky="w")

root.mainloop()
