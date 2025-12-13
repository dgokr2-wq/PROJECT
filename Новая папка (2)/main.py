
"""
GUI-приложение на tkinter для демонстрации работы учебного шифра SAFER K-128.
Возможности:
- выбор одного из подготовленных Excel-датасетов;
- просмотр его содержимого (первые строки);
- копирование датасета в поле входного текста;
- шифрование и расшифрование текста по нажатию кнопок.
"""
import os
import tkinter as tk
from tkinter import ttk, messagebox
import pandas as pd

from safer_cipher import encrypt_message, decrypt_message

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATASETS_DIR = os.path.join(BASE_DIR, "datasets")

DATASETS = {
    "Пользователи (users)": "dataset_users.xlsx",
    "CMDB (cmdb)": "dataset_cmdb.xlsx",
    "Тикеты ITSM (itsm_tickets)": "dataset_itsm_tickets.xlsx",
}

class CryptoApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("Учебное приложение шифрования SAFER K-128")
        self.geometry("1000x700")
        self.configure(bg="#f5f5f5")

        self.current_df = None
        self._build_ui()

    def _build_ui(self) -> None:
        # Верхняя панель: выбор датасета
        top_frame = tk.Frame(self, bg="#f5f5f5")
        top_frame.pack(fill=tk.X, padx=10, pady=10)

        tk.Label(top_frame, text="Выбор набора данных (Excel):", bg="#f5f5f5",
                 font=("Arial", 11, "bold")).pack(side=tk.LEFT)

        self.dataset_var = tk.StringVar(value=list(DATASETS.keys())[0])
        dataset_combo = ttk.Combobox(top_frame, textvariable=self.dataset_var,
                                     values=list(DATASETS.keys()), state="readonly", width=40)
        dataset_combo.pack(side=tk.LEFT, padx=10)
        dataset_combo.bind("<<ComboboxSelected>>", lambda e: self.load_dataset())

        btn_load = tk.Button(top_frame, text="Загрузить датасет",
                             command=self.load_dataset, bg="#2b5797", fg="white")
        btn_load.pack(side=tk.LEFT, padx=5)

        btn_copy = tk.Button(top_frame, text="Копировать датасет в текст",
                             command=self.copy_dataset_to_text, bg="#4caf50", fg="white")
        btn_copy.pack(side=tk.LEFT, padx=5)

        # Средняя панель: предпросмотр датасета
        mid_frame = tk.Frame(self, bg="#f5f5f5")
        mid_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))

        tk.Label(mid_frame, text="Предпросмотр датасета (первые строки):",
                 bg="#f5f5f5", font=("Arial", 10)).pack(anchor="w")

        self.dataset_preview = tk.Text(mid_frame, height=10, wrap="none",
                                       font=("Consolas", 9))
        self.dataset_preview.pack(fill=tk.BOTH, expand=False)
        self.dataset_preview.configure(state="disabled")

        # Разделитель
        ttk.Separator(self, orient=tk.HORIZONTAL).pack(fill=tk.X, padx=10, pady=5)

        # Поле ключа
        key_frame = tk.Frame(self, bg="#f5f5f5")
        key_frame.pack(fill=tk.X, padx=10, pady=5)

        tk.Label(key_frame, text="Ключ (строка, будет приведена к 128 бит):",
                 bg="#f5f5f5", font=("Arial", 11)).pack(side=tk.LEFT)
        self.entry_key = tk.Entry(key_frame, width=40, show="*", font=("Arial", 11))
        self.entry_key.pack(side=tk.LEFT, padx=10)
        self.entry_key.insert(0, "test_key_128")

        # Поля ввода/вывода
        text_frame = tk.Frame(self, bg="#f5f5f5")
        text_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        left_frame = tk.Frame(text_frame, bg="#f5f5f5")
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        tk.Label(left_frame, text="Входной текст (открытый или шифртекст Base64):",
                 bg="#f5f5f5", font=("Arial", 10)).pack(anchor="w")
        self.text_in = tk.Text(left_frame, wrap="word", font=("Consolas", 10))
        self.text_in.pack(fill=tk.BOTH, expand=True)

        right_frame = tk.Frame(text_frame, bg="#f5f5f5")
        right_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(10, 0))

        tk.Label(right_frame, text="Результат:",
                 bg="#f5f5f5", font=("Arial", 10)).pack(anchor="w")
        self.text_out = tk.Text(right_frame, wrap="word", font=("Consolas", 10))
        self.text_out.pack(fill=tk.BOTH, expand=True)

        # Кнопки действий
        btn_frame = tk.Frame(self, bg="#f5f5f5")
        btn_frame.pack(fill=tk.X, padx=10, pady=10)

        btn_encrypt = tk.Button(btn_frame, text="Зашифровать",
                                command=self.on_encrypt, bg="#4caf50", fg="white", width=20)
        btn_encrypt.pack(side=tk.LEFT)

        btn_decrypt = tk.Button(btn_frame, text="Расшифровать",
                                command=self.on_decrypt, bg="#f44336", fg="white", width=20)
        btn_decrypt.pack(side=tk.LEFT, padx=10)

        btn_clear = tk.Button(btn_frame, text="Очистить поля",
                              command=self.clear_texts, bg="#9e9e9e", fg="white", width=15)
        btn_clear.pack(side=tk.LEFT)

        # Статус
        self.status_var = tk.StringVar(value="Готово")
        status_bar = tk.Label(self, textvariable=self.status_var, anchor="w",
                              bg="#e0e0e0", font=("Arial", 9))
        status_bar.pack(fill=tk.X, side=tk.BOTTOM)

        # Автоматически загрузим первый датасет при старте
        self.load_dataset()

    # --------- Работа с датасетами ---------

    def load_dataset(self) -> None:
        """Загрузка выбранного Excel-датасета и отображение первых строк."""
        name = self.dataset_var.get()
        filename = DATASETS.get(name)
        if not filename:
            messagebox.showerror("Ошибка", "Не найден путь к датасету.")
            return

        path = os.path.join(DATASETS_DIR, filename)
        if not os.path.exists(path):
            messagebox.showerror("Ошибка", f"Файл {filename} не найден в каталоге datasets.")
            return

        try:
            df = pd.read_excel(path)
            self.current_df = df
            preview = df.head(10).to_string(index=False)
            self.dataset_preview.configure(state="normal")
            self.dataset_preview.delete("1.0", tk.END)
            self.dataset_preview.insert(tk.END, preview)
            self.dataset_preview.configure(state="disabled")
            self.status_var.set(f"Загружен датасет '{name}', строк: {len(df)}")
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось загрузить датасет: {e}")
            self.status_var.set("Ошибка загрузки датасета")

    def copy_dataset_to_text(self) -> None:
        """Копировать весь датасет в поле входного текста как таблицу."""
        if self.current_df is None:
            messagebox.showwarning("Внимание", "Сначала загрузите датасет.")
            return
        text = self.current_df.to_string(index=False)
        self.text_in.delete("1.0", tk.END)
        self.text_in.insert(tk.END, text)
        self.status_var.set("Датасет скопирован в поле входного текста")

    # --------- Криптооперации ---------

    def on_encrypt(self) -> None:
        key = self.entry_key.get().strip()
        data = self.text_in.get("1.0", tk.END).rstrip("\n")
        if not key or not data:
            messagebox.showwarning("Внимание", "Введите ключ и текст для шифрования.")
            return
        try:
            result = encrypt_message(data, key)
            self.text_out.delete("1.0", tk.END)
            self.text_out.insert(tk.END, result)
            self.status_var.set("Текст успешно зашифрован")
        except Exception as e:
            messagebox.showerror("Ошибка", f"Ошибка шифрования: {e}")
            self.status_var.set("Ошибка шифрования")

    def on_decrypt(self) -> None:
        key = self.entry_key.get().strip()
        data = self.text_in.get("1.0", tk.END).strip()
        if not key or not data:
            messagebox.showwarning("Внимание", "Введите ключ и зашифрованный текст (Base64).")
            return
        try:
            result = decrypt_message(data, key)
            self.text_out.delete("1.0", tk.END)
            self.text_out.insert(tk.END, result)
            self.status_var.set("Текст успешно расшифрован")
        except Exception as e:
            messagebox.showerror("Ошибка", f"Ошибка расшифрования: {e}")
            self.status_var.set("Ошибка расшифрования")

    def clear_texts(self) -> None:
        self.text_in.delete("1.0", tk.END)
        self.text_out.delete("1.0", tk.END)
        self.status_var.set("Поля очищены")


if __name__ == "__main__":
    app = CryptoApp()
    app.mainloop()
