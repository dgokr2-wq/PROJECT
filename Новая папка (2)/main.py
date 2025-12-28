"""
GUI-приложение на tkinter для демонстрации работы учебного шифра SAFER K-128.
Возможности:
- выбор одного из подготовленных Excel-датасетов;
- просмотр его содержимого (первые строки);
- копирование датасета в поле входного текста;
- шифрование и расшифрование текста по нажатию кнопок.
"""

import os  # Работа с путями к файлам и папкам
import tkinter as tk  
from tkinter import ttk, messagebox  # Виджеты ttk и стандартные диалоговые окна
import pandas as pd  # Чтение и обработка Excel-датасетов

from safer_cipher import encrypt_message, decrypt_message  # Импорт функций шифрования и дешифрования

# Базовая директория проекта (папка, где находится данный main.py)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
# Папка, в которой хранятся тестовые Excel-датасеты
DATASETS_DIR = os.path.join(BASE_DIR, "datasets")

# Словарь с «читаемыми» названиями датасетов и соответствующими именами файлов
DATASETS = {
    "Пользователи (users)": "dataset_users.xlsx",
    "CMDB (cmdb)": "dataset_cmdb.xlsx",
    "Тикеты ITSM (itsm_tickets)": "dataset_itsm_tickets.xlsx",
}


class CryptoApp(tk.Tk):
    """Главный класс GUI-приложения, наследуется от tk.Tk."""

    def __init__(self) -> None:
        # Инициализация базового окна tkinter
        super().__init__()
        # Заголовок окна
        self.title("Учебное приложение шифрования SAFER K-128")
        # Фиксированный размер окна (ширина x высота)
        self.geometry("1000x700")
        # Цвет фона для единообразного стиля
        self.configure(bg="#f5f5f5")

        # Текущий загруженный датафрейм (датасет) хранится здесь
        self.current_df = None
        # Вынесенная в отдельный метод сборка интерфейса
        self._build_ui()

    def _build_ui(self) -> None:
        """Создание всех элементов интерфейса и размещение их в окне."""

        # Верхняя панель: выбор датасета и кнопки работы с ним
        top_frame = tk.Frame(self, bg="#f5f5f5")
        top_frame.pack(fill=tk.X, padx=10, pady=10)

        # Подпись к выпадающему списку с датасетами
        tk.Label(
            top_frame,
            text="Выбор набора данных (Excel):",
            bg="#f5f5f5",
            font=("Arial", 11, "bold"),
        ).pack(side=tk.LEFT)

        # Переменная, в которой хранится выбранный в Combobox датасет
        self.dataset_var = tk.StringVar(value=list(DATASETS.keys())[0])

        # Combobox для выбора одного из трёх Excel-датасетов
        dataset_combo = ttk.Combobox(
            top_frame,
            textvariable=self.dataset_var,
            values=list(DATASETS.keys()),
            state="readonly",
            width=40,
        )
        dataset_combo.pack(side=tk.LEFT, padx=10)
        # При смене выбранного элемента автоматически подгружаем датасет
        dataset_combo.bind("<<ComboboxSelected>>", lambda e: self.load_dataset())

        # Кнопка явной загрузки датасета (перечитать файл)
        btn_load = tk.Button(
            top_frame,
            text="Загрузить датасет",
            command=self.load_dataset,
            bg="#2b5797",
            fg="white",
        )
        btn_load.pack(side=tk.LEFT, padx=5)

        # Кнопка копирования содержимого датасета в поле входного текста
        btn_copy = tk.Button(
            top_frame,
            text="Копировать датасет в текст",
            command=self.copy_dataset_to_text,
            bg="#4caf50",
            fg="white",
        )
        btn_copy.pack(side=tk.LEFT, padx=5)

        # Средняя панель: окно предпросмотра выбранного датасета
        mid_frame = tk.Frame(self, bg="#f5f5f5")
        mid_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))

        # Подпись над полем предпросмотра
        tk.Label(
            mid_frame,
            text="Предпросмотр датасета (первые строки):",
            bg="#f5f5f5",
            font=("Arial", 10),
        ).pack(anchor="w")

        # Текстовое поле, в которое выводятся первые строки Excel-таблицы
        self.dataset_preview = tk.Text(
            mid_frame,
            height=10,
            wrap="none",
            font=("Consolas", 9),
        )
        self.dataset_preview.pack(fill=tk.BOTH, expand=False)
        # По умолчанию поле только для чтения (чтобы пользователь не правил предпросмотр)
        self.dataset_preview.configure(state="disabled")

        # Горизонтальный разделитель между предпросмотром и зоной шифрования/дешифрования
        ttk.Separator(self, orient=tk.HORIZONTAL).pack(fill=tk.X, padx=10, pady=5)

        # Блок ввода ключа шифрования
        key_frame = tk.Frame(self, bg="#f5f5f5")
        key_frame.pack(fill=tk.X, padx=10, pady=5)

        # Подпись к полю ключа (строка будет приведена к 128 бит внутри модуля)
        tk.Label(
            key_frame,
            text="Ключ (строка, будет приведена к 128 бит):",
            bg="#f5f5f5",
            font=("Arial", 11),
        ).pack(side=tk.LEFT)

        # Поле ввода ключа; символы скрываются (show="*")
        self.entry_key = tk.Entry(key_frame, width=40, show="*", font=("Arial", 11))
        self.entry_key.pack(side=tk.LEFT, padx=10)
        # Значение по умолчанию для удобства тестирования
        self.entry_key.insert(0, "test_key_128")

        # Основная зона с двумя текстовыми полями: входной текст и результат
        text_frame = tk.Frame(self, bg="#f5f5f5")
        text_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        # Левая часть: поле для ввода исходного текста или шифртекста Base64
        left_frame = tk.Frame(text_frame, bg="#f5f5f5")
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        tk.Label(
            left_frame,
            text="Входной текст (открытый или шифртекст Base64):",
            bg="#f5f5f5",
            font=("Arial", 10),
        ).pack(anchor="w")

        # Многострочное поле для ввода/вставки текста
        self.text_in = tk.Text(left_frame, wrap="word", font=("Consolas", 10))
        self.text_in.pack(fill=tk.BOTH, expand=True)

        # Правая часть: поле, куда выводится результат шифрования/дешифрования
        right_frame = tk.Frame(text_frame, bg="#f5f5f5")
        right_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(10, 0))

        tk.Label(
            right_frame,
            text="Результат:",
            bg="#f5f5f5",
            font=("Arial", 10),
        ).pack(anchor="w")

        # Многострочное поле для отображения результата операций
        self.text_out = tk.Text(right_frame, wrap="word", font=("Consolas", 10))
        self.text_out.pack(fill=tk.BOTH, expand=True)

        # Нижняя панель с кнопками действий над текстом
        btn_frame = tk.Frame(self, bg="#f5f5f5")
        btn_frame.pack(fill=tk.X, padx=10, pady=10)

        # Кнопка запуска шифрования (использует encrypt_message)
        btn_encrypt = tk.Button(
            btn_frame,
            text="Зашифровать",
            command=self.on_encrypt,
            bg="#4caf50",
            fg="white",
            width=20,
        )
        btn_encrypt.pack(side=tk.LEFT)

        # Кнопка запуска расшифрования (использует decrypt_message)
        btn_decrypt = tk.Button(
            btn_frame,
            text="Расшифровать",
            command=self.on_decrypt,
            bg="#f44336",
            fg="white",
            width=20,
        )
        btn_decrypt.pack(side=tk.LEFT, padx=10)

        # Кнопка очистки обоих текстовых полей
        btn_clear = tk.Button(
            btn_frame,
            text="Очистить поля",
            command=self.clear_texts,
            bg="#9e9e9e",
            fg="white",
            width=15,
        )
        btn_clear.pack(side=tk.LEFT)

        # Строка статуса внизу окна для отображения подсказок и результатов
        self.status_var = tk.StringVar(value="Готово")
        status_bar = tk.Label(
            self,
            textvariable=self.status_var,
            anchor="w",
            bg="#e0e0e0",
            font=("Arial", 9),
        )
        status_bar.pack(fill=tk.X, side=tk.BOTTOM)

        # Автоматически загружаем первый датасет при старте приложения
        self.load_dataset()

    # --------- Работа с датасетами ---------

    def load_dataset(self) -> None:
        """Загрузка выбранного Excel-датасета и отображение первых строк в preview."""
        name = self.dataset_var.get()  # Человеко-читаемое имя набора
        filename = DATASETS.get(name)  # Фактическое имя файла по словарю DATASETS
        if not filename:
            messagebox.showerror("Ошибка", "Не найден путь к датасету.")
            return

        # Формируем полный путь к Excel-файлу в подкаталоге datasets
        path = os.path.join(DATASETS_DIR, filename)
        if not os.path.exists(path):
            messagebox.showerror("Ошибка", f"Файл {filename} не найден в каталоге datasets.")
            return

        try:
            # Читаем Excel-файл целиком в DataFrame
            df = pd.read_excel(path)
            self.current_df = df  # Сохраняем загруженный датасет в атрибут
            # Берём первые 10 строк для отображения в окне предпросмотра
            preview = df.head(10).to_string(index=False)
            self.dataset_preview.configure(state="normal")
            self.dataset_preview.delete("1.0", tk.END)
            self.dataset_preview.insert(tk.END, preview)
            self.dataset_preview.configure(state="disabled")
            # В статусной строке показываем, сколько всего строк загружено
            self.status_var.set(f"Загружен датасет '{name}', строк: {len(df)}")
        except Exception as e:
            # При ошибке чтения файла выводим сообщение пользователю
            messagebox.showerror("Ошибка", f"Не удалось загрузить датасет: {e}")
            self.status_var.set("Ошибка загрузки датасета")

    def copy_dataset_to_text(self) -> None:
        """Копировать весь текущий датасет в левое текстовое поле."""
        # Если датасет ещё не загружен, предупреждаем пользователя
        if self.current_df is None:
            messagebox.showwarning("Внимание", "Сначала загрузите датасет.")
            return
        # Переводим DataFrame в строку в табличном формате
        text = self.current_df.to_string(index=False)
        # Очищаем поле ввода и вставляем туда текстовую таблицу
        self.text_in.delete("1.0", tk.END)
        self.text_in.insert(tk.END, text)
        # Обновляем строку статуса
        self.status_var.set("Датасет скопирован в поле входного текста")

    # --------- Криптооперации ---------

    def on_encrypt(self) -> None:
        """Обработчик кнопки «Зашифровать»."""
        # Читаем ключ из соответствующего поля
        key = self.entry_key.get().strip()
        # Читаем весь текст из левого многострочного поля
        data = self.text_in.get("1.0", tk.END).rstrip("\n")
        # Проверка: и ключ, и текст должны быть непустыми
        if not key or not data:
            messagebox.showwarning("Внимание", "Введите ключ и текст для шифрования.")
            return
        try:
            # Вызов функции шифрования из модуля safer_cipher
            result = encrypt_message(data, key)
            # Очищаем правое поле и выводим туда шифртекст (Base64)
            self.text_out.delete("1.0", tk.END)
            self.text_out.insert(tk.END, result)
            # Обновляем статус об успешном шифровании
            self.status_var.set("Текст успешно зашифрован")
        except Exception as e:
            # В случае любой ошибки выводим окно с описанием
            messagebox.showerror("Ошибка", f"Ошибка шифрования: {e}")
            self.status_var.set("Ошибка шифрования")

    def on_decrypt(self) -> None:
        """Обработчик кнопки «Расшифровать»."""
        # Считываем ключ из поля ввода
        key = self.entry_key.get().strip()
        # Считываем предполагаемый шифртекст (Base64) из левого поля
        data = self.text_in.get("1.0", tk.END).strip()
        # Если нет ключа или шифртекста — предупреждаем пользователя
        if not key or not data:
            messagebox.showwarning(
                "Внимание",
                "Введите ключ и зашифрованный текст (Base64).",
            )
            return
        try:
            # Попытка расшифровать данные через safer_cipher.decrypt_message
            result = decrypt_message(data, key)
            # Выводим результат в правое поле
            self.text_out.delete("1.0", tk.END)
            self.text_out.insert(tk.END, result)
            # Сообщаем в строке статуса об успешном восстановлении текста
            self.status_var.set("Текст успешно расшифрован")
        except Exception as e:
            # При ошибке (неправильный Base64, неверный ключ и т.п.) выводим сообщение
            messagebox.showerror("Ошибка", f"Ошибка расшифрования: {e}")
            self.status_var.set("Ошибка расшифрования")

    def clear_texts(self) -> None:
        """Очистка обоих текстовых полей и сброс статуса."""
        # Полностью очищаем левое поле ввода
        self.text_in.delete("1.0", tk.END)
        # Полностью очищаем правое поле результата
        self.text_out.delete("1.0", tk.END)
        # Обновляем строку статуса
        self.status_var.set("Поля очищены")


# Точка входа в программу: создаётся экземпляр окна и запускается главный цикл событий
if __name__ == "__main__":
    app = CryptoApp()  # Инициализация приложения
    app.mainloop()     # Запуск обработки событий tkinter

