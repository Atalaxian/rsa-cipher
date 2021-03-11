import secrets
import random
import sys
from typing import Tuple

from PyQt5 import QtCore
from PyQt5.QtWidgets import QApplication, QWidget, QFileDialog
from error_window import Ui_widget
from main_window import Ui_Form


class MyException(Exception):
    text = None

    def __init__(self, text) -> None:
        super().__init__()
        self.text = text


class ErrorWindow(QWidget, Ui_widget):
    def __init__(self, text) -> None:
        super().__init__()
        self.setupUi(self)
        self.setWindowTitle('Ошибка')
        self.error_label.setText(text)


def gcd_extended(a, b) -> Tuple[int, int, int]:
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = gcd_extended(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y


class RSA:
    text = None
    start_prime_number = None
    open_key = None
    close_key = None

    def __init__(self, text, open_key=None, close_key=None, start_prime_number=1000) -> None:
        self.text = text
        self.open_key = open_key
        self.close_key = close_key
        self.start_prime_number = start_prime_number

    def encode_rsa(self) -> str:
        prime_numbers = self.get_prime_number(self.start_prime_number)
        p = secrets.choice(prime_numbers)
        prime_numbers.remove(p)
        q = secrets.choice(prime_numbers)
        n = p * q
        eyler = (p - 1) * (q - 1)
        list_e = list()
        for x in range(2, eyler + 1):
            if self.is_prime(x):
                gcd, xe, y = gcd_extended(x, eyler)
                if gcd == 1:
                    list_e.append(x)
                    if len(list_e) == 10:
                        break
        e = 0
        d = 0
        random.shuffle(list_e)
        for elem in list_e:
            gcd, x, y = gcd_extended(elem, eyler)
            if gcd == 1 and x > 0:
                d = x
                e = elem
                break
        self.open_key = (e, n)
        self.close_key = (d, n)
        encode_text = ''
        for x, elem in enumerate(self.text):
            if x != 0:
                encode_text += ','
            intelem = ord(elem)
            to_degree = intelem ** e
            code_int = to_degree % n
            encode_text += str(code_int)
        return encode_text

    def decode_rsa(self) -> str:
        self.close_key = self.close_key.replace('{', '')
        self.close_key = self.close_key.replace('}', '')
        self.close_key = self.close_key.replace('(', '')
        self.close_key = self.close_key.replace(')', '')
        keys = self.close_key.split(',')
        d, n = [int(x) for x in keys]
        decode_text = ''
        for elem in self.text:
            to_degree = int(elem) ** d
            mod = to_degree % n
            code_char = chr(mod)
            decode_text += str(code_char)
        return decode_text

    @staticmethod
    def get_prime_number(n, search_segment=1000) -> list:
        a = range(n + search_segment + 1)
        a = list(a)
        a[1] = 0
        prev_result_list = []
        i = 2
        while i <= (n + search_segment):
            if a[i] != 0:
                prev_result_list.append(a[i])
                for j in range(i, n + search_segment + 1, i):
                    a[j] = 0
            i += 1
        result_list = [x for x in prev_result_list if x >= n]
        return result_list

    @staticmethod
    def is_prime(number) -> bool:
        n = number
        counter = 0
        for i in range(1, n + 1):
            if n % i == 0:
                counter += 1
        return True if counter == 2 else False

    def get_open_key(self) -> tuple:
        return self.open_key

    def get_close_key(self) -> tuple:
        return self.close_key


class MainWindow(QWidget, Ui_Form):
    error_window = None

    def __init__(self) -> None:
        super().__init__()
        self.setupUi(self)
        self.setWindowTitle('Шифр RSA')
        self.code_text.clicked.connect(self.encode_text_rsa)
        self.save_code_text.clicked.connect(self.save_code_file)
        self.load_text_for_code.clicked.connect(self.load_code_file)
        self.load_text_for_decode.clicked.connect(self.load_decode_file)
        self.save_decode_text.clicked.connect(self.save_decode_file)
        self.decode_text.clicked.connect(self.decode_text_rsa)
        self.min_count.setText('100')

    @QtCore.pyqtSlot()
    def encode_text_rsa(self) -> None:
        text = self.code_start.toPlainText()
        if len(text) == 0:
            self.error_window = ErrorWindow('Текст для дешифрования отсутствует.')
            self.error_window.show()
            return
        try:
            number = int(self.min_count.text())
        except ValueError:
            self.error_window = ErrorWindow('Не удалось получить минимальное число.')
            self.error_window.show()
            return
        coder = RSA(text=text, start_prime_number=number)
        encode_text = coder.encode_rsa()
        open_key = coder.get_open_key()
        close_key = coder.get_close_key()
        self.code_open_key.setText(str(open_key))
        self.code_closed_key.setText(str(close_key))
        self.code_end.setText(encode_text)

    @QtCore.pyqtSlot()
    def decode_text_rsa(self) -> None:
        text = self.decode_start.toPlainText()
        text = text.split(',')
        text = [int(x) for x in text]
        if len(text) == 0:
            self.error_window = ErrorWindow('Текст для дешифрования отсутствует.')
            self.error_window.show()
            return
        key = self.decode_closed_key.text()
        if len(key) == 0:
            self.error_window = ErrorWindow('Ключ для дешифрования отсутствует.')
            self.error_window.show()
            return
        decoder = RSA(text=text, close_key=key)
        decode_text = decoder.decode_rsa()
        self.decode_end.setText(decode_text)

    @QtCore.pyqtSlot()
    def load_code_file(self) -> None:
        filegialog = QFileDialog.getOpenFileUrl(self, 'Загрузка',
                                                filter=str("Текстовый файл (*.txt)"))
        if filegialog[0]:
            file_path = filegialog[0].toLocalFile()
            if file_path == '':
                return
            file = open(file_path, 'r')
            text = file.read()
            self.code_start.setText(text)

    @QtCore.pyqtSlot()
    def load_decode_file(self) -> None:
        filegialog = QFileDialog.getOpenFileUrl(self, 'Загрузка',
                                                filter=str("Текстовый файл (*.txt)"))
        if filegialog[0]:
            file_path = filegialog[0].toLocalFile()
            if file_path == '':
                return
            file = open(file_path, 'r')
            text = file.read()
            self.decode_start.setText(text)

    @QtCore.pyqtSlot()
    def save_code_file(self) -> None:
        text = self.code_end.toPlainText()
        if len(text) == 0:
            self.error_window = ErrorWindow('Нет закодированных данных')
            self.error_window.show()
            return
        filegialog = QFileDialog.getSaveFileUrl(self, 'Сохранение',
                                                filter=str("Текстовый файл (*.txt)"))
        if filegialog[0]:
            file_path = filegialog[0].toLocalFile()
            if file_path == '':
                return
            file = open(file_path, 'w')
            file.write(text)

    @QtCore.pyqtSlot()
    def save_decode_file(self) -> None:
        text = self.decode_end.toPlainText()
        if len(text) == 0:
            self.error_window = ErrorWindow('Нет декодированных данных')
            self.error_window.show()
            return
        filegialog = QFileDialog.getSaveFileUrl(self, 'Сохранение',
                                                filter=str("Текстовый файл (*.txt)"))
        if filegialog[0]:
            file_path = filegialog[0].toLocalFile()
            if file_path == '':
                return
            file = open(file_path, 'w')
            file.write(text)


if __name__ == '__main__':
    qapp = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(qapp.exec())
