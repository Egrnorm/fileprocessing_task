import json
import sys
import threading
from datetime import datetime,timedelta
from time import sleep
from typing import List, Optional, Dict
import minio.error
import requests
import os
import py7zr
from minio import Minio
import yara
from airflow import DAG
from airflow.operators.python import PythonOperator

MINIO_URL: str = "localhost:9000"
MINIO_ACCESS_KEY: str = "admin"
MINIO_SECRET_KEY: str = "upupuch123"
MINIO_BUCKET_NAME: str = "virussign"
MINIO_BUCKET_REPORTS: str = "scan-reports"



def parse_data(date_input: str) -> Optional[List[str]]:
    date_parts: List[str] = date_input.split('.')
    year: str = date_parts[0]
    month: str = date_parts[1]
    day: str = date_parts[2]
    date_array: List[str] = [year, month, day]
    try:
        parsed_data = datetime.strptime(date_input, "%Y.%m.%d").date()
        print(f"Вы ввели дату: {parsed_data}")
        return date_array
    except ValueError:
        print("[ERROR] Введите дату в правильном формате (ГГГГ.ММ.ДД)")


def compile_url_and_filename(date_array: List[str]) -> (str,str):
    year: str = date_array[0]
    month: str = date_array[1]
    day: str = date_array[2]

    url: str = f"https://samples.vx-underground.org/Samples/VirusSign%20Collection/{year}.{month}/Virussign.{year}.{month}.{day}.7z"
    archive_name: str = f"Virussign.{year}.{month}.{day}.7z"
    return url, archive_name

def animation(stop_event: threading.Event, state: int) -> None:
    animation: List[str]
    index: int = 0

    if state == 0:
        animation = ["Скачивание файла[\\]", "Скачивание файла[|]", "Скачивание файла[/]", "Скачивание файла[—]"]
    elif state == 1:
        animation = ["Разархивирование[\\]", "Разархивирование[|]", "Разархивирование[/]", "Разархивирование[—]"]
    elif state == 2:
        animation = ["Cкачивание архива[\\]", "Cкачивание архива[|]", "Cкачивание архива[/]", "Cкачивание архива[—]"]
    else:
        return

    while not stop_event.is_set():
        sys.stdout.write(f"\r{animation[index]}")
        sys.stdout.flush()
        index = (index + 1) % len(animation)
        sleep(0.3)


def download(url: str, destination_path: str, end_message: str = "", show_animation: bool = True, anim_type: int = 0) -> Optional[bool]:
    if os.path.exists(destination_path):
        print(f"Файл {destination_path} уже существует. Пропуск скачивания.")
        return

    try:
        response = requests.get(url, stream=True)
        if response.status_code == 404:
            print("Такого файла не существует")
        else:
            with open(destination_path, "wb") as file:
                if show_animation == True:
                    stop_event = threading.Event()
                    animation_thread = threading.Thread(target=animation, args=(stop_event, anim_type))
                    animation_thread.start()

                for chunk in response.iter_content(chunk_size=1024):
                    file.write(chunk)

                if show_animation == True:
                    stop_event.set()
                    animation_thread.join()
            print(f"\r{end_message}", end="")

    except requests.exceptions.HTTPError as http_error:
        print(f"\rОшибка http: {http_error}")
        sys.stdout.flush()
    except requests.exceptions.ConnectionError:
        print("\rОшибка подключения. Проверьте интернет")
        sys.stdout.flush()
    except requests.exceptions.Timeout:
        print("\rИстекло время ожидания запроса")
        sys.stdout.flush()
    except requests.exceptions.RequestException as error:
        print(f"\rОшибка запроса: {error}", end="")
        sys.stdout.flush()


def download_archive(url: str, archive_name: str) -> Optional[bool]:
    if os.path.exists(archive_name):
        print(f"Файл {archive_name} уже существует. Пропуск скачивания.")
        return
    end_message: str = "Архив успешно скачан\n"
    download(url, archive_name, end_message, anim_type=2)

def download_yar_rules(destination_path: str, rules_url_ghAPI: str = "https://api.github.com/repos/kevoreilly/CAPEv2/contents/data/yara/CAPE") -> None:
    if os.path.exists(destination_path):
        print(f"\nФайл {destination_path} уже существует. Пропуск скачивания.")
        return
    os.makedirs(destination_path, exist_ok=True)

    response = requests.get(rules_url_ghAPI)
    response.raise_for_status()
    files_json = response.json()

    for file_info in files_json:
        if file_info["type"] == "file" and file_info["name"].endswith(".yar"):
            file_url: str = file_info["download_url"]
            file_path: str = os.path.join(destination_path, file_info["name"])
            sys.stdout.write("\r" + " " * os.get_terminal_size().columns + "\r")
            print(f"\rСкачивание правила: {file_info['name']}", end="")
            sys.stdout.flush()
            download(file_url, file_path, show_animation=False)
    print(f"Все YAR файлы скачались в папку {os.path.abspath(destination_path)}")



def unzip(archive_name: str) -> None:
    folder_name = archive_name[:-3]
    if os.path.exists(folder_name):
        print(f"Файл {folder_name} уже существует. Пропуск скачивания.")
        return

    password = "infected"
    folder_name = os.path.splitext(archive_name)[0]

    try:
        with py7zr.SevenZipFile(archive_name, mode="r", password=password) as archive:

            stop_event = threading.Event()
            animation_thread = threading.Thread(target=animation, args=(stop_event, 1))
            animation_thread.start()

            archive.extractall(path=folder_name)

        stop_event.set()
        animation_thread.join()
        print(f"\rСодержимое архива успешно извлечено по адресу {os.path.abspath(folder_name)}")
        sys.stdout.flush()
    except py7zr.exceptions.Bad7zFile:
        print("\rФайл или повреждён или не является архивом")
        sys.stdout.flush()
    except py7zr.exceptions.PasswordRequired:
        print("\rНеверный пароль")
        sys.stdout.flush()

def upload(file_path: str, MINIO_BUCKET: str) -> None:
    client = Minio(MINIO_URL, MINIO_ACCESS_KEY, MINIO_SECRET_KEY, secure=False)

    if not client.bucket_exists(MINIO_BUCKET):
        client.make_bucket(MINIO_BUCKET)

    object_name: str = os.path.basename(file_path)

    if object_exist(client, MINIO_BUCKET, object_name):
        sys.stdout.write("\r" + " " * os.get_terminal_size().columns + "\r")
        print(f"\rФайл {object_name} уже существует в бакете {MINIO_BUCKET}. Пропуск загрузки.", end="")
        sys.stdout.flush()
        return

    try:
        client.fput_object(bucket_name=MINIO_BUCKET, object_name=object_name, file_path=file_path)
        sys.stdout.write("\r" + " " * os.get_terminal_size().columns + "\r")
        print(f"\rФайл загружен как {object_name} в бакет {MINIO_BUCKET}", end="")
        sys.stdout.flush()
    except minio.error.S3Error as s3_error:
        print(f"\rОшибка загрузки файла {file_path}: {s3_error}", end="")
        sys.stdout.flush()


def upload_folder(folder_name: str) -> None:
    for file in os.listdir(folder_name):
        file_path = os.path.join(folder_name, file)

        upload(file_path, MINIO_BUCKET_NAME)
    sys.stdout.write("\r" + " " * os.get_terminal_size().columns + "\r")
    print(f"Папка {folder_name} была загружена в бакет {MINIO_BUCKET_NAME} вместе с её содержимым", end="")

def object_exist(client: Minio, MINIO_BUCKET: str, object_name: str) -> bool:
    try:
        client.stat_object(MINIO_BUCKET, object_name)
        return True
    except minio.error.S3Error as error:
        if error.code == "NoSuchKey":
            return False
        else:
            raise

def compile_yar_rules(rulesfolder_path: str) -> yara.Rules:
    rule_paths: Dict[str, str] = {}
    for file_name in os.listdir(rulesfolder_path):
        if file_name.endswith(".yar"):
            file_path: str = os.path.join(rulesfolder_path, file_name)
            rule_paths[file_name] = file_path
    if not rule_paths:
        raise ValueError("В указанной папке нету YARA правил")

    return yara.compile(filepaths=rule_paths)

def scan_files(rules: yara.Rules, targetfolder_path: str, date_array: List[str]) -> str:
    year: str = date_array[0]
    month: str = date_array[1]
    day: str = date_array[2]
    output_file: str = f"scan_report-{year}-{month}-{day}.json"

    scan_results = []
    for file_name in os.listdir(targetfolder_path): #цикл перебора файлов вирусных для yar правил
        file_path: str = os.path.join(targetfolder_path, file_name)
        sys.stdout.write("\r" + " " * os.get_terminal_size().columns + "\r")
        print(f"\rСканируем файл: {file_path}", end="")
        sys.stdout.flush()
        try:
            matches = rules.match(file_path)

            if matches:
                match_details = []

                for match in matches:
                    rule_info= {
                        "rule": match.rule,
                        "tags": match.tags,
                        "meta": match.meta,
                    }
                    match_details.append(rule_info)
                scan_results.append({"file": file_path, "matches": match_details})
        except yara.Error as e:
            print(f"Ошибка при сканировании {file_path}: {e}")

    with open(output_file, "w") as file:
        json.dump(scan_results, file, indent=4)
    sys.stdout.write("\r" + " " * os.get_terminal_size().columns + "\r")
    print(f"\rРезультаты сканирования сохранены в файл {output_file}")
    return output_file

def start() -> None:
    # Подготовка переменных
    date_input: str = input("Введите дату в формате ГГГГ.ММ.ДД:\n")
    date_array: List[str] = parse_data(date_input)
    year: str = date_array[0]
    month: str = date_array[1]
    day: str = date_array[2]
    url_archive: str
    archive_name: str
    url_archive, archive_name = compile_url_and_filename(date_array)  # получение юрл архива для скачивания и получение названия архива
    folder_name: str = archive_name[:-3]  # будущая папка разархивированного архива
    scan_report: str = f"scan_report-{year}-{month}-{day}.json"  # будущий отчёт
    yara_rules_folder: str = "yara-rules"  # папка с yara правилами

    # Скачивание архива и распаковка
    download_archive(url_archive, archive_name)
    unzip(archive_name)

    # Загрузка папки в MinIO S3
    upload_folder(folder_name)
    # Скачивание yar правил с гитхаба (можно если чё передать api ссыоку в необязательный параметр rules_url_ghAPI)
    download_yar_rules(yara_rules_folder)  # тут передаю папку которая создастся, в которой будет загружены yar правила

    # Компиляция правил, сканирование файлов и загрузка отчёта в MinIO S3
    yara_rules: yara.Rules = compile_yar_rules(yara_rules_folder)
    scan_report: str = scan_files(yara_rules, folder_name, date_array)
    upload(scan_report, MINIO_BUCKET_REPORTS)
    print("\n")




start()











