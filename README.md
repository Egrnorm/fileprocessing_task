### Запуск  
1. ##### Клонируем репозиторий:  
- `https://github.com/Egrnorm/fileprocessing_task.git`  
2. ##### Переходим в папку:  
- `cd fileprocessing_task`  
3. ##### Скачиваем poetry, если не установлен:  
- `curl -sSL https://install.python-poetry.org | python3`
4. ##### Устанавливаем зависимости:  
- `poetry install`
5. ##### Инициализируем базу данных для airflow:
- `poetry run airflow db init`
6. ##### Создаём пользователя airflow. Например:
- `poetry run airflow users create \
  --username admin \
  --password admin \
  --firstname YourName \
  --lastname YourLastName \
  --role Admin \
  --email admin@example.com`
7. ##### Узнаём в какой папке хранятся dags в airflow:
- `poetry run airflow config get-value core dags_folder`
8. ##### Переносим dag.py в папку, где хранятся dags в airflow:
- `mv file_processing_task/dag.py [путь до папки]`
- В моём случае это:
- `mv file_processing_task/dag.py ~/airflow/dags`
9. ##### Запускаем docker-compose для MinIO:  
- `sudo docker-compose up -d`  
10. ##### Запускаем веб-сервер airflow:  
- `poetry run airflow webserver`
11. ##### Запускаем планировщик airflow:
- `poetry run airflow scheduler`
---
### Немного о проекте  
##### Этот проект представляет собой приложение, работающее с airflow, которое переодически скачивает файлы за указанную дату, в соответсвии с расписанием, с сайта [VX-Underground](https://vx-underground.org/), загружает их в S3 хранилище MinIO, сканирует скаченные файлы с помощью [YARA правил](https://github.com/kevoreilly/CAPEv2/tree/master/data/yara/CAPE) и загружает json отчёт в S3 хранилище MinIO  
---
### Логин и пароль для доступа к веб-интерфейсу MinIO  
- `admin:upupuch123`  
- Для того, чтобы поставить свой логин/пароль нужно поменять параметры в docker-compose.yml:  
  - `MINIO_ROOT_USER=admin`  
  - `MINIO_ROOT_PASSWORD=upupuch123`  
- И поменять в файле core.py переменные:
  - `MINIO_ACCESS_KEY: str = "admin"`  
  - `MINIO_SECRET_KEY: str = "upupuch123"`
---  
### Веб-интерфейс MinIO доступен по адресу:  
- `localhost:9001`  
---  
### Веб-интерфейс apache-airflow доступен по адресу:
- `localhost:8080`
- Логин и пароль для доступа:
- `admin:admin`
