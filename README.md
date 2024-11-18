### Запуск  
1. ##### Клонируем репозиторий:  
- `git clone https://github.com/Egrnorm/fileprocessing_task.git`  
2. ##### Переходим в папку:  
- `cd fileprocessing_task`  
3. ##### Скачиваем poetry, если не установлен:  
- `curl -sSL https://install.python-poetry.org | python3`
4. ##### Устанавливаем зависимости:  
- `poetry install`  
5. ##### Запускаем docker-compose для MinIO:  
- `sudo docker-compose up -d`  
6. ##### Запускаем:  
- `poetry run python -m file_processing_task.core`  
---
### Немного о проекте  
##### Этот проект представляет собой консольную утилиту, которая скачивает файлы за указанную дату с сайта [VX-Underground](https://vx-underground.org/), загружает их в S3 хранилище MinIO, сканирует скаченные файлы с помощью [YARA правил](https://github.com/kevoreilly/CAPEv2/tree/master/data/yara/CAPE) и загружает json отчёт в S3 хранилище MinIO  
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
