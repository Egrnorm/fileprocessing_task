### Запуск  
1. ##### Клонируем репозиторий:  
- `https://github.com/Egrnorm/fileprocessing_task.git`  
2. ##### Переходим в папку:  
- `cd fileprocessing_task`  
3. ##### Запускаем docker-compose для MinIO:  
- `sudo docker-compose up -d`
4. ##### Скачиваем poetry, если не установлен:  
- `curl -sSL https://install.python-poetry.org | python3`
5. ##### Устанавливаем зависимости:  
- `poetry install`  
6. ##### Запускаем:  
- `poetry run python -m file_processing_task.core`  
---
### Немного о проекте  
##### Этот проект представляет собой консольную утилиту, которая скачивает файлы за указанную дату с сайта [VX-Underground](https://vx-underground.org/), загружает их в S3 хранилище MinIO, сканирует скаченные файлы с помощью [YARA правил](https://github.com/kevoreilly/CAPEv2/tree/master/data/yara/CAPE) и загружает json отчёт в S3 хранилище MinIO  
---
### Логин и пароль для доступа к веб-интерфейсу MinIO  
- `admin:upupuch123`  
### Веб-интерфейс MinIO доступен по адресу:  
- `localhost:9001`
