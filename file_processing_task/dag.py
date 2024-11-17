from airflow import DAG
from airflow.operators.python import PythonOperator
from datetime import datetime, timedelta

from file_processing_task.core import start

default_args = {
    "retries": 1,
    "retry_delay": timedelta(minutes=1),
}

dag = DAG(
    "daily_analysis",
    default_args=default_args,
    description="Ежедневное скачивание, анализ и загрузка файлов с VX-Underground",
    schedule_interval=timedelta(days=1),
    start_date=datetime(2024, 11, 1),
    catchup=True
)

run_analysis_task = PythonOperator(
    task_id="run_daily_analysis",
    python_callable=start,
    provide_context=True,
    dag=dag,
)
