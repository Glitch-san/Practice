# Apache Log Aggregator

## Установка и запуск

### Требования
- Python 3.12
- PostgreSQL

### Инструкция
1. Установить PostgreSQL, создать БД `logdb`
2. Склонировать репозиторий
3. `python -m venv venv`
4. `venv\Scripts\activate`
5. `pip install -r requirements.txt`
6. `python main.py`
7. Открыть `http://127.0.0.1:8000`

### Логин/Пароль
- admin / admin123

## Добавление данных

### Способ 1. Через веб-интерфейс
Нажмите кнопку **"Принудительный парсинг логов"** — тестовые данные создадутся автоматически.

### Способ 2. Вручную через pgAdmin (SQL)
Выполните в Query Tool:

```sql
INSERT INTO log_entries (ip, timestamp, request, method, url, status, bytes_sent)
VALUES 
('192.168.1.1', '2026-06-09 12:00:00', 'GET /index.html', 'GET', '/index.html', 200, 2326),
('192.168.1.2', '2026-06-09 13:00:00', 'GET /about.html', 'GET', '/about.html', 200, 1245);