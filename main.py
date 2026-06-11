import os
import re
import glob
from datetime import datetime, timedelta
from typing import Optional
from contextlib import contextmanager

from fastapi import FastAPI, Depends, HTTPException, Query, BackgroundTasks
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.responses import HTMLResponse
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Index
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from passlib.context import CryptContext
from jose import JWTError, jwt
import yaml

# ========== КОНФИГУРАЦИЯ ==========
with open("config.yaml", "r", encoding="utf-8") as f:
    config = yaml.safe_load(f)

DATABASE_URL = f"postgresql://{config['database']['user']}:{config['database']['password']}@{config['database']['host']}/{config['database']['name']}"
SECRET_KEY = config['app']['secret_key']
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# ========== БАЗА ДАННЫХ ==========
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# ========== МОДЕЛИ ==========
class LogEntry(Base):
    __tablename__ = "log_entries"
    id = Column(Integer, primary_key=True)
    ip = Column(String(45), nullable=False)
    timestamp = Column(DateTime, nullable=False)
    request = Column(String(1000))
    method = Column(String(10))
    url = Column(String(500))
    status = Column(Integer)
    bytes_sent = Column(Integer)
    
    __table_args__ = (
        Index('idx_ip', 'ip'),
        Index('idx_timestamp', 'timestamp'),
    )

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    username = Column(String(100), unique=True, nullable=False)
    hashed_password = Column(String(200), nullable=False)

Base.metadata.create_all(bind=engine)

# ========== АВТОРИЗАЦИЯ ==========
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/token")

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        return username
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ========== ПАРСЕР ЛОГОВ ==========
COMMON_PATTERN = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<timestamp>[^\]]+)\] "(?P<method>\S+) (?P<url>\S+) \S+" (?P<status>\d+) (?P<bytes>\S+)'
)

def parse_timestamp(ts_str):
    try:
        return datetime.strptime(ts_str, "%d/%b/%Y:%H:%M:%S")
    except:
        return None

def parse_log_file(filepath, db_session):
    entries = []
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            match = COMMON_PATTERN.match(line)
            if match:
                data = match.groupdict()
                ts = parse_timestamp(data['timestamp'])
                if ts:
                    entry = LogEntry(
                        ip=data['ip'],
                        timestamp=ts,
                        method=data['method'],
                        url=data['url'],
                        request=f"{data['method']} {data['url']}",
                        status=int(data['status']),
                        bytes_sent=int(data['bytes']) if data['bytes'] != '-' else 0
                    )
                    entries.append(entry)
    
    if entries:
        db_session.bulk_save_objects(entries)
        db_session.commit()
    return len(entries)

def scan_and_parse(db_session):
    log_dir = config['logs']['directory']
    mask = config['logs']['file_mask']
    
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
        with open(os.path.join(log_dir, "sample.log"), "w", encoding='utf-8') as f:
            f.write('192.168.1.1 - - [10/Oct/2023:13:55:36 +0300] "GET /index.html HTTP/1.1" 200 2326\n')
            f.write('192.168.1.2 - - [10/Oct/2023:13:56:36 +0300] "GET /about.html HTTP/1.1" 200 1245\n')
            f.write('192.168.1.1 - - [10/Oct/2023:13:57:36 +0300] "GET /contact.html HTTP/1.1" 404 523\n')
    
    full_path = os.path.join(log_dir, mask)
    files = glob.glob(full_path)
    total = 0
    for fpath in files:
        total += parse_log_file(fpath, db_session)
    return total

# ========== FASTAPI ПРИЛОЖЕНИЕ ==========
app = FastAPI(title="Apache Log Aggregator")

@app.on_event("startup")
def startup():
    db = SessionLocal()
    if not db.query(User).filter(User.username == "admin").first():
        admin = User(username="admin", hashed_password=get_password_hash("admin123"))
        db.add(admin)
        db.commit()
    db.close()

@app.post("/api/token")
async def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    token = create_access_token(data={"sub": user.username})
    return {"access_token": token, "token_type": "bearer"}

@app.get("/api/logs")
async def get_logs(
    start_date: Optional[datetime] = Query(None),
    end_date: Optional[datetime] = Query(None),
    ip_filter: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    current_user: str = Depends(get_current_user)
):
    query = db.query(LogEntry)
    
    if start_date:
        query = query.filter(LogEntry.timestamp >= start_date)
    if end_date:
        query = query.filter(LogEntry.timestamp <= end_date)
    if ip_filter:
        query = query.filter(LogEntry.ip == ip_filter)
    
    logs = query.order_by(LogEntry.timestamp.desc()).limit(500).all()
    return [
        {
            "id": log.id,
            "ip": log.ip,
            "timestamp": log.timestamp,
            "request": log.request,
            "status": log.status,
            "bytes_sent": log.bytes_sent
        }
        for log in logs
    ]

@app.get("/api/urls")
async def get_urls(db: Session = Depends(get_db), current_user: str = Depends(get_current_user)):
    urls = db.query(LogEntry.url).filter(LogEntry.url.isnot(None)).distinct().limit(100).all()
    return [u[0] for u in urls if u[0]]

@app.post("/api/parse-logs")
async def parse_logs(background_tasks: BackgroundTasks, db: Session = Depends(get_db), current_user: str = Depends(get_current_user)):
    def parse_task():
        new_db = SessionLocal()
        try:
            total = scan_and_parse(new_db)
            print(f"Parsed {total} entries")
        finally:
            new_db.close()
    
    background_tasks.add_task(parse_task)
    return {"message": "Parsing started"}

@app.get("/")
async def root():
    html_content = """
<!DOCTYPE html>
<html>
<head>
    <title>Apache Log Aggregator</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: Arial, sans-serif; background: #f5f5f5; padding: 20px; }
        .container { max-width: 1200px; margin: auto; background: white; border-radius: 10px; padding: 20px; }
        h1 { color: #667eea; margin-bottom: 20px; }
        input, select, button { padding: 10px; margin: 5px; border: 1px solid #ddd; border-radius: 5px; }
        button { background: #667eea; color: white; cursor: pointer; }
        button:hover { background: #5a67d8; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th, td { border: 1px solid #ddd; padding: 10px; text-align: left; }
        th { background: #667eea; color: white; }
        .error { color: red; }
        .status { color: green; margin: 10px 0; }
    </style>
</head>
<body>
<div class="container">
    <h1>📊 Apache Log Aggregator</h1>
    <div id="login">
        <h2>Вход</h2>
        <input type="text" id="username" placeholder="Логин" value="admin">
        <input type="password" id="password" placeholder="Пароль" value="admin123">
        <button onclick="login()">Войти</button>
        <div id="error" class="error"></div>
    </div>
    <div id="dashboard" style="display:none;">
        <button onclick="parseLogs()">🔄 Принудительный парсинг логов</button>
        <div id="status" class="status"></div>
        <div>
            <input type="date" id="startDate">
            <input type="date" id="endDate">
            <input type="text" id="ipFilter" placeholder="Фильтр по IP">
            <button onclick="loadLogs()">🔍 Показать</button>
        </div>
        <div>
            <h3>📁 Список URL из логов</h3>
            <select id="urlList" size="5" style="width:100%" onchange="filterByUrl()"></select>
        </div>
        <div id="logs"></div>
    </div>
</div>
<script>
    let token = null;
    
    async function login() {
        const username = document.getElementById('username').value;
        const password = document.getElementById('password').value;
        try {
            const resp = await fetch('/api/token', {
                method: 'POST',
                headers: {'Content-Type': 'application/x-www-form-urlencoded'},
                body: `username=${encodeURIComponent(username)}&password=${encodeURIComponent(password)}`
            });
            if (resp.ok) {
                const data = await resp.json();
                token = data.access_token;
                document.getElementById('login').style.display = 'none';
                document.getElementById('dashboard').style.display = 'block';
                loadLogs();
                loadUrls();
            } else {
                document.getElementById('error').innerText = 'Ошибка входа';
            }
        } catch(e) {
            document.getElementById('error').innerText = e.message;
        }
    }
    
    async function loadLogs() {
        if (!token) return;
        const start = document.getElementById('startDate').value;
        const end = document.getElementById('endDate').value;
        const ip = document.getElementById('ipFilter').value;
        let url = '/api/logs?';
        if (start) url += `start_date=${start}T00:00:00&`;
        if (end) url += `end_date=${end}T23:59:59&`;
        if (ip) url += `ip_filter=${ip}&`;
        try {
            const resp = await fetch(url, {headers: {'Authorization': `Bearer ${token}`}});
            if (resp.ok) {
                const data = await resp.json();
                displayLogs(data);
            }
        } catch(e) {
            document.getElementById('logs').innerHTML = '<p style="color:red">Ошибка загрузки</p>';
        }
    }
    
    function displayLogs(logs) {
        if (!logs || logs.length === 0) {
            document.getElementById('logs').innerHTML = '<p>Нет данных</p>';
            return;
        }
        let html = '<table><tr><th>IP</th><th>Время</th><th>Запрос</th><th>Статус</th><th>Байт</th></tr>';
        for (let log of logs) {
            html += `<tr>
                <td>${log.ip}</td>
                <td>${new Date(log.timestamp).toLocaleString()}</td>
                <td>${log.request || ''}</td>
                <td>${log.status}</td>
                <td>${log.bytes_sent}</td>
            </tr>`;
        }
        html += '</table>';
        document.getElementById('logs').innerHTML = html;
    }
    
    async function loadUrls() {
        if (!token) return;
        const resp = await fetch('/api/urls', {headers: {'Authorization': `Bearer ${token}`}});
        if (resp.ok) {
            const urls = await resp.json();
            const select = document.getElementById('urlList');
            select.innerHTML = '<option value="">Выберите URL</option>';
            urls.forEach(url => {
                const option = document.createElement('option');
                option.value = url;
                option.textContent = url.length > 80 ? url.substring(0, 80) + '...' : url;
                select.appendChild(option);
            });
        }
    }
    
    async function filterByUrl() {
        const select = document.getElementById('urlList');
        const url = select.value;
        if (!url) return;
        const resp = await fetch('/api/logs', {headers: {'Authorization': `Bearer ${token}`}});
        if (resp.ok) {
            const logs = await resp.json();
            const filtered = logs.filter(log => log.request && log.request.includes(url));
            displayLogs(filtered);
        }
    }
    
    async function parseLogs() {
        if (!token) return;
        const btn = event.target;
        btn.disabled = true;
        btn.textContent = '⏳ Парсинг...';
        document.getElementById('status').innerHTML = '⏳ Запуск парсинга...';
        try {
            const resp = await fetch('/api/parse-logs', {
                method: 'POST',
                headers: {'Authorization': `Bearer ${token}`}
            });
            if (resp.ok) {
                document.getElementById('status').innerHTML = '✅ Парсинг запущен! Через 5 секунд данные обновятся.';
                setTimeout(() => {
                    loadLogs();
                    loadUrls();
                    document.getElementById('status').innerHTML = '';
                }, 5000);
            }
        } catch(e) {
            document.getElementById('status').innerHTML = '<span style="color:red">Ошибка парсинга</span>';
        } finally {
            btn.disabled = false;
            btn.textContent = '🔄 Принудительный парсинг логов';
        }
    }
</script>
</body>
</html>
    """
    return HTMLResponse(content=html_content)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)