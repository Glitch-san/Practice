import os
import sys
from datetime import datetime

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from main import scan_and_parse, SessionLocal

def main():
    print("=" * 50)
    print("Apache Log Aggregator - Автоматический парсинг")
    print(f"Время запуска: {datetime.now()}")
    print("-" * 50)
    
    db = SessionLocal()
    try:
        total = scan_and_parse(db)
        if total > 0:
            print(f"✅ Новых записей: {total}")
        else:
            print(f"ℹ️ Новых записей: {total} (нет новых логов)")
    except Exception as e:
        print(f"❌ Ошибка: {e}")
    finally:
        db.close()
    
    print("=" * 50)

if __name__ == "__main__":
    main()