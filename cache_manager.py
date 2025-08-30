import sqlite3
import hashlib
import json
import os
from datetime import datetime, timedelta
from typing import Optional, Dict, Any

class CacheManager:
    def __init__(self, db_path: str = "iris_cache.db"):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Khởi tạo database và tạo bảng cache"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS cache (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cache_key TEXT UNIQUE NOT NULL,
                function_name TEXT NOT NULL,
                input_data TEXT NOT NULL,
                result TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP,
                hit_count INTEGER DEFAULT 0
            )
        ''')
        
        # Tạo index để tìm kiếm nhanh hơn
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_cache_key ON cache(cache_key)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_function_name ON cache(function_name)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_expires_at ON cache(expires_at)')
        
        conn.commit()
        conn.close()
    
    def generate_cache_key(self, function_name: str, **kwargs) -> str:
        """Tạo cache key từ tên hàm và tham số"""
        # Sắp xếp kwargs để đảm bảo key nhất quán
        sorted_kwargs = dict(sorted(kwargs.items()))
        data_string = f"{function_name}:{json.dumps(sorted_kwargs, sort_keys=True)}"
        return hashlib.md5(data_string.encode()).hexdigest()
    
    def get_cache(self, cache_key: str) -> Optional[str]:
        """Lấy kết quả từ cache"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Kiểm tra cache và thời gian hết hạn
        cursor.execute('''
            SELECT result, expires_at, hit_count 
            FROM cache 
            WHERE cache_key = ? AND (expires_at IS NULL OR expires_at > ?)
        ''', (cache_key, datetime.now().isoformat()))
        
        result = cursor.fetchone()
        
        if result:
            # Tăng hit count
            cursor.execute('''
                UPDATE cache 
                SET hit_count = hit_count + 1 
                WHERE cache_key = ?
            ''', (cache_key,))
            conn.commit()
            conn.close()
            return result[0]
        
        conn.close()
        return None
    
    def set_cache(self, cache_key: str, function_name: str, input_data: Dict[str, Any], 
                  result: str, expires_hours: int = 24*7) -> None:
        """Lưu kết quả vào cache"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        expires_at = datetime.now() + timedelta(hours=expires_hours)
        
        cursor.execute('''
            INSERT OR REPLACE INTO cache 
            (cache_key, function_name, input_data, result, expires_at)
            VALUES (?, ?, ?, ?, ?)
        ''', (cache_key, function_name, json.dumps(input_data), result, expires_at.isoformat()))
        
        conn.commit()
        conn.close()
    
    def clear_expired_cache(self) -> int:
        """Xóa cache đã hết hạn"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            DELETE FROM cache 
            WHERE expires_at IS NOT NULL AND expires_at <= ?
        ''', (datetime.now().isoformat(),))
        
        deleted_count = cursor.rowcount
        conn.commit()
        conn.close()
        
        return deleted_count
    
    def get_cache_stats(self) -> Dict[str, Any]:
        """Lấy thống kê cache"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Tổng số cache entries
        cursor.execute('SELECT COUNT(*) FROM cache')
        total_entries = cursor.fetchone()[0]
        
        # Cache theo function
        cursor.execute('''
            SELECT function_name, COUNT(*), SUM(hit_count) 
            FROM cache 
            GROUP BY function_name
        ''')
        function_stats = cursor.fetchall()
        
        # Cache hits tổng
        cursor.execute('SELECT SUM(hit_count) FROM cache')
        total_hits = cursor.fetchone()[0] or 0
        
        conn.close()
        
        return {
            'total_entries': total_entries,
            'total_hits': total_hits,
            'function_stats': {
                func: {'entries': count, 'hits': hits} 
                for func, count, hits in function_stats
            }
        }
    
    def clear_all_cache(self) -> int:
        """Xóa toàn bộ cache"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('DELETE FROM cache')
        deleted_count = cursor.rowcount
        conn.commit()
        conn.close()
        
        return deleted_count