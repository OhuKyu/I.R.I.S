from cache_manager import CacheManager
import os

def setup_database():
    print("🔧 Đang khởi tạo database cache...")
    cache = CacheManager()
    
    print("✅ Database cache đã được khởi tạo thành công!")
    print(f"📁 File database: {os.path.abspath(cache.db_path)}")
    
    stats = cache.get_cache_stats()
    print(f"📊 Thống kê cache:")
    print(f"   - Tổng entries: {stats['total_entries']}")
    print(f"   - Tổng hits: {stats['total_hits']}")

if __name__ == "__main__":
    setup_database()