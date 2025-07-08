import sqlite3
import os
from datetime import datetime, timedelta
import json

class Database:
    def __init__(self, db_path="data/data.db"):
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self.connection = sqlite3.connect(db_path)
        self.cursor = self.connection.cursor()
        self.global_ban_servers = set()
        self.gban_allowed_roles = {}
        self.global_bans = {}
        self._create_tables()
        self._ensure_guild_ids_column()
        self._load_data_to_memory()

    def _ensure_guild_ids_column(self):
        try:
            self.cursor.execute("PRAGMA table_info(global_bans)")
            columns = [col[1] for col in self.cursor.fetchall()]
            if "guild_ids" not in columns:
                self.cursor.execute("ALTER TABLE global_bans ADD COLUMN guild_ids TEXT")
                self.connection.commit()
        except sqlite3.Error as e:
            print(f"[Ошибка БД] Не удалось добавить столбец guild_ids: {e}")

    def _load_data_to_memory(self):
        try:
            self.cursor.execute("SELECT guild_id FROM global_ban_servers")
            self.global_ban_servers = {row[0] for row in self.cursor.fetchall()}
            self.cursor.execute("SELECT guild_id, role_id FROM gban_allowed_roles")
            for guild_id, role_id in self.cursor.fetchall():
                if guild_id not in self.gban_allowed_roles:
                    self.gban_allowed_roles[guild_id] = set()
                self.gban_allowed_roles[guild_id].add(role_id)
        except sqlite3.Error as e:
            print(f"[Ошибка БД] Не удалось загрузить данные в память: {e}")

    def _create_tables(self):
        try:
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS global_ban_servers (
                    guild_id INTEGER PRIMARY KEY,
                    owner_id INTEGER NOT NULL,
                    enabled INTEGER DEFAULT 1
                )''')
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS global_bans_servers (
                    user_id INTEGER,
                    guild_id INTEGER,
                    PRIMARY KEY (user_id, guild_id)
                )''')
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS gban_allowed_roles (
                    guild_id INTEGER,
                    role_id INTEGER,
                    PRIMARY KEY (guild_id, role_id)
                )''')
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS global_bans (
                    user_id INTEGER PRIMARY KEY,
                    timestamp REAL NOT NULL,
                    reason TEXT,
                    issuer_id INTEGER,
                    guild_ids TEXT
                )''')
            
            # --- Таблица для хранения состояния защиты (вкл/выкл) ---
            self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS protection_status (
                guild_id INTEGER PRIMARY KEY,
                is_enabled INTEGER DEFAULT 0
            )
            ''')

            # --- Таблица для хранения лимитов действий ---
            self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS action_limits (
                guild_id INTEGER PRIMARY KEY,
                role_limit INTEGER DEFAULT 5,
                channel_limit INTEGER DEFAULT 5
            )
            ''')

            # Таблица для логирования попыток рейдов
            self.cursor.execute('''CREATE TABLE IF NOT EXISTS raid_attempts (
                                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                                  guild_id INTEGER,
                                  timestamp TEXT)''')

            # Таблица для логирования активаций защиты
            self.cursor.execute('''CREATE TABLE IF NOT EXISTS protection_activations (
                                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                                  guild_id INTEGER,
                                  timestamp TEXT)''')

            # Таблица для логирования блокировки ролей
            self.cursor.execute('''CREATE TABLE IF NOT EXISTS role_blocks (
                                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                                  guild_id INTEGER,
                                  role_id INTEGER,
                                  timestamp TEXT)''')

            # Таблица для логирования удаления каналов
            self.cursor.execute('''CREATE TABLE IF NOT EXISTS channel_blocks (
                                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                                  guild_id INTEGER,
                                  channel_id INTEGER,
                                  timestamp TEXT)''')

            # --- Таблица для логирования использования запрета ---
            self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS aban_usage_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                guild_id INTEGER,
                admin_id INTEGER,
                target_id INTEGER,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            ''')

            # --- Таблица для хранения доверенных лиц ---
            self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS trusted_users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                guild_id INTEGER,
                user_id INTEGER,
                added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(guild_id, user_id)
            )
            ''')

            # --- Таблица для разрешённых ролей для команды /aban ---
            self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS aban_allowed_roles (
                guild_id INTEGER,
                role_id INTEGER,
                PRIMARY KEY (guild_id, role_id)
            )
            ''')

            # --- Таблица для отслеживания действий пользователей ---
            self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS user_actions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                guild_id INTEGER,
                user_id INTEGER,
                action_type TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            ''')

            # --- НОВАЯ ТАБЛИЦА: Действия с ролями ---
            self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS role_actions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                guild_id INTEGER,
                user_id INTEGER,
                action_type TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            ''')

            # --- НОВАЯ ТАБЛИЦА: Действия с каналами ---
            self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS channel_actions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                guild_id INTEGER,
                user_id INTEGER,
                action_type TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            ''')

            # --- Таблица для хранения изображений серверов ---
            self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS server_images (
                guild_id INTEGER PRIMARY KEY,
                image_url TEXT,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            ''')

            # --- Таблица для хранения премиум-кодов ---
            self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS premium_codes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                code TEXT UNIQUE,
                duration_days INTEGER,
                expires_at TIMESTAMP,
                used INTEGER DEFAULT 0,
                used_by INTEGER,
                used_at TIMESTAMP
            )
            ''')

            # --- Таблица для хранения премиум-статуса пользователей ---
            self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS premium_status (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                guild_id INTEGER,
                expires_at TIMESTAMP,
                UNIQUE(user_id, guild_id)
            )
            ''')

            # --- Таблица для хранения черного списка ролей ---
            self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS blacklisted_roles (
                guild_id INTEGER,
                role_id INTEGER,
                PRIMARY KEY (guild_id, role_id)
            )
            ''')

            # --- Таблица для хранения прав каналов при включении raid_mode ---
            self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS channel_permissions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                guild_id INTEGER,
                channel_id INTEGER,
                permissions TEXT,
                saved_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP,
                UNIQUE(guild_id, channel_id)
            )
            ''')

            self.connection.commit()
        except sqlite3.Error as e:
            print(f"Ошибка создания таблиц: {e}")

    def add_global_ban_server(self, guild_id, owner_id):
        try:
            self.cursor.execute("""
                INSERT OR IGNORE INTO global_ban_servers 
                (guild_id, owner_id, enabled) 
                VALUES (?, ?, 1)
            """, (guild_id, owner_id))
            self.connection.commit()
            self.global_ban_servers.add(guild_id)
            return True
        except sqlite3.Error as e:
            print(f"[Ошибка БД] add_global_ban_server: {e}")
            return False

    def remove_global_ban_server(self, guild_id):
        try:
            self.cursor.execute("DELETE FROM global_ban_servers WHERE guild_id = ?", (guild_id,))
            self.connection.commit()
            self.global_ban_servers.discard(guild_id)
            return True
        except sqlite3.Error as e:
            print(f"[Ошибка БД] remove_global_ban_server: {e}")
            return False

    def is_global_ban_server(self, guild_id):
        return guild_id in self.global_ban_servers

    def get_global_ban(self, user_id):
        try:
            self.cursor.execute("SELECT * FROM global_bans WHERE user_id = ?", (user_id,))
            result = self.cursor.fetchone()
            if result:
                return {
                    "user_id": result[0],
                    "timestamp": result[1],
                    "reason": result[2],
                    "issuer_id": result[3],
                    "guild_ids": json.loads(result[4]) if result[4] else []
                }
            return None
        except sqlite3.Error as e:
            print(f"[Ошибка БД] get_global_ban: {e}")
            return None

    def add_global_ban(self, user_id, ban_data):
        try:
            guild_ids = ban_data.get("guild_ids", [])
            self.cursor.execute("""
                INSERT OR REPLACE INTO global_bans 
                (user_id, timestamp, reason, issuer_id, guild_ids) 
                VALUES (?, ?, ?, ?, ?)
            """, (
                user_id,
                ban_data["timestamp"],
                ban_data["reason"],
                ban_data["issuer_id"],
                json.dumps(guild_ids)
            ))
            self.connection.commit()
            return True
        except sqlite3.Error as e:
            print(f"[Ошибка БД] add_global_ban: {e}")
            return False

    def remove_global_ban(self, user_id):
        try:
            self.cursor.execute("DELETE FROM global_bans WHERE user_id = ?", (user_id,))
            self.connection.commit()
            return True
        except sqlite3.Error as e:
            print(f"[Ошибка БД] remove_global_ban: {e}")
            return False

    def get_gban_allowed_roles(self, guild_id):
        try:
            if guild_id in self.gban_allowed_roles:
                return list(self.gban_allowed_roles[guild_id])
            return []
        except Exception as e:
            print(f"[Ошибка БД] get_gban_allowed_roles: {e}")
            return []

    def add_gban_allowed_role(self, guild_id, role_id):
        try:
            if guild_id not in self.gban_allowed_roles:
                self.gban_allowed_roles[guild_id] = set()
            self.gban_allowed_roles[guild_id].add(role_id)
            self.cursor.execute("""
                INSERT OR IGNORE INTO gban_allowed_roles 
                (guild_id, role_id) VALUES (?, ?)
            """, (guild_id, role_id))
            self.connection.commit()
            return True
        except sqlite3.Error as e:
            print(f"[Ошибка БД] add_gban_allowed_role: {e}")
            return False

    def remove_gban_allowed_role(self, guild_id, role_id):
        try:
            if guild_id in self.gban_allowed_roles:
                self.gban_allowed_roles[guild_id].discard(role_id)
            self.cursor.execute("""
                DELETE FROM gban_allowed_roles 
                WHERE guild_id = ? AND role_id = ?
            """, (guild_id, role_id))
            self.connection.commit()
            return True
        except sqlite3.Error as e:
            print(f"[Ошибка БД] remove_gban_allowed_role: {e}")
            return False

    def check_premium_status(self, owner_id):
        return True
    
    def set_server_image(self, guild_id, image_url):
        """Установка изображения для сервера"""
        try:
            self.cursor.execute(
                """
                INSERT OR REPLACE INTO server_images (guild_id, image_url, updated_at) 
                VALUES (?, ?, CURRENT_TIMESTAMP)
                """,
                (guild_id, image_url)
            )
            self.connection.commit()
            return True
        except sqlite3.Error as e:
            print(f"Ошибка установки изображения сервера: {e}")
            return False
    
    def get_server_image(self, guild_id):
        """Получение URL изображения для сервера"""
        try:
            self.cursor.execute(
                "SELECT image_url FROM server_images WHERE guild_id = ?",
                (guild_id,)
            )
            result = self.cursor.fetchone()
            return result[0] if result else None
        except sqlite3.Error as e:
            print(f"Ошибка получения изображения сервера: {e}")
            return None
    
    def get_premium_status(self, user_id, guild_id):
        """Проверка премиум-статуса пользователя на сервере"""
        try:
            self.cursor.execute(
                "SELECT expires_at FROM premium_status WHERE user_id = ? AND guild_id = ?",
                (user_id, guild_id)
            )
            result = self.cursor.fetchone()
            if result:
                expires_at = datetime.strptime(result[0], '%Y-%m-%d %H:%M:%S')
                if expires_at > datetime.now():
                    return {"is_premium": True, "expires_at": result[0]}
                else:
                    self.cursor.execute(
                        "DELETE FROM premium_status WHERE user_id = ? AND guild_id = ?",
                        (user_id, guild_id)
                    )
                    self.connection.commit()
            return {"is_premium": False, "expires_at": None}
        except sqlite3.Error as e:
            print(f"Ошибка проверки премиум-статуса: {e}")
            return {"is_premium": False, "expires_at": None}

    def add_trusted_user(self, guild_id, user_id):
        """Добавление пользователя в список доверенных лиц"""
        try:
            self.cursor.execute(
                "INSERT OR IGNORE INTO trusted_users (guild_id, user_id) VALUES (?, ?)",
                (guild_id, user_id)
            )
            self.connection.commit()
            return self.cursor.rowcount > 0
        except sqlite3.Error as e:
            print(f"Ошибка добавления доверенного лица: {e}")
            return False
    
    def remove_trusted_user(self, guild_id, user_id):
        """Удаление пользователя из списка доверенных лиц"""
        try:
            self.cursor.execute(
                "DELETE FROM trusted_users WHERE guild_id = ? AND user_id = ?",
                (guild_id, user_id)
            )
            self.connection.commit()
            return self.cursor.rowcount > 0
        except sqlite3.Error as e:
            print(f"Ошибка удаления доверенного лица: {e}")
            return False
    
    def is_trusted_user(self, guild_id, user_id):
        """Проверка, является ли пользователь доверенным лицом"""
        try:
            self.cursor.execute(
                "SELECT 1 FROM trusted_users WHERE guild_id = ? AND user_id = ?",
                (guild_id, user_id)
            )
            return self.cursor.fetchone() is not None
        except sqlite3.Error as e:
            print(f"Ошибка проверки доверенного лица: {e}")
            return False
    
    def get_trusted_users(self, guild_id):
        """Получение списка доверенных лиц для сервера"""
        try:
            self.cursor.execute(
                "SELECT user_id FROM trusted_users WHERE guild_id = ?",
                (guild_id,)
            )
            return [row[0] for row in self.cursor.fetchall()]
        except sqlite3.Error as e:
            print(f"Ошибка получения списка доверенных лиц: {e}")
            return []

    def get_action_limits(self, guild_id):
        """Получение лимитов действий для сервера"""
        try:
            self.cursor.execute("SELECT role_limit, channel_limit FROM action_limits WHERE guild_id = ?", (guild_id,))
            result = self.cursor.fetchone()
            if result:
                return {"role_limit": result[0], "channel_limit": result[1]}
            else:
                self.cursor.execute(
                    "INSERT INTO action_limits (guild_id, role_limit, channel_limit) VALUES (?, 5, 5)",
                    (guild_id,)
                )
                self.connection.commit()
                return {"role_limit": 5, "channel_limit": 5}
        except sqlite3.Error as e:
            print(f"Ошибка получения лимитов действий: {e}")
            return {"role_limit": 5, "channel_limit": 5}
    
    def set_action_limits(self, guild_id, role_limit, channel_limit):
        """Установка лимитов действий для сервера"""
        try:
            self.cursor.execute(
                "INSERT OR REPLACE INTO action_limits (guild_id, role_limit, channel_limit) VALUES (?, ?, ?)",
                (guild_id, role_limit, channel_limit)
            )
            self.connection.commit()
            return True
        except sqlite3.Error as e:
            print(f"Ошибка установки лимитов действий: {e}")
            return False
        

    def get_blacklisted_roles(self, guild_id):
        try:
            self.cursor.execute("SELECT role_id FROM blacklisted_roles WHERE guild_id = ?", (guild_id,))
            return [row[0] for row in self.cursor.fetchall()]
        except sqlite3.Error as e:
            print(f"[Ошибка БД] get_blacklisted_roles: {e}")
            return []

    def set_blacklisted_roles(self, guild_id, role_ids):
        try:
            self.cursor.execute("DELETE FROM blacklisted_roles WHERE guild_id = ?", (guild_id,))
            if role_ids:
                data = [(guild_id, role_id) for role_id in role_ids]
                self.cursor.executemany("INSERT OR IGNORE INTO blacklisted_roles (guild_id, role_id) VALUES (?, ?)", data)
            self.connection.commit()
            return True
        except sqlite3.Error as e:
            print(f"[Ошибка БД] set_blacklisted_roles: {e}")
            return False

    def get_aban_allowed_roles(self, guild_id):
        try:
            self.cursor.execute("SELECT role_id FROM aban_allowed_roles WHERE guild_id = ?", (guild_id,))
            return [row[0] for row in self.cursor.fetchall()]
        except sqlite3.Error as e:
            print(f"[Ошибка БД] get_aban_allowed_roles: {e}")
            return []

    def set_aban_allowed_roles(self, guild_id, role_ids):
        try:
            self.cursor.execute("DELETE FROM aban_allowed_roles WHERE guild_id = ?", (guild_id,))
            if role_ids:
                data = [(guild_id, role_id) for role_id in role_ids]
                self.cursor.executemany("INSERT OR IGNORE INTO aban_allowed_roles (guild_id, role_id) VALUES (?, ?)", data)
            self.connection.commit()
            return True
        except sqlite3.Error as e:
            print(f"[Ошибка БД] set_aban_allowed_roles: {e}")
            return False

    def log_aban_usage(self, guild_id, admin_id, target_id):
        try:
            self.cursor.execute("""
                INSERT INTO aban_usage_log 
                (guild_id, admin_id, target_id, timestamp) 
                VALUES (?, ?, ?, ?)
            """, (guild_id, admin_id, target_id, datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
            self.connection.commit()
            return True
        except sqlite3.Error as e:
            print(f"[Ошибка БД] log_aban_usage: {e}")
            return False

    def get_aban_history(self, guild_id, limit=10):
        """Возвращает историю использования команды /aban для сервера"""
        try:
            self.cursor.execute(
                """
                SELECT admin_id, target_id, timestamp 
                FROM aban_usage_log 
                WHERE guild_id = ? 
                ORDER BY timestamp DESC 
                LIMIT ?
                """,
                (guild_id, limit)
            )
            rows = self.cursor.fetchall()
            return [{"admin_id": r[0], "target_id": r[1], "timestamp": r[2]} for r in rows]
        except sqlite3.Error as e:
            print(f"Ошибка получения истории использования /aban: {e}")
            return []

    def get_protection_status(self, guild_id):
        """Получение статуса защиты для сервера"""
        try:
            self.cursor.execute("SELECT is_enabled FROM protection_status WHERE guild_id = ?", (guild_id,))
            result = self.cursor.fetchone()
            if result:
                return bool(result[0])
            else:
                self.cursor.execute("INSERT INTO protection_status (guild_id, is_enabled) VALUES (?, 0)", (guild_id,))
                self.connection.commit()
                return False
        except sqlite3.Error as e:
            print(f"Ошибка получения статуса защиты: {e}")
            return False
    
    def set_protection_status(self, guild_id, status):
        """Установка статуса защиты для сервера"""
        try:
            self.cursor.execute(
                "INSERT OR REPLACE INTO protection_status (guild_id, is_enabled) VALUES (?, ?)",
                (guild_id, int(status))
            )
            self.connection.commit()
            return True
        except sqlite3.Error as e:
            print(f"Ошибка установки статуса защиты: {e}")
            return False

    def grant_temporary_permissions(self, guild_id, channel_id, role_id, duration_minutes):
        try:
            expires_at = (datetime.now() + timedelta(minutes=duration_minutes)).strftime('%Y-%m-%d %H:%M:%S')
            self.cursor.execute("""
                INSERT OR REPLACE INTO channel_permissions 
                (guild_id, channel_id, role_id, expires_at) 
                VALUES (?, ?, ?, ?)
            """, (guild_id, channel_id, role_id, expires_at))
            self.connection.commit()
            return True
        except sqlite3.Error as e:
            print(f"[Ошибка БД] grant_temporary_permissions: {e}")
            return False

    def get_temporary_permissions(self, guild_id, channel_id):
        try:
            self.cursor.execute("""
                SELECT role_id, expires_at FROM channel_permissions 
                WHERE guild_id = ? AND channel_id = ? AND expires_at > ?
            """, (guild_id, channel_id, datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
            result = self.cursor.fetchone()
            if result:
                return {"role_id": result[0], "expires_at": result[1]}
            return None
        except sqlite3.Error as e:
            print(f"[Ошибка БД] get_temporary_permissions: {e}")
            return None

    def clear_expired_permissions(self):
        try:
            expires_at_threshold = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            self.cursor.execute("DELETE FROM channel_permissions WHERE expires_at <= ?", (expires_at_threshold,))
            self.connection.commit()
            return True
        except sqlite3.Error as e:
            print(f"[Ошибка БД] clear_expired_permissions: {e}")
            return False

    def close(self):
        if self.connection:
            self.connection.close()

    def get_all_global_ban_servers(self):
        try:
            self.cursor.execute("SELECT guild_id FROM global_ban_servers WHERE enabled = 1")
            return [row[0] for row in self.cursor.fetchall()]
        except sqlite3.Error as e:
            print(f"[Ошибка БД] get_all_global_ban_servers: {e}")
            return []

    def set_gban_allowed_roles(self, guild_id, role_ids):
        try:
            self.cursor.execute("DELETE FROM gban_allowed_roles WHERE guild_id = ?", (guild_id,))
            if role_ids:
                data = [(guild_id, role_id) for role_id in role_ids]
                self.cursor.executemany(
                    "INSERT OR IGNORE INTO gban_allowed_roles (guild_id, role_id) VALUES (?, ?)", 
                    data
                )
            self.connection.commit()
            if guild_id in self.gban_allowed_roles:
                self.gban_allowed_roles[guild_id] = set(role_ids)
            return True
        except sqlite3.Error as e:
            print(f"[Ошибка БД] set_gban_allowed_roles: {e}")
            return False

    def get_all_global_ban_servers(self):
        try:
            self.cursor.execute("SELECT guild_id FROM global_ban_servers WHERE enabled = 1")
            return [row[0] for row in self.cursor.fetchall()]
        except sqlite3.Error as e:
            print(f"[Ошибка БД] get_all_global_ban_servers: {e}")
            return []
    
    def add_count_column(self):
        try:
            self.cursor.execute("ALTER TABLE user_actions ADD COLUMN count INTEGER DEFAULT 0")
            print("[OK] Колонка 'count' успешно добавлена.")
        except sqlite3.OperationalError as e:
            if "duplicate column name" in str(e):
                print("[INFO] Колонка 'count' уже существует.")
            else:
                print(f"[ERROR] Ошибка при добавлении колонки: {e}")
        self.connection.commit()
    
    def reset_user_actions(self, guild_id, user_id, action_type):
        try:
            self.cursor.execute(
                "DELETE FROM user_actions WHERE guild_id = ? AND user_id = ? AND action_type = ?",
                (guild_id, user_id, action_type)
            )
            self.connection.commit()
            return True
        except sqlite3.Error as e:
            print(f"[Ошибка] Сброса счетчика действий: {e}")
            return False
        
    def get_blacklisted_roles(self, guild_id):
        try:
            self.cursor.execute(
                "SELECT role_id FROM blacklisted_roles WHERE guild_id = ?",
                (guild_id,)
            )
            return [row[0] for row in self.cursor.fetchall()]
        except sqlite3.Error as e:
            print(f"Ошибка получения черного списка ролей: {e}")
            return []

    def remove_blacklisted_role(self, guild_id, role_id):
        try:
            self.cursor.execute(
                "DELETE FROM blacklisted_roles WHERE guild_id = ? AND role_id = ?",
                (guild_id, role_id)
            )
            self.connection.commit()
            return self.cursor.rowcount > 0
        except sqlite3.Error as e:
            print(f"Ошибка удаления роли из черного списка: {e}")
            return False

    def get_protection_stats(self, guild_id):
        pass

    def log_raid_attempt(self, guild_id):
        pass

    def log_role_block(self, guild_id):
        pass

    def log_channel_block(self, guild_id):
        pass

    def log_trusted_action(self, guild_id):
        pass

    def get_blacklisted_roles(self, guild_id: int) -> list:
        try:
            self.cursor.execute(
                "SELECT role_id FROM blacklisted_roles WHERE guild_id = ?",
                (guild_id,)
            )
            return [row[0] for row in self.cursor.fetchall()]
        except sqlite3.Error as e:
            print(f"Ошибка получения черного списка ролей: {e}")
            return []

    def add_blacklisted_role(self, guild_id: int, role_id: int) -> bool:
        try:
            self.cursor.execute(
                "INSERT OR IGNORE INTO blacklisted_roles (guild_id, role_id) VALUES (?, ?)",
                (guild_id, role_id)
            )
            self.connection.commit()
            return True
        except sqlite3.Error as e:
            print(f"Ошибка добавления роли в черный список: {e}")
            return False

    def remove_blacklisted_role(self, guild_id: int, role_id: int) -> bool:
        try:
            self.cursor.execute(
                "DELETE FROM blacklisted_roles WHERE guild_id = ? AND role_id = ?",
                (guild_id, role_id)
            )
            self.connection.commit()
            return True
        except sqlite3.Error as e:
            print(f"Ошибка удаления роли из черного списка: {e}")
            return False
        
    def get_channel_permissions(self, guild_id):
        try:
            self.cursor.execute(
                "SELECT channel_id, permissions FROM channel_permissions WHERE guild_id = ?",
                (guild_id,)
            )
            results = self.cursor.fetchall()
            return {str(row[0]): row[1] for row in results}
        except sqlite3.Error as e:
            print(f"Ошибка получения прав каналов: {e}")
            return {}

    def save_channel_permissions(self, guild_id, channel_id, permissions):
        try:
            expires_at = (datetime.now() + timedelta(days=3)).strftime('%Y-%m-%d %H:%M:%S')
            self.cursor.execute(
                """
                INSERT OR REPLACE INTO channel_permissions (guild_id, channel_id, permissions, expires_at)
                VALUES (?, ?, ?, ?)
                """,
                (guild_id, channel_id, permissions, expires_at)
            )
            self.connection.commit()
            return True
        except sqlite3.Error as e:
            print(f"Ошибка сохранения прав канала: {e}")
            return False

    def clear_channel_permissions(self, guild_id):
        try:
            self.cursor.execute(
                "DELETE FROM channel_permissions WHERE guild_id = ?",
                (guild_id,)
            )
            self.connection.commit()
            return True
        except sqlite3.Error as e:
            print(f"Ошибка очистки прав каналов: {e}")
            return False

    def cleanup_expired_permissions(self):
        try:
            expires_at_threshold = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            self.cursor.execute(
                "DELETE FROM channel_permissions WHERE expires_at <= ?",
                (expires_at_threshold,)
            )
            self.connection.commit()
            return True
        except sqlite3.Error as e:
            print(f"Ошибка очистки истекших прав: {e}")
            return False
