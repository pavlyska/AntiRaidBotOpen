import sqlite3
from datetime import datetime, timedelta

class Database:
    def __init__(self):
        self.conn = sqlite3.connect('bot_database.db', check_same_thread=False)
        self.cursor = self.conn.cursor()
        self.create_tables()

    def create_tables(self):
        self.cursor.execute('''CREATE TABLE IF NOT EXISTS guilds (
            guild_id INTEGER PRIMARY KEY,
            protection_enabled BOOLEAN DEFAULT 0,
            role_limit INTEGER DEFAULT 5,
            channel_limit INTEGER DEFAULT 5
        )''')
        self.cursor.execute('''CREATE TABLE IF NOT EXISTS trusted_users (
            guild_id INTEGER,
            user_id INTEGER,
            PRIMARY KEY (guild_id, user_id)
        )''')
        self.cursor.execute('''CREATE TABLE IF NOT EXISTS blacklisted_roles (
            guild_id INTEGER,
            role_id INTEGER,
            PRIMARY KEY (guild_id, role_id)
        )''')
        self.cursor.execute('''CREATE TABLE IF NOT EXISTS actions (
            guild_id INTEGER,
            user_id INTEGER,
            action_type TEXT,
            timestamp DATETIME
        )''')
        self.cursor.execute('''CREATE TABLE IF NOT EXISTS channel_permissions (
            guild_id INTEGER,
            channel_id INTEGER,
            permissions TEXT,
            expiry_time DATETIME,
            PRIMARY KEY (guild_id, channel_id)
        )''')
        self.cursor.execute('''CREATE TABLE IF NOT EXISTS aban_allowed_roles (
            guild_id INTEGER,
            role_id INTEGER,
            PRIMARY KEY (guild_id, role_id)
        )''')
        self.cursor.execute('''CREATE TABLE IF NOT EXISTS aban_history (
            guild_id INTEGER,
            admin_id INTEGER,
            target_id INTEGER,
            timestamp DATETIME
        )''')
        self.cursor.execute('''CREATE TABLE IF NOT EXISTS protection_stats (
            guild_id INTEGER PRIMARY KEY,
            raids_detected INTEGER DEFAULT 0,
            protections_activated INTEGER DEFAULT 0,
            users_blocked INTEGER DEFAULT 0,
            roles_removed INTEGER DEFAULT 0,
            channels_deleted INTEGER DEFAULT 0
        )''')
        self.conn.commit()

    def get_protection_status(self, guild_id):
        self.cursor.execute('SELECT protection_enabled FROM guilds WHERE guild_id = ?', (guild_id,))
        result = self.cursor.fetchone()
        return result[0] if result else False

    def set_protection_status(self, guild_id, status):
        self.cursor.execute('INSERT OR REPLACE INTO guilds (guild_id, protection_enabled) VALUES (?, ?)', (guild_id, status))
        self.conn.commit()

    def get_action_limits(self, guild_id):
        self.cursor.execute('SELECT role_limit, channel_limit FROM guilds WHERE guild_id = ?', (guild_id,))
        result = self.cursor.fetchone()
        return {'role_limit': result[0], 'channel_limit': result[1]} if result else {'role_limit': 5, 'channel_limit': 5}

    def set_action_limits(self, guild_id, role_limit, channel_limit):
        self.cursor.execute('INSERT OR REPLACE INTO guilds (guild_id, role_limit, channel_limit) VALUES (?, ?, ?)',
                           (guild_id, role_limit, channel_limit))
        self.conn.commit()

    def add_trusted_user(self, guild_id, user_id):
        self.cursor.execute('INSERT OR IGNORE INTO trusted_users (guild_id, user_id) VALUES (?, ?)', (guild_id, user_id))
        self.conn.commit()
        return True

    def remove_trusted_user(self, guild_id, user_id):
        self.cursor.execute('DELETE FROM trusted_users WHERE guild_id = ? AND user_id = ?', (guild_id, user_id))
        self.conn.commit()
        return True

    def get_trusted_users(self, guild_id):
        self.cursor.execute('SELECT user_id FROM trusted_users WHERE guild_id = ?', (guild_id,))
        return [row[0] for row in self.cursor.fetchall()]

    def is_trusted_user(self, guild_id, user_id):
        self.cursor.execute('SELECT 1 FROM trusted_users WHERE guild_id = ? AND user_id = ?', (guild_id, user_id))
        return bool(self.cursor.fetchone())

    def add_blacklisted_role(self, guild_id, role_id):
        self.cursor.execute('INSERT OR IGNORE INTO blacklisted_roles (guild_id, role_id) VALUES (?, ?)', (guild_id, role_id))
        self.conn.commit()
        return True

    def remove_blacklisted_role(self, guild_id, role_id):
        self.cursor.execute('DELETE FROM blacklisted_roles WHERE guild_id = ? AND role_id = ?', (guild_id, role_id))
        self.conn.commit()
        return True

    def get_blacklisted_roles(self, guild_id):
        self.cursor.execute('SELECT role_id FROM blacklisted_roles WHERE guild_id = ?', (guild_id,))
        return [row[0] for row in self.cursor.fetchall()]

    def log_action(self, guild_id, user_id, action_type):
        self.cursor.execute('INSERT INTO actions (guild_id, user_id, action_type, timestamp) VALUES (?, ?, ?, ?)',
                           (guild_id, user_id, action_type, datetime.now()))
        self.conn.commit()

    def count_user_actions(self, guild_id, user_id, action_type):
        cutoff = datetime.now() - timedelta(days=1)
        self.cursor.execute(
            'SELECT COUNT(*) FROM actions WHERE guild_id = ? AND user_id = ? AND action_type = ? AND timestamp > ?',
            (guild_id, user_id, action_type, cutoff))
        return self.cursor.fetchone()[0]

    def reset_user_actions(self, guild_id, user_id, action_type_prefix):
        cutoff = datetime.now() - timedelta(days=1)
        self.cursor.execute(
            'DELETE FROM actions WHERE guild_id = ? AND user_id = ? AND action_type LIKE ? AND timestamp > ?',
            (guild_id, user_id, f"{action_type_prefix}%", cutoff))
        self.conn.commit()

    def save_channel_permissions(self, guild_id, channel_id, permissions):
        expiry = datetime.now() + timedelta(days=3)
        self.cursor.execute('INSERT OR REPLACE INTO channel_permissions (guild_id, channel_id, permissions, expiry_time) VALUES (?, ?, ?, ?)',
                           (guild_id, channel_id, permissions, expiry))
        self.conn.commit()

    def get_channel_permissions(self, guild_id):
        self.cursor.execute('SELECT channel_id, permissions FROM channel_permissions WHERE guild_id = ?', (guild_id,))
        return {row[0]: row[1] for row in self.cursor.fetchall()}

    def clear_channel_permissions(self, guild_id):
        self.cursor.execute('DELETE FROM channel_permissions WHERE guild_id = ?', (guild_id,))
        self.conn.commit()

    def cleanup_expired_permissions(self):
        self.cursor.execute('DELETE FROM channel_permissions WHERE expiry_time <= ?', (datetime.now(),))
        self.conn.commit()

    def add_aban_allowed_role(self, guild_id, role_id):
        self.cursor.execute('INSERT OR IGNORE INTO aban_allowed_roles (guild_id, role_id) VALUES (?, ?)', (guild_id, role_id))
        self.conn.commit()
        return True

    def remove_aban_allowed_role(self, guild_id, role_id):
        self.cursor.execute('DELETE FROM aban_allowed_roles WHERE guild_id = ? AND role_id = ?', (guild_id, role_id))
        self.conn.commit()
        return True

    def get_aban_allowed_roles(self, guild_id):
        self.cursor.execute('SELECT role_id FROM aban_allowed_roles WHERE guild_id = ?', (guild_id,))
        return [row[0] for row in self.cursor.fetchall()]

    def log_aban_usage(self, guild_id, admin_id, target_id):
        self.cursor.execute('INSERT INTO aban_history (guild_id, admin_id, target_id, timestamp) VALUES (?, ?, ?, ?)',
                           (guild_id, admin_id, target_id, datetime.now()))
        self.conn.commit()

    def get_aban_history(self, guild_id):
        self.cursor.execute('SELECT admin_id, target_id, timestamp FROM aban_history WHERE guild_id = ?', (guild_id,))
        return [{'admin_id': row[0], 'target_id': row[1], 'timestamp': row[2]} for row in self.cursor.fetchall()]

    def get_protection_stats(self, guild_id):
        self.cursor.execute('SELECT raids_detected, protections_activated, users_blocked, roles_removed, channels_deleted FROM protection_stats WHERE guild_id = ?', (guild_id,))
        result = self.cursor.fetchone()
        if result:
            return {
                'raids_detected': result[0],
                'protections_activated': result[1],
                'users_blocked': result[2],
                'roles_removed': result[3],
                'channels_deleted': result[4]
            }
        return None
