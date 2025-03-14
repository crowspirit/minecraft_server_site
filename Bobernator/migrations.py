from app import app, db, User
from flask_migrate import Migrate, upgrade
import sys

migrate = Migrate(app, db)

def upgrade_database():
    with app.app_context():
        # Додаємо колонку parent_id та is_pinned
        with db.engine.connect() as conn:
            conn.execute('PRAGMA foreign_keys=OFF;')
            conn.execute('''
                CREATE TABLE IF NOT EXISTS forum_message_new (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    content TEXT NOT NULL,
                    image_path VARCHAR(200),
                    created_at DATETIME NOT NULL,
                    topic_id INTEGER NOT NULL,
                    user_id INTEGER NOT NULL,
                    parent_id INTEGER,
                    is_pinned BOOLEAN DEFAULT 0,
                    FOREIGN KEY (topic_id) REFERENCES forum_topic (id),
                    FOREIGN KEY (user_id) REFERENCES user (id),
                    FOREIGN KEY (parent_id) REFERENCES forum_message (id)
                );
            ''')
            
            # Копіюємо дані зі старої таблиці
            conn.execute('''
                INSERT INTO forum_message_new (id, content, image_path, created_at, topic_id, user_id, parent_id)
                SELECT id, content, image_path, created_at, topic_id, user_id, parent_id FROM forum_message;
            ''')
            
            # Видаляємо стару таблицю і перейменовуємо нову
            conn.execute('DROP TABLE forum_message;')
            conn.execute('ALTER TABLE forum_message_new RENAME TO forum_message;')
            conn.execute('PRAGMA foreign_keys=ON;')
            
        # Get database connection
        connection = db.engine.connect()
        
        # Add new columns for statistics
        try:
            # Add columns one by one
            statements = [
                "ALTER TABLE user ADD COLUMN playtime_minutes INTEGER DEFAULT 0",
                "ALTER TABLE user ADD COLUMN deaths INTEGER DEFAULT 0",
                "ALTER TABLE user ADD COLUMN mobs_killed INTEGER DEFAULT 0",
                "ALTER TABLE user ADD COLUMN blocks_broken INTEGER DEFAULT 0",
                "ALTER TABLE user ADD COLUMN blocks_placed INTEGER DEFAULT 0",
                "ALTER TABLE user ADD COLUMN distance_walked FLOAT DEFAULT 0",
                "ALTER TABLE user ADD COLUMN last_stats_update TIMESTAMP"
            ]
            
            for statement in statements:
                try:
                    connection.execute(statement)
                    print(f"Successfully executed: {statement}")
                except Exception as e:
                    # If column already exists, just skip it
                    if "duplicate column name" in str(e).lower():
                        print(f"Column already exists, skipping: {statement}")
                    else:
                        raise e
                    
            print("Successfully added all statistics columns")
            
        except Exception as e:
            print(f"Error adding columns: {e}")
            sys.exit(1)

        db.session.commit()

if __name__ == '__main__':
    upgrade_database()
    print("Міграцію успішно виконано!") 