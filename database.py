import sqlite3

# Initialize database
def init_db(db_name='predictions.db'):
    conn = sqlite3.connect(db_name)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS predictions
                 (id INTEGER PRIMARY KEY, feature_values TEXT, prediction TEXT)''')
    conn.commit()
    conn.close()

# Insert prediction into database
def insert_prediction(feature_values, prediction, db_name='predictions.db'):
    conn = sqlite3.connect(db_name)
    c = conn.cursor()
    c.execute('INSERT INTO predictions (feature_values, prediction) VALUES (?, ?)', (feature_values, prediction))
    conn.commit()
    conn.close()
