import mysql.connector
from config import DB_HOST, DB_PORT, DB_USER, DB_PASSWORD, DB_NAME

# DB_NAME will be fetched dynamically
import os

def get_connection():
    db_name = os.getenv("DB_NAME")

    return mysql.connector.connect(
        host=DB_HOST,
        port=int(DB_PORT),
        user=DB_USER,
        password=DB_PASSWORD,
        database=db_name
    )
    
def get_databases():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SHOW DATABASES;")
    dbs = [row[0] for row in cursor.fetchall()]
    cursor.close()
    conn.close()
    return dbs

def get_tables():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SHOW TABLES;")
    tables = [row[0] for row in cursor.fetchall()]
    cursor.close()
    conn.close()
    return tables
