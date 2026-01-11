from db.connection import get_connection

def log_query(operation_type, sql):
    try:
        conn = get_connection()
        cursor = conn.cursor()

        insert_sql = """
        INSERT INTO audit_logs (operation_type, sql_query)
        VALUES (%s, %s)
        """

        cursor.execute(insert_sql, (operation_type, sql))
        conn.commit()

        cursor.close()
        conn.close()
    except Exception as e:
        print("Audit log error:", e)
