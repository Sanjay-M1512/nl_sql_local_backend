import re

def classify_sql(query: str):
    q = query.strip().upper()

    if q.startswith("SELECT"):
        return "DQL"
    elif q.startswith(("INSERT", "UPDATE", "DELETE")):
        return "DML"
    elif q.startswith(("CREATE", "ALTER", "DROP", "TRUNCATE", "RENAME")):
        return "DDL"
    elif q.startswith(("GRANT", "REVOKE")):
        return "DCL"
    elif q.startswith(("COMMIT", "ROLLBACK", "SAVEPOINT", "SET TRANSACTION")):
        return "TCL"
    else:
        return "UNKNOWN"
