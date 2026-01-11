from flask import Flask, request, jsonify
from flask_cors import CORS

from db.connection import get_databases, get_tables, get_connection
from llm.nl_to_sql import nl_to_sql
from security.sql_classifier import classify_sql
from utils.audit_logger import log_query
from utils.env_updater import update_env_variable
import os
from dotenv import load_dotenv

load_dotenv()
app = Flask(__name__)
CORS(app)

@app.route("/", methods=["GET"])
def home():
    return jsonify({"status": "Backend running"}), 200

@app.route("/databases", methods=["GET"])
def databases():
    try:
        return jsonify({"databases": get_databases()})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/tables", methods=["GET"])
def tables():
    try:
        return jsonify({"tables": get_tables()})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/query", methods=["POST"])
def query():
    try:
        data = request.json
        nl_query = data.get("prompt")
        confirm = data.get("confirm", False)
        decision = data.get("decision", "").lower()

        if not nl_query:
            return jsonify({"error": "Prompt is required"}), 400

        # (Later we will auto-fetch schema)
        schema_text = "Use the connected database tables and columns only."

        # NL → SQL
        sql = nl_to_sql(nl_query, schema_text)
        qtype = classify_sql(sql)

        sql_upper = sql.upper()

        # 🟢 SELECT → Just fetch
        if qtype == "DQL":
            pass

        # 🟡 INSERT / UPDATE / CREATE / ALTER → Warning, proceed if confirm=true
        elif qtype in ["DML", "DDL"] and sql_upper.startswith(("INSERT", "UPDATE", "CREATE", "ALTER")):
            if not confirm:
                return jsonify({
                    "sql": sql,
                    "type": qtype,
                    "status": "warning",
                    "message": "This query will modify data or structure. Set confirm=true to proceed."
                }), 403

        # 🟠 GRANT / REVOKE / COMMIT / ROLLBACK / RENAME / SAVEPOINT / SET TRANSACTION
        elif (
            qtype in ["DCL", "TCL"] or
            sql_upper.startswith(("RENAME", "SAVEPOINT", "SET TRANSACTION"))
        ):
            if decision != "yes":
                return jsonify({
                    "sql": sql,
                    "type": qtype,
                    "status": "confirmation_required",
                    "message": "This operation affects permissions or transactions. Are you sure? (yes/no)"
                }), 403

        # 🔴 DELETE / DROP / TRUNCATE → Critical YES/NO
        elif sql_upper.startswith(("DELETE", "DROP", "TRUNCATE")):
            if decision != "yes":
                return jsonify({
                    "sql": sql,
                    "type": qtype,
                    "status": "critical",
                    "message": "⚠ This operation can permanently delete data. Are you sure? (yes/no)"
                }), 403

        # Execute SQL
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute(sql)

        # Commit for non-SELECT
        if qtype != "DQL":
            conn.commit()
            cursor.close()
            conn.close()

            # 🧾 AUDIT LOG
            log_query(qtype, sql)

            return jsonify({
                "sql": sql,
                "type": qtype,
                "status": "executed",
                "message": f"{qtype} query executed successfully and logged"
            })


        # For SELECT
        rows = cursor.fetchall()
        columns = [col[0] for col in cursor.description]

        cursor.close()
        conn.close()

        return jsonify({
            "sql": sql,
            "type": qtype,
            "columns": columns,
            "rows": rows
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/audit-logs", methods=["GET"])
def get_audit_logs():
    try:
        # Optional query params
        limit = request.args.get("limit", 50)
        operation_type = request.args.get("type")  # DML, DDL, etc.

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        if operation_type:
            query = """
                SELECT id, operation_type, sql_query, executed_at
                FROM audit_logs
                WHERE operation_type = %s
                ORDER BY executed_at DESC
                LIMIT %s
            """
            cursor.execute(query, (operation_type, int(limit)))
        else:
            query = """
                SELECT id, operation_type, sql_query, executed_at
                FROM audit_logs
                ORDER BY executed_at DESC
                LIMIT %s
            """
            cursor.execute(query, (int(limit),))

        logs = cursor.fetchall()

        cursor.close()
        conn.close()

        return jsonify({
            "count": len(logs),
            "logs": logs
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/change-database", methods=["POST"])
def change_database():
    try:
        data = request.json
        new_db = data.get("database")

        if not new_db:
            return jsonify({"error": "Database name is required"}), 400

        # Update .env file
        update_env_variable("DB_NAME", new_db)

        # Reload environment variables
        load_dotenv(override=True)

        return jsonify({
            "status": "success",
            "message": f"Database changed to '{new_db}' successfully",
            "active_database": new_db
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/current-database", methods=["GET"])
def current_database():
    return jsonify({
        "active_database": os.getenv("DB_NAME")
    })

if __name__ == "__main__":
    print("Starting Flask server...")
    app.run(host="127.0.0.1", port=5000, debug=True)
