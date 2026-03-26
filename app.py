from flask import Flask, request, jsonify
from flask_cors import CORS

from db.connection import get_databases, get_tables, get_connection
from llm.nl_to_sql import nl_to_sql
from security.sql_classifier import classify_sql
from utils.audit_logger import log_query
from utils.env_updater import update_env_variable
import os
from dotenv import load_dotenv
from pymongo import MongoClient
import bcrypt 
import jwt
from datetime import datetime, timedelta
from bson.objectid import ObjectId
import pymysql

load_dotenv()
app = Flask(__name__)
CORS(app)
MONGO_URI = os.getenv("MONGO_URI")
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")
JWT_EXPIRATION_HOURS = int(os.getenv("JWT_EXPIRATION_HOURS", 8))

client = MongoClient(MONGO_URI)
db = client["nl_dbq"]

developers = db["developers"]
companies = db["companies"]
audit_logs = db["audit_logs"]
schema_cache = db["schema_cache"]
from functools import wraps
from flask import request, jsonify
import jwt
import os

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):

        token = None

        # Get token from Authorization header
        if "Authorization" in request.headers:
            auth_header = request.headers["Authorization"]

            # Expected: Bearer <token>
            if auth_header.startswith("Bearer "):
                token = auth_header.split(" ")[1]

        if not token:
            return jsonify({"error": "Token is missing"}), 401

        try:
            data = jwt.decode(token, JWT_SECRET_KEY, algorithms=["HS256"])

            # Attach user to request
            request.user = data

        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token"}), 401

        return f(*args, **kwargs)

    return decorated

import re

def extract_collection(nl_query):
    query = nl_query.lower()

    # 🔹 Case 1: "from <collection>"
    match = re.search(r"from\s+(\w+)", query)
    if match:
        return match.group(1)

    # 🔹 Case 2: "into <collection>"
    match = re.search(r"into\s+(\w+)", query)
    if match:
        return match.group(1)

    # 🔹 Case 3: "update <collection>"
    match = re.search(r"update\s+(\w+)", query)
    if match:
        return match.group(1)

    # 🔹 Case 4: "delete <collection>"
    match = re.search(r"delete\s+(\w+)", query)
    if match:
        return match.group(1)

    # 🔹 Case 5: fallback → first plural noun (simple heuristic)
    words = query.split()

    for word in words:
        if word.endswith("s"):  # users, orders, products
            return word

    # 🔹 Final fallback
    return "users"

def extract_mysql_schema(creds, db_name):
    conn = pymysql.connect(
        host=creds["db_host"],
        user=creds["db_user"],
        password=creds["db_password"],
        port=creds["db_port"],
        database=db_name
    )
    cursor = conn.cursor()

    cursor.execute("SHOW TABLES")
    tables = cursor.fetchall()

    schema = []

    for table in tables:
        table_name = table[0]

        cursor.execute(f"DESCRIBE {table_name}")
        columns = [col[0] for col in cursor.fetchall()]

        schema.append({
            "table_name": table_name,
            "columns": columns
        })

    cursor.close()
    conn.close()

    return schema

def nl_to_mongo_full(nl_query):
    query = nl_query.lower()
    mongo_query = {}

    pattern = r"(\w+)\s*(=|>|<|>=|<=)\s*([\w@.\-]+)"
    matches = re.findall(pattern, query)

    conditions = []

    for field, op, value in matches:
        if value.isdigit():
            value = int(value)

        if op == "=":
            conditions.append({field: value})
        elif op == ">":
            conditions.append({field: {"$gt": value}})
        elif op == "<":
            conditions.append({field: {"$lt": value}})
        elif op == ">=":
            conditions.append({field: {"$gte": value}})
        elif op == "<=":
            conditions.append({field: {"$lte": value}})

    if " and " in query:
        mongo_query["$and"] = conditions
    elif " or " in query:
        mongo_query["$or"] = conditions
    elif conditions:
        mongo_query = conditions[0]

    # contains / like
    if "contains" in query:
        parts = query.split("contains")
        field = parts[0].split()[-1]
        value = parts[1].strip()
        mongo_query[field] = {"$regex": value, "$options": "i"}

    return mongo_query

def extract_mongo_schema(mongo_uri, db_name):
    client = MongoClient(mongo_uri)
    db = client[db_name]

    collections = db.list_collection_names()

    schema = []

    for col in collections:
        doc = db[col].find_one()

        if doc:
            fields = list(doc.keys())
        else:
            fields = []

        schema.append({
            "table_name": col,
            "columns": fields
        })

    return schema

def sync_schema_internal(owner_id, db_name, owner_type="company"):

    if owner_type == "company":
        owner = companies.find_one({"_id": ObjectId(owner_id)})
        db_list = owner.get("databases", [])

    elif owner_type == "personal":
        owner = developers.find_one({"_id": ObjectId(owner_id)})
        db_list = owner.get("databases", [])

    else:
        return

    db_config = next(
        (db for db in db_list if db["db_name"] == db_name),
        None
    )

    if not db_config:
        return

    db_type = db_config["db_type"]
    creds = db_config["credentials"]

    if db_type == "mysql":
        schema = extract_mysql_schema(creds, db_name)

    elif db_type == "mongodb":
        schema = extract_mongo_schema(creds["mongo_uri"], db_name)

    else:
        return

    schema_cache.update_one(
        {
            "owner_type": owner_type,
            "owner_id": ObjectId(owner_id),
            "database_name": db_name
        },
        {
            "$set": {
                "tables": schema,
                "last_synced": datetime.utcnow()
            }
        },
        upsert=True
    )

@app.route("/", methods=["GET"])
def home():
    return jsonify({"status": "Backend running"}), 200

# @app.route("/databases", methods=["GET"])
# def databases():
#     try:
#         return jsonify({"databases": get_databases()})
#     except Exception as e:
#         return jsonify({"error": str(e)}), 500

# @app.route("/tables", methods=["GET"])
# def tables():
#     try:
#         return jsonify({"tables": get_tables()})
#     except Exception as e:
#         return jsonify({"error": str(e)}), 500
# @app.route("/change-database", methods=["POST"])
# def change_database():
#     try:
#         data = request.json
#         new_db = data.get("database")

#         if not new_db:
#             return jsonify({"error": "Database name is required"}), 400

#         # Update .env file
#         update_env_variable("DB_NAME", new_db)

#         # Reload environment variables
#         load_dotenv(override=True)

#         return jsonify({
#             "status": "success",
#             "message": f"Database changed to '{new_db}' successfully",
#             "active_database": new_db
#         })

#     except Exception as e:
#         return jsonify({"error": str(e)}), 500

# @app.route("/current-database", methods=["GET"])
# def current_database():
#     return jsonify({
#         "active_database": os.getenv("DB_NAME")
#     })
@app.route("/database/schema/sync", methods=["POST"])
@token_required
def sync_schema():
    try:
        data = request.json
        db_name = data.get("database_name")

        if not db_name:
            return jsonify({"error": "database_name required"}), 400

        user = request.user
        role = user.get("role")
        company_id = user.get("company_id")

        # 🔒 ONLY admin + pdev allowed
        if role not in ["super_admin", "personal_dev"]:
            return jsonify({"error": "Permission denied"}), 403

        company = companies.find_one({"_id": ObjectId(company_id)})

        if not company:
            return jsonify({"error": "Company not found"}), 404

        db_config = next(
            (db for db in company.get("databases", []) if db["db_name"] == db_name),
            None
        )

        if not db_config:
            return jsonify({"error": "Database not found"}), 404

        db_type = db_config["db_type"]
        creds = db_config["credentials"]

        # 🔍 Extract schema
        if db_type == "mysql":
            schema = extract_mysql_schema(creds, db_name)

        elif db_type == "mongodb":
            schema = extract_mongo_schema(creds["mongo_uri"], db_name)

        else:
            return jsonify({"error": "Unsupported DB"}), 400

        # 💾 Save schema (multi-tenant safe)
        schema_cache.update_one(
            {
                "owner_type": "company",
                "owner_id": ObjectId(company_id),
                "database_name": db_name
            },
            {
                "$set": {
                    "tables": schema,
                    "last_synced": datetime.utcnow()
                }
            },
            upsert=True
        )

        return jsonify({
            "message": "Schema synced successfully",
            "tables": schema
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/database/schema", methods=["GET"])
@token_required
def get_schema():
    try:
        db_name = request.args.get("db")

        if not db_name:
            return jsonify({"error": "db is required"}), 400

        user = request.user
        company_id = user.get("company_id")

        schema = schema_cache.find_one({
            "owner_type": "company",
            "owner_id": ObjectId(company_id),
            "database_name": db_name
        })

        if not schema:
            return jsonify({"error": "Schema not found. Run sync first."}), 404

        # Convert ObjectId safely
        schema["_id"] = str(schema["_id"])
        schema["owner_id"] = str(schema["owner_id"])

        return jsonify(schema)

    except Exception as e:
        return jsonify({"error": str(e)}), 500
    

@app.route("/admin/database/add", methods=["POST"])
@token_required
def add_database():
    try:
        data = request.json

        # 🔐 Get user from JWT
        user = request.user

        # ✅ Only admin allowed
        if user.get("role") != "super_admin":
            return jsonify({"error": "Only admin can add database"}), 403

        company_id = user.get("company_id")

        # 📦 Get DB details
        db_name = data.get("db_name")
        db_type = data.get("db_type")
        credentials = data.get("credentials")

        if not all([db_name, db_type, credentials]):
            return jsonify({"error": "db_name, db_type and credentials are required"}), 400

        # 🔍 Check company exists
        company = companies.find_one({"_id": ObjectId(company_id)})

        if not company:
            return jsonify({"error": "Company not found"}), 404

        # 🚫 Prevent duplicate DB
        for db in company.get("databases", []):
            if db["db_name"] == db_name:
                return jsonify({"error": "Database already exists"}), 400

        # 🆕 New DB object
        new_db = {
            "db_name": db_name,
            "db_type": db_type,
            "credentials": credentials,
            "status": "active",
            "created_at": datetime.utcnow()
        }

        # 💾 Push into company
        companies.update_one(
            {"_id": ObjectId(company_id)},
            {"$push": {"databases": new_db}}
        )
        try:
            sync_schema_internal(company_id, db_name)
        except:
            print("❌ Schema sync failed:", str(e))
            return jsonify({"error": f"Schema sync failed: {str(e)}"}), 500
        
        return jsonify({
            "message": "Database added successfully",
            "database": {
                "db_name": db_name,
                "db_type": db_type
            }
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/tables", methods=["GET"])
@token_required
def tables():
    try:
        db_name = request.args.get("db")

        if not db_name:
            return jsonify({"error": "Database name is required"}), 400

        user = request.user
        company_id = user.get("company_id")

        company = companies.find_one({"_id": ObjectId(company_id)})

        db_config = None
        for db in company.get("databases", []):
            if db["db_name"] == db_name:
                db_config = db
                break

        if not db_config:
            return jsonify({"error": "Database not found"}), 404

        creds = db_config["credentials"]

        conn = pymysql.connect(
            host=creds["db_host"],
            user=creds["db_user"],
            password=creds["db_password"],
            port=creds["db_port"],
            database=db_name
        )

        cursor = conn.cursor()

        cursor.execute("SHOW TABLES")
        tables = [row[0] for row in cursor.fetchall()]

        cursor.close()
        conn.close()

        return jsonify({"tables": tables})  # ✅ CORRECT

    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
    
@app.route("/company/databases", methods=["GET"])
@token_required
def get_company_databases():
    try:
        user = request.user
        company_id = user.get("company_id")

        company = companies.find_one({"_id": ObjectId(company_id)})

        if not company:
            return jsonify({"error": "Company not found"}), 404

        dbs = company.get("databases", [])

        # Convert ObjectId if needed
        for db in dbs:
            db["created_at"] = str(db.get("created_at"))

        return jsonify({
            "count": len(dbs),
            "databases": dbs
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
@app.route("/query", methods=["POST"])
@token_required
def query():
    try:
        data = request.json
        nl_query = data.get("prompt")
        confirm = data.get("confirm", False)
        decision = data.get("decision", "").lower()
        db_name = data.get("database_name")

        if not nl_query:
            return jsonify({"error": "Prompt is required"}), 400

        if not db_name:
            return jsonify({"error": "database_name is required"}), 400

        # 🔐 JWT user
        user = request.user
        role = user.get("role")
        actor_id = user.get("user_id")
        company_id = user.get("company_id")

        # 🔥 HANDLE COMPANY vs PERSONAL DEV

        db_config = None
        owner_type = None

        if user.get("mode") == "company":

            # 🏢 COMPANY FLOW
            company = companies.find_one({"_id": ObjectId(company_id)})
            if not company:
                return jsonify({"error": "Company not found"}), 404

            for db in company.get("databases", []):
                if db["db_name"] == db_name:
                    db_config = db
                    break

            owner_type = "company"

        elif user.get("mode") == "personal":

            # 🧑‍💻 PDEV FLOW
            dev = developers.find_one({"_id": ObjectId(actor_id)})
            if not dev:
                return jsonify({"error": "Developer not found"}), 404

            for db in dev.get("databases", []):
                if db["db_name"] == db_name:
                    db_config = db
                    break

            owner_type = "personal"

        # ❌ DB not found
        if not db_config:
            return jsonify({"error": "Database not found"}), 404

        if not db_config:
            return jsonify({"error": "Database not found"}), 404

        db_type = db_config.get("db_type")
        creds = db_config.get("credentials")

        # (Schema placeholder)
        schema_doc = schema_cache.find_one({
            "owner_type": owner_type,
            "owner_id": ObjectId(company_id if owner_type == "company" else actor_id),
            "database_name": db_name
        })

        if schema_doc:
            schema_text = str(schema_doc["tables"])
        else:
            schema_text = "Use available tables and columns"

        # NL → SQL (only for MySQL)
        sql = nl_to_sql(nl_query, schema_text)
        qtype = classify_sql(sql)
        sql_upper = sql.upper()

        # 🚫 Employee restriction
        if role == "employee" and sql_upper.startswith(("DELETE", "DROP", "TRUNCATE")):
            return jsonify({
                "status": "blocked",
                "message": "Employees cannot run destructive queries"
            }), 403

        # 🟡 DML / DDL confirmation
        if qtype in ["DML", "DDL"] and sql_upper.startswith(("INSERT", "UPDATE", "CREATE", "ALTER")):
            if not confirm:
                return jsonify({
                    "sql": sql,
                    "type": qtype,
                    "status": "warning",
                    "message": "Set confirm=true to proceed."
                }), 403

        # 🟠 DCL / TCL confirmation
        if (
            qtype in ["DCL", "TCL"] or
            sql_upper.startswith(("RENAME", "SAVEPOINT", "SET TRANSACTION"))
        ):
            if decision != "yes":
                return jsonify({
                    "sql": sql,
                    "type": qtype,
                    "status": "confirmation_required",
                    "message": "Are you sure? (yes/no)"
                }), 403

        # 🔴 Critical operations
        if sql_upper.startswith(("DELETE", "DROP", "TRUNCATE")):
            if decision != "yes":
                return jsonify({
                    "sql": sql,
                    "type": qtype,
                    "status": "critical",
                    "message": "⚠ Permanent delete. Confirm?"
                }), 403

        # =========================
        # 🚀 MYSQL EXECUTION
        # =========================
        if db_type == "mysql":

            conn = pymysql.connect(
                host=creds["db_host"],
                user=creds["db_user"],
                password=creds["db_password"],
                port=creds["db_port"],
                database=db_name
            )
            cursor = conn.cursor()

            start_time = datetime.utcnow()
            cursor.execute(sql)

            # 🟢 SELECT
            if qtype == "DQL":
                rows = cursor.fetchall()
                columns = [col[0] for col in cursor.description]

                cursor.close()
                conn.close()

                execution_time = (datetime.utcnow() - start_time).total_seconds() * 1000

                audit_logs.insert_one({
                    "actor_type": role,
                    "actor_id": ObjectId(actor_id) if actor_id else None,
                    "mode": user.get("mode"),
                    "company_id": ObjectId(company_id) if owner_type == "company" else None,
                    "database_name": db_name,
                    "natural_query": nl_query,
                    "generated_query": sql,
                    "operation_type": qtype,
                    "status": "success",
                    "rows_returned": len(rows),
                    "execution_time_ms": execution_time,
                    "executed_at": datetime.utcnow()
                })

                return jsonify({
                    "sql": sql,
                    "type": qtype,
                    "columns": columns,
                    "rows": rows
                })

            # 🔵 Non-SELECT
            conn.commit()
            cursor.close()
            conn.close()

            execution_time = (datetime.utcnow() - start_time).total_seconds() * 1000

            audit_logs.insert_one({
                "actor_type": role,
                "actor_id": ObjectId(actor_id) if actor_id else None,
                "mode": user.get("mode"),
                "company_id": ObjectId(company_id) if owner_type == "company" else None,
                "database_name": db_name,
                "natural_query": nl_query,
                "generated_query": sql,
                "operation_type": qtype,
                "status": "success",
                "rows_returned": 0,
                "execution_time_ms": execution_time,
                "executed_at": datetime.utcnow()
            })

            return jsonify({
                "sql": sql,
                "type": qtype,
                "status": "executed",
                "message": f"{qtype} query executed successfully"
            })

        # =========================
        # 🚀 MONGODB EXECUTION
        # =========================
        elif db_type == "mongodb":

            client = MongoClient(creds["mongo_uri"])
            db = client[db_name]

            start_time = datetime.utcnow()

            collection_name = extract_collection(nl_query)
            collection = db[collection_name]

            query_lower = nl_query.lower()

            # ================= SELECT =================
            if any(x in query_lower for x in ["show", "get", "fetch"]):

                mongo_filter = nl_to_mongo_full(nl_query)
                docs = list(collection.find(mongo_filter).limit(50))

                for doc in docs:
                    doc["_id"] = str(doc["_id"])

                result = {
                    "type": "mongodb",
                    "operation": "find",
                    "collection": collection_name,
                    "filter": mongo_filter,
                    "rows": docs
                }

            # ================= INSERT =================
            elif "insert" in query_lower or "add" in query_lower:

                data_pairs = dict(re.findall(r"(\w+)=([\w@.\-]+)", nl_query))

                res = collection.insert_one(data_pairs)

                result = {
                    "operation": "insert",
                    "collection": collection_name,
                    "inserted_id": str(res.inserted_id)
                }

            # ================= UPDATE =================
            elif "update" in query_lower:

                set_part = re.findall(r"set (.+?) where", query_lower)
                where_part = re.findall(r"where (.+)", query_lower)

                update_data = dict(re.findall(r"(\w+)=([\w@.\-]+)", set_part[0]))
                filter_query = nl_to_mongo_full(where_part[0])

                res = collection.update_many(filter_query, {"$set": update_data})

                result = {
                    "operation": "update",
                    "collection": collection_name,
                    "modified_count": res.modified_count
                }

            # ================= DELETE =================
            elif "delete" in query_lower:

                where_part = re.findall(r"where (.+)", query_lower)
                filter_query = nl_to_mongo_full(where_part[0])

                res = collection.delete_many(filter_query)

                result = {
                    "operation": "delete",
                    "collection": collection_name,
                    "deleted_count": res.deleted_count
                }

            else:
                return jsonify({"error": "Unsupported MongoDB operation"}), 400

            execution_time = (datetime.utcnow() - start_time).total_seconds() * 1000

            audit_logs.insert_one({
                "actor_type": role,
                "actor_id": ObjectId(actor_id) if actor_id else None,
                "mode": user.get("mode"),
                "company_id": ObjectId(company_id) if owner_type == "company" else None,
                "database_name": db_name,
                "natural_query": nl_query,
                "generated_query": str(result),
                "operation_type": "DQL",
                "status": "success",
                "rows_returned": len(result.get("rows", [])),
                "execution_time_ms": execution_time,
                "executed_at": datetime.utcnow()
            })

            return jsonify(result)

        else:
            return jsonify({"error": "Unsupported database type"}), 400

    except Exception as e:

        # 🔐 Safe extraction
        user = getattr(request, "user", None)

        role = user.get("role") if user else None
        mode = user.get("mode") if user else None

        actor_id = ObjectId(user["user_id"]) if user and user.get("user_id") else None

        # ✅ Fix company_id handling
        company_id = None
        if mode == "company" and user.get("company_id"):
            company_id = ObjectId(user["company_id"])

        audit_logs.insert_one({
            "actor_type": role,
            "actor_id": actor_id,
            "mode": mode,
            "company_id": company_id,   # ✅ correct for both flows
            "database_name": data.get("database_name") if data else None,
            "natural_query": data.get("prompt") if data else None,
            "generated_query": None,
            "operation_type": None,
            "status": "failed",
            "error_message": str(e),
            "executed_at": datetime.utcnow()
        })

        return jsonify({"error": str(e)}), 500

@app.route("/audit-logs", methods=["GET"])
def get_audit_logs():
    try:
        limit = int(request.args.get("limit", 50))

        operation_type = request.args.get("type")
        actor_type = request.args.get("actor_type")
        mode = request.args.get("mode")
        company_id = request.args.get("company_id")
        actor_id = request.args.get("actor_id")

        query = {}

        # 🔍 Filters
        if operation_type:
            query["operation_type"] = operation_type

        if actor_type:
            query["actor_type"] = actor_type

        if mode:
            query["mode"] = mode

        if company_id:
            query["company_id"] = ObjectId(company_id)

        if actor_id:
            query["actor_id"] = ObjectId(actor_id)

        logs_cursor = audit_logs.find(query).sort("executed_at", -1).limit(limit)

        logs = []

        for log in logs_cursor:
            log["_id"] = str(log["_id"])

            if log.get("actor_id"):
                log["actor_id"] = str(log["actor_id"])

            if log.get("company_id"):
                log["company_id"] = str(log["company_id"])

            logs.append(log)

        return jsonify({
            "count": len(logs),
            "filters_applied": query,
            "logs": logs
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500

#NEW ENDPOINTS FOR USER AND COMPANY MANAGEMENT

@app.route("/comp/register", methods=["POST"])
def register_company():
    try:
        data = request.json

        company_name = data.get("company_name")
        username = data.get("username")
        email = data.get("email")
        password = data.get("password")
        database = data.get("database")  # ✅ NEW

        if not all([company_name, username, email, password]):
            return jsonify({"error": "All fields required"}), 400

        # Hash password
        password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

        # Create company with DB config
        company = {
            "name": company_name,
            "employees": [],
            "databases": [],
            "created_at": datetime.utcnow(),
            "is_active": True
        }

        # ✅ Add database if provided
        if database:
            company["databases"].append({
                "db_name": database.get("db_name"),
                "db_type": database.get("db_type"),
                "credentials": database.get("credentials"),
                "status": "active",
                "created_at": datetime.utcnow()
            })

        company_id = companies.insert_one(company).inserted_id

        # Create super admin
        admin = {
            "email": email,
            "password_hash": password_hash,
            "username": username,
            "role": "super_admin",
            "mode": "company",
            "company_id": company_id,
            "created_at": datetime.utcnow(),
            "last_login": None,
            "is_active": True
        }

        admin_id = developers.insert_one(admin).inserted_id

        # Update company with admin id
        companies.update_one(
            {"_id": company_id},
            {"$set": {"super_admin_id": admin_id}}
        )
        # 🔥 AUTO SCHEMA SYNC (NEW)
        try:
            if database:
                sync_schema_internal(company_id, database.get("db_name"))
        except Exception as sync_error:
            print("Schema sync failed:", sync_error)
    
        return jsonify({
            "message": "Company registered successfully",
            "company_id": str(company_id),
            "admin_id": str(admin_id)
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
@app.route("/admin/login", methods=["POST"])
def admin_login():
    try:
        data = request.json
        email = data.get("email")
        password = data.get("password")

        user = developers.find_one({"email": email, "role": "super_admin"})

        if not user:
            return jsonify({"error": "Invalid credentials"}), 401

        if not bcrypt.checkpw(password.encode(), user["password_hash"]):
            return jsonify({"error": "Invalid credentials"}), 401

        payload = {
            "user_id": str(user["_id"]),
            "role": user["role"],
            "mode": user["mode"],
            "company_id": str(user["company_id"]),
            "exp": datetime.utcnow() + timedelta(hours=8)
        }

        token = jwt.encode(payload, JWT_SECRET_KEY, algorithm="HS256")

        developers.update_one(
            {"_id": user["_id"]},
            {"$set": {"last_login": datetime.utcnow()}}
        )

        return jsonify({"token": token})

    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
@app.route("/admin/create-employee", methods=["POST"])
@token_required   # 🔥 REQUIRED
def create_employee():
    try:
        data = request.json

        # 🔐 Get admin from JWT
        user = request.user

        if user.get("role") != "super_admin":
            return jsonify({"error": "Only admin can create employees"}), 403

        company_id = user.get("company_id")

        username = data.get("username")
        email = data.get("email")
        password = data.get("password")

        if not all([username, email, password]):
            return jsonify({"error": "All fields required"}), 400

        password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

        employee = {
            "email": email,
            "password_hash": password_hash,
            "username": username,
            "role": "employee",
            "mode": "company",
            "company_id": ObjectId(company_id),
            "created_at": datetime.utcnow(),
            "last_login": None,
            "is_active": True
        }

        emp_id = developers.insert_one(employee).inserted_id

        # ✅ Update company employees list
        companies.update_one(
            {"_id": ObjectId(company_id)},
            {"$push": {"employees": emp_id}}
        )

        return jsonify({
            "message": "Employee created successfully",
            "employee_id": str(emp_id)
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/emp/login", methods=["POST"])
def employee_login():
    try:
        data = request.json

        email = data.get("email")
        password = data.get("password")

        user = developers.find_one({"email": email, "role": "employee"})

        if not user:
            return jsonify({"error": "Invalid credentials"}), 401

        if not bcrypt.checkpw(password.encode(), user["password_hash"]):
            return jsonify({"error": "Invalid credentials"}), 401

        payload = {
            "user_id": str(user["_id"]),
            "role": user["role"],
            "mode": user["mode"],
            "company_id": str(user["company_id"]),
            "exp": datetime.utcnow() + timedelta(hours=8)
        }

        token = jwt.encode(payload, JWT_SECRET_KEY, algorithm="HS256")

        return jsonify({"token": token})

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/pdev/register", methods=["POST"])
def register_pdev():
    try:
        data = request.json

        username = data.get("username")
        email = data.get("email")
        password = data.get("password")
        database = data.get("database")  # 🔥 NEW

        if not all([username, email, password]):
            return jsonify({"error": "All fields required"}), 400

        password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

        dev = {
            "email": email,
            "password_hash": password_hash,
            "username": username,
            "role": "personal_dev",
            "mode": "personal",
            "company_id": None,
            "databases": [],   # 🔥 NEW
            "created_at": datetime.utcnow(),
            "last_login": None,
            "is_active": True
        }

        # ✅ Add initial DB
        if database:
            dev["databases"].append({
                "db_name": database.get("db_name"),
                "db_type": database.get("db_type"),
                "credentials": database.get("credentials"),
                "status": "active",
                "created_at": datetime.utcnow()
            })

        dev_id = developers.insert_one(dev).inserted_id

        # 🔥 OPTIONAL schema sync
        try:
            if database:
                sync_schema_internal(dev_id, database.get("db_name"), owner_type="personal")
        except:
            pass

        return jsonify({
            "message": "Developer registered",
            "developer_id": str(dev_id)
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/pdev/database/add", methods=["POST"])
@token_required
def add_pdev_database():
    try:
        user = request.user

        # 🔒 Only personal_dev allowed
        if user.get("role") != "personal_dev":
            return jsonify({"error": "Only personal_dev allowed"}), 403

        data = request.json

        db_name = data.get("db_name")
        db_type = data.get("db_type")
        credentials = data.get("credentials")

        if not all([db_name, db_type, credentials]):
            return jsonify({"error": "db_name, db_type, credentials required"}), 400

        dev_id = user.get("user_id")

        dev = developers.find_one({"_id": ObjectId(dev_id)})

        if not dev:
            return jsonify({"error": "Developer not found"}), 404

        # 🚫 Prevent duplicate DB
        for db in dev.get("databases", []):
            if db["db_name"] == db_name:
                return jsonify({"error": "Database already exists"}), 400

        new_db = {
            "db_name": db_name,
            "db_type": db_type,
            "credentials": credentials,
            "status": "active",
            "created_at": datetime.utcnow()
        }

        developers.update_one(
            {"_id": ObjectId(dev_id)},
            {"$push": {"databases": new_db}}
        )

        # 🔥 Auto schema sync
        try:
            sync_schema_internal(dev_id, db_name, owner_type="personal")
        except:
            pass

        return jsonify({
            "message": "Database added successfully",
            "database": {
                "db_name": db_name,
                "db_type": db_type
            }
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500
    

@app.route("/pdev/login", methods=["POST"])
def pdev_login():
    try:
        data = request.json

        email = data.get("email")
        password = data.get("password")

        user = developers.find_one({"email": email, "role": "personal_dev"})

        if not user:
            return jsonify({"error": "Invalid credentials"}), 401

        if not bcrypt.checkpw(password.encode(), user["password_hash"]):
            return jsonify({"error": "Invalid credentials"}), 401

        payload = {
            "user_id": str(user["_id"]),
            "role": user["role"],
            "mode": user["mode"],
            "exp": datetime.utcnow() + timedelta(hours=8)
        }

        token = jwt.encode(payload, JWT_SECRET_KEY, algorithm="HS256")

        return jsonify({"token": token})

    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
# @app.route("/auth/logout", methods=["POST"])
# def logout():
#     return jsonify({"message": "Logout successful (client should discard token)"})

@app.route("/admin/profile", methods=["GET"])
@token_required
def get_admin_profile():
    try:
        user = request.user

        if user.get("role") != "super_admin":
            return jsonify({"error": "Unauthorized"}), 403

        admin = developers.find_one({"_id": ObjectId(user["user_id"])})

        if not admin:
            return jsonify({"error": "Admin not found"}), 404

        admin["_id"] = str(admin["_id"])
        admin["company_id"] = str(admin.get("company_id"))

        # ❌ remove password
        admin.pop("password_hash", None)

        return jsonify(admin)

    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
@app.route("/emp/profile", methods=["GET"])
@token_required
def get_emp_profile():
    try:
        user = request.user

        if user.get("role") != "employee":
            return jsonify({"error": "Unauthorized"}), 403

        emp = developers.find_one({"_id": ObjectId(user["user_id"])})

        emp["_id"] = str(emp["_id"])
        emp["company_id"] = str(emp.get("company_id"))

        emp.pop("password_hash", None)

        return jsonify(emp)

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/pdev/profile", methods=["GET"])
@token_required
def get_pdev_profile():
    try:
        user = request.user

        if user.get("role") != "personal_dev":
            return jsonify({"error": "Unauthorized"}), 403

        dev = developers.find_one({"_id": ObjectId(user["user_id"])})

        dev["_id"] = str(dev["_id"])
        dev.pop("password_hash", None)

        return jsonify(dev)

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/admin/profile", methods=["PUT"])
@token_required
def update_admin_profile():
    try:
        user = request.user

        if user.get("role") != "super_admin":
            return jsonify({"error": "Unauthorized"}), 403

        data = request.json

        update_data = {}

        if "username" in data:
            update_data["username"] = data["username"]

        if "password" in data:
            update_data["password_hash"] = bcrypt.hashpw(
                data["password"].encode(), bcrypt.gensalt()
            )

        developers.update_one(
            {"_id": ObjectId(user["user_id"])},
            {"$set": update_data}
        )

        return jsonify({"message": "Admin profile updated"})

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/emp/profile", methods=["PUT"])
@token_required
def update_emp_profile():
    try:
        user = request.user

        if user.get("role") != "employee":
            return jsonify({"error": "Unauthorized"}), 403

        data = request.json

        update_data = {}

        if "username" in data:
            update_data["username"] = data["username"]

        if "password" in data:
            update_data["password_hash"] = bcrypt.hashpw(
                data["password"].encode(), bcrypt.gensalt()
            )

        developers.update_one(
            {"_id": ObjectId(user["user_id"])},
            {"$set": update_data}
        )

        return jsonify({"message": "Employee profile updated"})

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/pdev/profile", methods=["PUT"])
@token_required
def update_pdev_profile():
    try:
        user = request.user

        if user.get("role") != "personal_dev":
            return jsonify({"error": "Unauthorized"}), 403

        data = request.json

        update_data = {}

        if "username" in data:
            update_data["username"] = data["username"]

        if "password" in data:
            update_data["password_hash"] = bcrypt.hashpw(
                data["password"].encode(), bcrypt.gensalt()
            )

        developers.update_one(
            {"_id": ObjectId(user["user_id"])},
            {"$set": update_data}
        )

        return jsonify({"message": "Personal dev profile updated"})

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/logout", methods=["POST"])
@token_required
def logout():
    return jsonify({
        "message": "Logged out successfully (client should delete token)"
    })

@app.route("/admin/database/delete", methods=["DELETE"])
@token_required
def delete_company_database():
    try:
        user = request.user

        # 🔒 Only admin
        if user.get("role") != "super_admin":
            return jsonify({"error": "Only admin allowed"}), 403

        company_id = user.get("company_id")

        data = request.json
        db_name = data.get("db_name")

        if not db_name:
            return jsonify({"error": "db_name required"}), 400

        # 🔍 Check company
        company = companies.find_one({"_id": ObjectId(company_id)})
        if not company:
            return jsonify({"error": "Company not found"}), 404

        # 🚫 Check DB exists
        db_exists = any(db["db_name"] == db_name for db in company.get("databases", []))
        if not db_exists:
            return jsonify({"error": "Database not found"}), 404

        # 🗑 Remove DB
        companies.update_one(
            {"_id": ObjectId(company_id)},
            {"$pull": {"databases": {"db_name": db_name}}}
        )

        # 🧹 Remove schema cache
        schema_cache.delete_many({
            "owner_type": "company",
            "owner_id": ObjectId(company_id),
            "database_name": db_name
        })

        return jsonify({
            "message": "Database deleted successfully",
            "db_name": db_name
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/pdev/database/delete", methods=["DELETE"])
@token_required
def delete_pdev_database():
    try:
        user = request.user

        # 🔒 Only pdev
        if user.get("role") != "personal_dev":
            return jsonify({"error": "Only personal_dev allowed"}), 403

        dev_id = user.get("user_id")

        data = request.json
        db_name = data.get("db_name")

        if not db_name:
            return jsonify({"error": "db_name required"}), 400

        dev = developers.find_one({"_id": ObjectId(dev_id)})
        if not dev:
            return jsonify({"error": "Developer not found"}), 404

        db_exists = any(db["db_name"] == db_name for db in dev.get("databases", []))
        if not db_exists:
            return jsonify({"error": "Database not found"}), 404

        # 🗑 Remove DB
        developers.update_one(
            {"_id": ObjectId(dev_id)},
            {"$pull": {"databases": {"db_name": db_name}}}
        )

        # 🧹 Remove schema cache
        schema_cache.delete_many({
            "owner_type": "personal",
            "owner_id": ObjectId(dev_id),
            "database_name": db_name
        })

        return jsonify({
            "message": "Database deleted successfully",
            "db_name": db_name
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
if __name__ == "__main__":
    print("Starting Flask server...")
    app.run(host="127.0.0.1", port=5000, debug=True)
