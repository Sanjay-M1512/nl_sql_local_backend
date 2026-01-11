from groq import Groq
from config import GROQ_API_KEY

client = Groq(api_key=GROQ_API_KEY)

def clean_sql(sql: str):
    # Remove markdown code blocks
    sql = sql.replace("```sql", "").replace("```", "")
    return sql.strip()

def nl_to_sql(nl_query, schema_text):
    prompt = f"""
You are a SQL expert.

Database schema:
{schema_text}

User request: "{nl_query}"

Rules:
- Use only tables and columns from the schema.
- Do not hallucinate columns.
- Do not add explanations.
- Output ONLY valid SQL.
"""

    completion = client.chat.completions.create(
        model="llama-3.1-8b-instant",
        messages=[{"role": "user", "content": prompt}],
        temperature=0
    )

    raw_sql = completion.choices[0].message.content.strip()
    cleaned_sql = clean_sql(raw_sql)

    return cleaned_sql
