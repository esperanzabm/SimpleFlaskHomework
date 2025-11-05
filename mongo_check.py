from pymongo import MongoClient

try:
    client = MongoClient("mongodb://localhost:27017/")
    db = client.test_database
    print("✅ Conexión a MongoDB exitosa. Bases de datos:")
    print(client.list_database_names())
except Exception as e:
    print("❌ Error de conexión:", e)