from mongo_config import init_mongo
from flask import Flask

app = Flask(__name__)

# CONFIG TEMPORAL PARA PRUEBA (Mongo local)
app.config["MONGO_URI"] = "mongodb://localhost:27017"

mongo = init_mongo(app)

try:
    mongo.db.command("ping")
    print("✅ Conexión a MongoDB exitosa")
except Exception as e:
    print("❌ Error de conexión:", e)