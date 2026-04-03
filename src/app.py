"""
================================================================================
PROJECT: Big’s BBQ File Search Chatbot (Prometheus)
MODULE: Flask Backend (Phase 2: Fixed Architecture)
AUTHOR: Jermaine Hunter (HunterCloudSec)
DATE: 2026-03-28
--------------------------------------------------------------------------------
STATUS: FIXED ARCHITECTURE.
Public chatbot is restricted to the PUBLIC vector store only.
Private documents remain isolated in a separate vector store.
================================================================================
"""
import os
from flask import Flask, render_template, request, jsonify
from openai import OpenAI
from dotenv import load_dotenv

load_dotenv("../.env")

app = Flask(
    __name__,
    template_folder="web/templates",
    static_folder="web/static"
)

client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

# FIXED: public chatbot uses only the PUBLIC vector store
PUBLIC_VECTOR_STORE_ID = os.getenv("PUBLIC_VECTOR_STORE_ID")

if not PUBLIC_VECTOR_STORE_ID:
    raise ValueError("PUBLIC_VECTOR_STORE_ID is missing from .env")


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/apply")
def apply():
    return render_template("apply.html")


@app.route("/menu")
def menu():
    return render_template("menu.html")


@app.route("/missions")
def missions():
    return render_template("missions.html")


@app.route("/chat", methods=["POST"])
def chat():
    try:
        user_message = request.json.get("message", "").strip()

        if not user_message:
            return jsonify({"reply": "Please enter a message."}), 400

        response = client.responses.create(
            model="gpt-4o",
            input=user_message,
            tools=[{
                "type": "file_search",
                "vector_store_ids": [PUBLIC_VECTOR_STORE_ID],
                "max_num_results": 3
            }] # type: ignore
        )

        return jsonify({"reply": response.output_text})

    except Exception as e:
        return jsonify({"reply": f"Backend error: {str(e)}"}), 500


if __name__ == "__main__":
    app.run(debug=True)