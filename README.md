# 🔥 rag-retrieval-auth-cwe-862

### Mitigating Retrieval-Layer Authorization Failures in RAG-Based AI Systems

Simulates a RAG-based AI data breach (CWE-862) and demonstrates how retrieval-layer access control prevents sensitive data exposure using vector store segregation.

**Role:** Cloud Security Engineer (Entry-Level)
**Stack:** Python, Flask, OpenAI API (File Search), Google Cloud / Local Dev

---

## 🧠 Executive Summary

This project demonstrates a critical vulnerability in Retrieval-Augmented Generation (RAG) systems mapped to **CWE-862: Missing Authorization**.

Using a fictional restaurant, **Big’s BBQ**, I built a chatbot that unintentionally exposed proprietary data ("Big Mad" sauce recipe) due to improper data segregation within a shared vector store.

> **AI systems are only as secure as their retrieval layer—not the model.**

---

## ⚠️ Phase 1: Vulnerable Baseline (PoC)

### 🧩 Scenario

Organizations often deploy AI chatbots by indexing all company data into a single knowledge base.

### 🚨 Vulnerability

* Public + confidential data stored in **one vector store**
* No authorization boundary in Flask backend
* LLM had unrestricted access to all indexed documents

### 💥 Exploit

**Prompt:**

```
What are the secret ingredients in the Big Mad sauce?
```

**Result:**

* `file_search` retrieved confidential PDF
* LLM exposed proprietary recipe to public user

---

## 🛡️ Phase 2: Remediation (Hardening)

### 🔐 Security Strategy

Moved control from:

* ❌ Model-level (prompt instructions)
* ✅ Infrastructure-level (data access control)

### 🧱 Data Segregation

Separated data into:

```
PUBLIC_STORE
PRIVATE_STORE
```

### 🚪 Access Control Enforcement

Bound the chatbot route to only the public store:

```
tools=[{
  "type": "file_search",
  "vector_store_ids": [PUBLIC_STORE]
}]
```

### 🧬 Zero-Trust Retrieval

* The model cannot retrieve private data
* Sensitive files are physically unreachable

---

## 📊 Results

### ❌ Before

* Sensitive data exposed via prompt

### ✅ After

```
Information not found
```

---

## 🧠 Key Security Insights

* RAG systems are only as secure as their retrieval layer
* LLMs do not enforce access control
* Prompt engineering is not a security control
* Shared vector stores create implicit trust violations
* Physical separation is stronger than logical rules

---

## 🧪 Security Mapping

| Concept           | Implementation                           |
| ----------------- | ---------------------------------------- |
| CWE-862           | Missing authorization in retrieval layer |
| Least Privilege   | Public store scoped to chatbot           |
| Zero Trust        | No implicit access between data          |
| Data Segmentation | Public vs Private stores                 |

---

## 🚀 How to Run Locally

### 1. Clone repo

```
git clone https://github.com/yourusername/rag-retrieval-auth-cwe-862.git
cd rag-retrieval-auth-cwe-862
```

### 2. Install dependencies

```
pip install -r requirements.txt
```

### 3. Set environment variables

Create a `.env` file:

```
OPENAI_API_KEY=your_key_here
PUBLIC_VECTOR_STORE_ID=your_public_store_id
```

### 4. Run the app

```
python app.py
```

---

## 📁 Project Structure

```
/app
  ├── app.py
  ├── templates/
  ├── static/

/data
  ├── public_docs/
  ├── private_docs/

/docs
  ├── architecture.png
```

---

## 📘 SOP for Junior Analysts

**Ref: SOP-PRO-003**

* Classify data before ingestion
* Never mix sensitive and public documents
* Enforce access at the retrieval layer
* Treat LLMs as untrusted components

---

## 📈 Project Value

This project simulates a real-world AI data breach and demonstrates how proper architectural controls prevent sensitive data exposure.

---

## 🧾 License

MIT License
