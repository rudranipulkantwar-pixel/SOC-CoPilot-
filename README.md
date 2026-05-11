# 🛡️ SOC Copilot – AI-Powered SOC Analyst Dashboard

SOC Copilot is an **AI-driven Security Operations Center (SOC) assistant** that helps analysts **analyze logs, classify incident severity, map MITRE ATT&CK techniques, and generate incident summaries with mitigation steps** — all via an interactive **Streamlit dashboard**.

This project mirrors **real-world SOC workflows** using structured log parsing, rule-based detection, and **local LLM reasoning**.

---

## 🚀 Features

- 🔍 **Log Ingestion & Parsing**
  - Extracts platform, timestamps, and indicators from raw logs
- 🚨 **Severity Classification**
  - LOW / MEDIUM / HIGH / CRITICAL using rules + AI
- 🧠 **LLM-Powered Reasoning**
  - Local LLMs (Ollama: Mistral / LLaMA) for analysis
- 🎯 **MITRE ATT&CK Mapping**
  - Detects relevant tactics & techniques
- 📝 **Incident Summary & Mitigation**
  - Human-readable reports and remediation guidance
- 📊 **Interactive SOC Dashboard**
  - Real-time investigation using Streamlit

---

## 🧰 Tech Stack

| Category | Technology |
|---|---|
| Language | Python |
| Dashboard | Streamlit |
| AI / LLM | Ollama (Mistral 7B / LLaMA) |
| Orchestration | LangChain |
| Threat Framework | MITRE ATT&CK |
| Data | Pandas |
| Visualization | Plotly |
| Version Control | Git & GitHub |

---

## 🏗️ Project Structure

soc-copilot/
│
├── app.py # Streamlit SOC dashboard
├── modules/ # Core SOC logic
│ ├── init.py
│ ├── log_parser.py
│ ├── severity_engine.py
│ ├── llm_engine.py
│ ├── langchain_pipeline.py
│ ├── mitre_engine.py
│ └── elastic_client.py
│
├── data/ # Sample / ingested logs
├── output/ # Generated outputs (ignored)
├── env/ # Virtual environment (ignored)
│
├── .gitignore
├── requirements.txt
└── README.md

---

## 🔄 SOC Analysis Flow

1. **Log Input** → raw logs provided via UI/file  
2. **Parsing** → platform, timestamps, indicators extracted  
3. **Severity Analysis** → rules + AI classification  
4. **MITRE Mapping** → tactics & techniques identified  
5. **LLM Reasoning** → summary & mitigation generated  
6. **Dashboard View** → analyst investigates in one place  

---

## ▶️ Run Locally

### 1) Clone

git clone https://github.com/Nileshrak305/soc_copilot.git
cd soc-copilot
### 2) Virtual Environment
python -m venv env
env\Scripts\activate   # Windows

### 3) Install Dependencies
pip install -r requirements.txt

### 4) Start App
streamlit run app.py

🤖 LLM Setup (Ollama)

### Install Ollama and pull a model:

ollama pull mistral or
ollama pull llama3

Ensure Ollama is running locally before starting the app.

### 🎯 Use Cases

SOC log triage & investigation

Blue-team training simulations

AI-assisted incident analysis

Threat detection practice

### 🔐 Security Practices

Virtual environments & outputs ignored via .gitignore

No secrets committed

Modular, auditable code

Local LLMs (no data exfiltration)

### 🛣️ Roadmap

Real-time Elasticsearch ingestion

SIEM integrations

Risk scoring & trends

Dockerized deployment

Automated incident ticketing

### 💼 Resume Highlight

Built an AI-powered SOC dashboard using Python, Streamlit, LangChain, and MITRE ATT&CK to analyze logs, classify severity, and generate automated incident summaries with local LLMs.

### 👤 Author

Rudrani Pulkantwar
SOC & Security Enthusiast
GitHub: https://github.com/Nileshrak305

⭐ If you find this useful, please star the repository!
