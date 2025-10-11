# Cyber Threat AI Agent

## Overview

The **Cyber Threat AI Agent** is an advanced platform leveraging machine learning and modern web technologies to detect, predict, and visualize cyber threats in real-time. Using models like **XGBoost**, the system autonomously analyzes network data, providing proactive defense and insightful dashboards for threat monitoring and auditing.

---

## Features

- **Real-time Threat Detection**: Continuously analyzes network activity, classifying events as benign or specific threat types.
- **Robust ML Backend**: Employs XGBoost and Python-based models for high-accuracy threat prediction.
- **Interactive Dashboard**: React-based web interface with rich visualizations powered by Recharts.
- **Persistent Logging**: Stores threat events in a Supabase (PostgreSQL) database for audit trails and analysis.
- **Modular Architecture**: Clear separation between frontend, backend (API), and model server.
- **Extensive Dataset Support**: Built and evaluated on datasets like CSE-CIC-IDS2018.

---

## Language Composition

- **JavaScript (React/Node.js)**: 47.7%
- **Jupyter Notebook**: 46.4%
- **CSS**: 3.7%
- **Python**: 2.1%
- **HTML**: 0.1%

---

## System Architecture

```
[ User ] ←→ [ React Frontend ] ←→ [ Node.js Backend API ] ←→ [ Python Model Server ]
                                                      ↘
                                              [ Supabase (DB) ]
```

---

## Setup Instructions

### Prerequisites

- **Node.js** (v18 or later)
- **Python** (v3.9 or later)

### Installation Steps

1. **Clone the repository:**
   ```bash
   git clone https://github.com/yaswanthkillampalli/cyber-threat-ai-agent.git
   cd cyber-threat-ai-agent
   ```

2. **Set up environment variables:**

   - Create a `.env` file in the `backend` directory:
     ```ini
     MODEL_API_URL=http://127.0.0.1:5000/
     PORT=8000
     USE_MOCK_MODEL=true
     SUPABASE_URL=https://uvajtztgfejjhopfinue.supabase.co
     SUPABASE_ANON_KEY=sb_publishable_H67GZ6Fn1qPQhuwq-oKYsA_QFcQHVHL
     MODEL_API_URL_SINGLE=http://127.0.0.1:5000/predict/single
     MODEL_API_URL_BATCH=http://127.0.0.1:5000/predict/batch
     ```

   - Create a `.env` file in the `frontend` directory:
     ```ini
     VITE_API_BASE_URL="http://localhost:8000"
     ```

3. **Install dependencies:**

   - **Frontend:**
     ```bash
     cd frontend
     npm install
     npm run dev
     # App runs at http://localhost:5173
     ```

   - **Backend:**
     ```bash
     cd backend
     npm install
     npm start
     # API runs at http://localhost:8000
     ```

   - **Model Server:**
     ```bash
     cd model-server
     pip install -r requirements.txt
     python app.py
     # Flask server at http://localhost:5000
     ```

---

## Usage

- Open the React dashboard at [http://localhost:5173](http://localhost:5173) to interact with the system.
- The backend API operates at [http://localhost:8000](http://localhost:8000), forwarding requests to the model server for predictions.

---

## Datasets

- Main dataset: **CSE-CIC-IDS2018** (for threat classification).
- See `notebooks/` for Jupyter Notebook explorations and model training.

---

## Deployment Links

- **Frontend Dashboard**: [https://model-frontend.yashdev.tech/](https://model-frontend.yashdev.tech/)
- **Backend API Health**: [https://model-backend.yashdev.tech/health](https://model-backend.yashdev.tech/health)

---

## Troubleshooting

- Ensure all `.env` files are correctly configured.
- Start the model server before the backend API.
- For database errors, check Supabase credentials and network connectivity.

---

## Contribution Guidelines

We welcome contributions!

1. Fork the repository.
2. Create a branch:
   ```bash
   git checkout -b feature/your-feature-name
   ```
3. Commit your changes:
   ```bash
   git commit -m "Describe your change"
   ```
4. Push and open a Pull Request.

---

## License

This project is licensed under the **MIT License**. See the `LICENSE.md` file for details.
