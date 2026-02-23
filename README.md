# SafePhishi

Simple web application built with Flask that lets users register, log in, and scan URLs and emails for potential phishing using a lightweight heuristic model (with room to plug in a real ML model later).

## Features

- User registration and login (`Flask-Login`)
- URL scanning dashboard with recent history
- Basic heuristic phishing detector (easily replaceable with a trained model)
- SQLite database by default (`SQLAlchemy`)
- Configurable via `.env` / `config.py`

## Project structure

```text
phishing-detector/
├── app.py            # Flask app factory and routes (index, dashboard, profile)
├── auth.py           # Authentication blueprint (login, register, logout)
├── models.py         # SQLAlchemy models (User, ScanResult)
├── config.py         # App configuration
├── requirements.txt  # Python dependencies
├── .env              # Local environment variables (not for production)
├── .env.example      # Example env file to copy from
├── .gitignore        # Git ignore configuration
├── README.md         # This file
├── LICENSE           # MIT License
├── templates/        # HTML templates
├── static/           # CSS / JS
├── model/            # ML / heuristic model code
├── uploads/          # User uploads (currently unused)
└── logs/             # Application logs
```

## Setup

1. **Create and activate a virtualenv** (recommended):

```bash
python -m venv .venv
.venv\Scripts\activate  # on Windows
```

2. **Install dependencies**:

```bash
pip install -r requirements.txt
```

3. **Configure environment variables**:

Copy the example file and edit as needed:

```bash
copy .env.example .env
```

At minimum, set a secure `SECRET_KEY` in `.env` for production use.

4. **Run the app**:

```bash
python app.py
```

Then open `http://127.0.0.1:5000/` in your browser.

## Replacing the heuristic model with a real ML model

The `model/ml_model.py` file exposes a `PhishingModel` class with a single method:

```python
is_phishing, score = model.predict(url)
```

- `is_phishing`: `True` if the URL is considered phishing, `False` otherwise
- `score`: confidence between 0 and 1 (or `None` if not available)

To plug in a real model:

1. Load your trained model in `PhishingModel.__post_init__`.
2. Implement richer feature extraction and scoring inside `predict`.
3. Keep the method signature the same so the rest of the app keeps working.

## License

This project is licensed under the MIT License. See `LICENSE` for details.

