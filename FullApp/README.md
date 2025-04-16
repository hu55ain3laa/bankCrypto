# Secure Bank App

A secure banking application built with Streamlit, featuring end-to-end encryption for sensitive data.

## Features

- Secure user authentication with JWT tokens
- End-to-end encryption for account balances and transactions
- Real-time balance updates
- Secure money transfers between users
- Session management with automatic expiration
- Automatic database initialization with seeded data

## Prerequisites

- Python 3.8+
- pip (Python package manager)

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd bankCrypto/FullApp
```

2. Create and activate a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requierments.txt
```

4. Create a `.streamlit/secrets.toml` file with the following content:
```toml
encryption_key = "your-32-byte-encryption-key"
jwt_secret = "your-jwt-secret-key"
```

## Running the Application

Start the Streamlit application:
```bash
streamlit run SecureBankApp.py
```

The application will automatically:
- Create the database tables
- Seed the initial data
- Start the web interface

The application will be available at `http://localhost:8501`

## Seeded Data

The application comes with the following pre-configured users:

- **User 1**
  - Username: `alice`
  - Password: `password123`
  - Initial Balance: $1000

- **User 2**
  - Username: `bob`
  - Password: `password123`
  - Initial Balance: $1000

## Security Features

- All sensitive data is encrypted using AES-256-CBC
- Passwords are hashed using bcrypt
- JWT tokens for session management
- Automatic session expiration
- Secure transaction processing

## Database Schema

The application uses SQLite with the following tables:

- **User**: Stores user information and encrypted balances
- **Transaction**: Records encrypted transaction details

## Contributing

Feel free to submit issues and enhancement requests.

## License

This project is licensed under the MIT License. 