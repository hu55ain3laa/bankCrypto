# 🏦 BankCrypto - Secure Banking System

<div align="center">
  
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Streamlit](https://img.shields.io/badge/Streamlit-FF4B4B?logo=Streamlit&logoColor=white)](https://streamlit.io/)
[![Supabase](https://img.shields.io/badge/Supabase-3ECF8E?logo=supabase&logoColor=white)](https://supabase.io/)

</div>

## 🎓 Bachelor's Degree Graduation Project

A secure banking application that implements advanced cryptographic techniques for protecting sensitive financial data. The project demonstrates the practical application of modern security practices in financial technology.

### 🔐 Security Features

1. **Advanced Encryption**
   - AES (Advanced Encryption Standard) implementation
   - CBC (Cipher Block Chaining) mode for secure encryption
   - PKCS7 padding mechanism
   - Unique Initialization Vectors (IV) per user

2. **Authentication & Authorization**
   - Secure password hashing using bcrypt
   - JWT (JSON Web Token) based session management
   - Token expiration and validation
   - Salted password storage

3. **Secure Data Handling**
   - End-to-end encryption of transaction data
   - Encrypted balance storage
   - Secure transaction logging
   - Real-time balance updates

## 🛠️ Technology Stack

- **Frontend Framework**
  - Streamlit (Python-based web interface)
  - Interactive forms and secure input handling
  - Real-time state management
  - Responsive dashboard design

- **Backend & Database**
  - Supabase (PostgreSQL-based backend)
  - Secure API endpoints
  - Encrypted data storage
  - Real-time database updates

- **Security Libraries**
  - cryptography.hazmat (for AES encryption)
  - bcrypt (for password hashing)
  - PyJWT (for token management)
  - base64 (for encoding binary data)

## 📊 System Architecture

```
├── SecureBankApp.py        # Main application file
├── .streamlit/             # Streamlit configuration
└── Documentation/          # Project documentation
    ├── UMLSvg.svg         # UML diagrams
    ├── SvgDFD.svg         # Data Flow Diagrams
    └── DBdesign.png       # Database Schema
```

## 🔧 Core Functionality

1. **User Management**
   - Secure user registration
   - Encrypted user authentication
   - Session management with JWT
   - Password hashing and verification

2. **Transaction System**
   - Secure money transfers
   - Real-time balance updates
   - Transaction history logging
   - Input validation and security checks

3. **Data Security**
   - AES-256 encryption for sensitive data
   - Unique IV generation per user
   - Secure key management
   - Encrypted database storage

## 🚀 Getting Started

### Prerequisites
```bash
Python >= 3.8
pip >= 21.0
```

### Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/bankCrypto.git
cd bankCrypto
```

2. Create and activate virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Set up environment variables:
Create a `.streamlit/secrets.toml` file with:
```toml
[supabase]
url = "YOUR_SUPABASE_URL"
key = "YOUR_SUPABASE_KEY"

encryption_key = "YOUR_32_BYTE_KEY"
jwt_secret = "YOUR_JWT_SECRET"
```

5. Run the application:
```bash
streamlit run SecureBankApp.py
```

## 🔒 Security Implementation Details

### Encryption Process
```python
def encrypt_data(data: str, iv: bytes) -> str:
    cipher = Cipher(
        algorithms.AES(get_encryption_key()),
        modes.CBC(iv),
        backend=default_backend()
    )
    # ... encryption implementation
```

### Authentication Flow
1. User submits credentials
2. Password is verified against bcrypt hash
3. JWT token is generated with 1-hour expiration
4. Secure session is established

### Transaction Security
- All transaction data is encrypted before storage
- Sender and receiver information is encrypted
- Amount values are encrypted
- Timestamps are recorded for audit trails

## 📚 Documentation

Detailed documentation including:
- UML Diagrams (`UMLSvg.svg`)
- Data Flow Diagrams (`SvgDFD.svg`)
- Database Design (`DBdesign.png`)
- Full Documentation (`Documentation.pdf`)

## 👥 Team

- [Your Name] - Project Developer
- [Supervisor Name] - Academic Supervisor

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

<div align="center">
  Built with security and privacy in mind 🛡️
</div> 