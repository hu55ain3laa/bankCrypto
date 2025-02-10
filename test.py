import diagrams
from diagrams import Diagram, Cluster, Edge
from diagrams.aws.database import RDS
from diagrams.onprem.client import User
from diagrams.programming.language import Python
from diagrams.generic.database import _Database as Database
from diagrams.gcp.security import KeyManagementService as CloudKeyManagementService

def create_dfd():
    with Diagram("Secure Bank App Data Flow", show=False, direction="LR") as diag:
        user = User("User")

        with Cluster("Application"):
            ui = Python("User Interface\n(Streamlit)")
            auth = Python("Authentication\nModule (JWT)")
            enc = Python("Encryption/Decryption\nModule")
            rate_limiter = Python("Rate Limiter")  # Added Rate Limiter
            audit_log = Python("Audit Logging") # Added Audit Logging

        db = RDS("Supabase Database")

        with Cluster("Data Storage"):
            transactions = Database("Transactions Table")
            user_data = Database("User Data Table") # Separate User Data Table

        kms = CloudKeyManagementService("KMS\n(Key Management)") # Added KMS

        # Authentication Flow
        user >> ui >> Edge(label="Login/Signup\n(Username, Password)") >> auth
        auth >> ui >> Edge(label="JWT Token") >> user
        ui >> rate_limiter >> auth # Rate Limiting

        # User Data
        ui >> Edge(label="User Data\n(Insert/Get)") >> user_data
        user_data >> Edge(label="User Data") >> ui

        # Balance Encryption/Decryption
        ui >> Edge(label="Balance\n(Encrypt)") >> enc
        enc >> Edge(label="Encrypted Balance") >> kms # KMS for key management
        kms >> Edge(label="Encryption Key") >> enc
        enc >> Edge(label="Encrypted Balance\n(Store)") >> db
        db >> Edge(label="Encrypted Balance\n(Retrieve)") >> enc
        enc >> Edge(label="Balance\n(Decrypt)") >> ui

        # Transactions
        ui >> Edge(label="Transaction Data\n(Create)") >> transactions
        transactions >> Edge(label="Transaction Data\n(Store)") >> db
        db >> Edge(label="Transaction History\n(Retrieve)") >> ui

        # Balance Update
        ui >> Edge(label="Balance Update") >> db
        db >> Edge(label="Updated Balance") >> ui

        # Security and Logging
        ui >> Edge(label="Request") >> audit_log
        audit_log >> Edge(label="Audit Logs") >> db # Store logs in DB

        # Detailed annotations (can be more descriptive)
        # ui >> Edge(label="Login Request", color="blue", style="dashed") >> auth

    diag.render()

create_dfd()