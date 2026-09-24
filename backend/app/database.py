import os
from sqlmodel import create_engine, Session, SQLModel

database_url = os.getenv("DATABASE_URL")

if database_url:
    # Railway and cloud providers give 'postgres://', but SQLAlchemy 2.0 requires 'postgresql://'
    if database_url.startswith("postgres://"):
        database_url = database_url.replace("postgres://", "postgresql://", 1)
    engine = create_engine(database_url, echo=False, pool_pre_ping=True)
else:
    # Local fallback to SQLite
    sqlite_file_name = "sentinelx.db"
    sqlite_url = f"sqlite:///{sqlite_file_name}"
    connect_args = {"check_same_thread": False}
    engine = create_engine(sqlite_url, echo=False, connect_args=connect_args)

def init_db():
    SQLModel.metadata.create_all(engine)

def get_session():
    with Session(engine) as session:
        yield session
