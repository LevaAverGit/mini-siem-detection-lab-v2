from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    db_path: str = "siem.db"
    rules_path: str = "app/rules/default_rules.yml"
    log_level: str = "INFO"
    api_host: str = "127.0.0.1"
    api_port: int = 8000

    model_config = {"env_prefix": "SIEM_"}


settings = Settings()
