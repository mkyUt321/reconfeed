from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    database_url: str
    session_secret: str

    nvd_api_key: str = ""
    github_token: str = ""

    resend_api_key: str = ""
    resend_from_email: str = "onboarding@resend.dev"

    app_base_url: str = "http://localhost:8000"


settings = Settings()
