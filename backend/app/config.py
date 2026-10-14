from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    database_url: str = "sqlite:///./cybersentinel.db"
    cors_origins: str = "http://localhost:8080,http://127.0.0.1:8080"
    failed_login_threshold: int = 5
    burst_threshold: int = 10
    burst_window_seconds: int = 90
    deduplication_window_minutes: int = 15

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    @property
    def origins(self) -> list[str]:
        return [x.strip() for x in self.cors_origins.split(",") if x.strip()]


settings = Settings()
