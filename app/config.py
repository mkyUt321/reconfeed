from pydantic_settings import BaseSettings, SettingsConfigDict

# Resend's shared sandbox sender. It needs no domain verification, but Resend only delivers
# mail sent from it to the API key owner's own address — every other recipient is rejected.
# Moving to a verified custom domain is what lifts that restriction (see README).
RESEND_SANDBOX_FROM = "onboarding@resend.dev"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    database_url: str
    session_secret: str

    nvd_api_key: str = ""
    github_token: str = ""

    resend_api_key: str = ""
    resend_from_email: str = RESEND_SANDBOX_FROM

    app_base_url: str = "http://localhost:8000"

    # Shows the "this is a demo" notice on signup/dashboard. Purely cosmetic — it does not gate
    # sending, so flipping it does not change who receives mail; see using_sandbox_sender for
    # the setting that actually determines that.
    demo_mode: bool = True

    @property
    def using_sandbox_sender(self) -> bool:
        """True while mail is still sent from Resend's shared sandbox address, i.e. while it can
        only reach the Resend account owner. Substring match so the "Name <addr>" form counts."""
        return RESEND_SANDBOX_FROM in self.resend_from_email.lower()


settings = Settings()
