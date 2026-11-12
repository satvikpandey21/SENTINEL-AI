from sentinel_demo.auth import DemoAuthSettings, install_login
from sentinel_security.application import create_application
from sentinel_security.config import Settings


def create_app(settings: Settings | None = None, auth_settings: DemoAuthSettings | None = None):
    settings = settings or Settings()
    auth_settings = auth_settings or DemoAuthSettings()
    if auth_settings.auth_enabled and settings.environment == "production":
        raise ValueError("demo login is restricted to development/test environments")
    app = create_application("sentinel-demo-api", settings)

    @app.get("/api/demo/ping", tags=["demo"])
    async def ping():
        return {"message": "pong"}

    @app.get("/api/demo/limited", tags=["demo"])
    async def limited():
        return {"message": "limited endpoint available"}

    if auth_settings.auth_enabled:
        install_login(app, auth_settings)
    return app
