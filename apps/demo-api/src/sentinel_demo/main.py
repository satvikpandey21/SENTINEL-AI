from sentinel_security.application import create_application


def create_app():
    app = create_application("sentinel-demo-api")

    @app.get("/api/demo/ping", tags=["demo"])
    async def ping():
        return {"message": "pong"}

    return app
