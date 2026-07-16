from flask import current_app
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer


def issue_token(purpose, user_id, value=""):
    serializer = URLSafeTimedSerializer(current_app.config["SECRET_KEY"], salt=f"domain-oss:{purpose}")
    return serializer.dumps({"user_id": user_id, "value": value})


def read_token(purpose, token, max_age=3600):
    serializer = URLSafeTimedSerializer(current_app.config["SECRET_KEY"], salt=f"domain-oss:{purpose}")
    try:
        return serializer.loads(token, max_age=max_age)
    except (BadSignature, SignatureExpired):
        return None
