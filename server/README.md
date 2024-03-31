# flask-authentication-system

use render.com for postgres instance\
another good postgres FREE provider is [aiven](https://aiven.io/)\
get app password from google security settings (for smtp function)

```bash
python3 -m venv/venv
source venv/bin/activate
pip3 install -r requirements.txt
touch .env
```

Get your SECRET_KEY with

```
import secrets
secrets.token_urlsafe(16)
secrets
```

Production run

```py
app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
```

Deploy

```bash
gcloud builds submit --tag gcr.io/<PROJECTID>/login
gcloud run deploy --image gcr.io/<PROJECTID>/login:latest
```

In production include /img directories.
