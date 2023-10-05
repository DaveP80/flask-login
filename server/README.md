# flask-authentication-system

use render.com for postgres instance
get app password from google security settings (for smtp function)

```bash
python3 -m venv/venv
source venv/bin/activate
pip3 install -r requirements.txt
touch .env
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
