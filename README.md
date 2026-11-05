# ClaimMesh

A minimal FastAPI project with health and info endpoints, test suite, and CI workflow.

## Setup

```bash
# create virtual environment (optional)
python -m venv venv
source venv/bin/activate   # on Windows: venv\Scripts\activate

# install dependencies
pip install -r requirements.txt

# run the app
uvicorn app.main:app --reload
```

## Tests

```bash
pytest
```

## CI

GitHub Actions will run on each push.

## License

MIT