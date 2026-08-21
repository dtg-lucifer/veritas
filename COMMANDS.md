### Run the backend

```bash
WINDOW_SECONDS=30 uv run uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

### Run the logger

```bash
sudo uv run python main.py sniff --interface any --user LOCAL-USER
```

### Run the simulator

```bash
uv run python simulate.py --mode normal
```

```bash
uv run python simulate.py --mode suspicious --multiplier 5 --attack-type wikileaks
```

```bash
uv run python app/test_multithreaded_pipeline.py
```