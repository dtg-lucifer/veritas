### Run the backend

```bash
WINDOW_SECONDS=30 uv run uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

### Run the logger

```bash
sudo uv run python main.py sniff --interface any --user LOCAL-USER

sudo uv run python main.py sniff --interface any --user PIUSH-THINKPAD --redis-url redis://default:2UXpJQ3Dqy5jUTtW4U9SDCxKq5wyPe79@redis-14713.crce283.ap-south-1-2.ec2.cloud.redislabs.com:14713/0
```

### Run the simulator

```bash
uv run python simulate.py --mode normal
```

```bash
uv run python simulate.py --mode mild
```

```bash
uv run python simulate.py --mode suspicious --multiplier 5 --attack-type wikileaks

sudo uv run python simulate.py --mode suspicious --multiplier 5 --attack-type wikileaks --redis-url redis://default:2UXpJQ3Dqy5jUTtW4U9SDCxKq5wyPe79@redis-14713.crce283.ap-south-1-2.ec2.cloud.redislabs.com:14713/0

sudo uv run python simulate.py --mode mild --multiplier 1 --attack-type wikileaks --redis-url redis://default:2UXpJQ3Dqy5jUTtW4U9SDCxKq5wyPe79@redis-14713.crce283.ap-south-1-2.ec2.cloud.redislabs.com:14713/0
```

```bash
uv run python app/test_multithreaded_pipeline.py
```
