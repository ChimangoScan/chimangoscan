FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir pymongo==4.10.1 neo4j==5.27.0

WORKDIR /app
COPY exposure_updater.py compute_exposure_ranking.py /app/

# defaults — override at runtime
ENV NEO4J_URI=bolt://127.0.0.1:7687 \
    MONGO_URI=mongodb://127.0.0.1:27017 \
    WORKDIR=/data/exposure_work \
    OUT_PATH=/data/ditector_exposure_ranked.jsonl \
    QUEUE_DB=/data/ditector.db

ENTRYPOINT ["python3", "/app/exposure_updater.py"]
CMD ["--queue-db", "/data/ditector.db", \
     "--ranker-script", "/app/compute_exposure_ranking.py", \
     "--work-dir", "/data/exposure_work", \
     "--ranked-jsonl", "/data/ditector_exposure_ranked.jsonl", \
     "--top-n", "500000", \
     "--loop", "21600"]
