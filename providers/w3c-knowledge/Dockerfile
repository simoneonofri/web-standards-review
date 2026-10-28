FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY pyproject.toml README.md ./
COPY w3c_knowledge ./w3c_knowledge
COPY config ./config
COPY migrations ./migrations
COPY alembic.ini ./
RUN pip install --no-cache-dir '.[vectors]'
ENTRYPOINT ["sh", "-c", "alembic upgrade head && exec \"$@\"", "--"]
CMD ["uvicorn", "w3c_knowledge.main:app", "--host", "0.0.0.0", "--port", "8000"]
