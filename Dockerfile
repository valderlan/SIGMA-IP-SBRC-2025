FROM python:3.12-slim-bookworm

RUN apt-get update && \
    apt-get install -y curl vim

COPY --from=ghcr.io/astral-sh/uv:0.7.9 /uv /uvx /bin/

ENV PATH="/root/.local/bin:$PATH"

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /django-app/

COPY pyproject.toml uv.lock ./
COPY ./api ./src
# COPY run.py .

RUN uv sync --locked

# CMD ["uv", "run", "run.py"]