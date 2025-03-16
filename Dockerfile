FROM python:3.11-slim-bookworm AS builder

# Install uv by copying from the official distroless image
COPY --from=ghcr.io/astral-sh/uv:0.6.6 /uv /usr/local/bin/
COPY --from=ghcr.io/astral-sh/uv:0.6.6 /uvx /usr/local/bin/

# Set working directory
WORKDIR /app

# Set UV cache directory to a constant location
ENV UV_CACHE_DIR=/opt/uv-cache/
ENV PYTHONPATH=/app

# Copy dependency files first (for better layer caching)
COPY pyproject.toml ./

# Create requirements file from dependencies (optional lock file)
RUN --mount=type=cache,target=${UV_CACHE_DIR} \
    uv pip export --all-extras > requirements.txt

# Install dependencies using uv sync
RUN --mount=type=cache,target=${UV_CACHE_DIR} \
    uv pip install --system -r requirements.txt

# Now copy the rest of the application code
COPY README.md ./
COPY src ./src

# Install the project itself (non-editable mode)
RUN --mount=type=cache,target=${UV_CACHE_DIR} \
    uv pip install --system --no-editable .

# Compile Python bytecode for faster startup
RUN python -m compileall /app/src

# Runtime stage - minimal image
FROM python:3.11-slim-bookworm

WORKDIR /app

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app

# Copy Python site-packages from builder (use --link for more efficient copies)
COPY --from=builder --link /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages

# Copy the application with compiled bytecode
COPY --from=builder --link /app/src /app/src

# Expose the port the app runs on
EXPOSE 8000

# Command to run the application
CMD ["python", "-m", "gl_adguard_bridge"]
