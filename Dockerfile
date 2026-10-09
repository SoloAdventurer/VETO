# --- build the dashboard ---
FROM node:22-alpine AS ui
WORKDIR /ui
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

# --- gateway + dashboard ---
FROM python:3.12-slim
WORKDIR /app
RUN pip install --no-cache-dir fastapi "uvicorn[standard]" jsonschema pyyaml
COPY backend/ ./backend/
COPY schemas/ ./schemas/
COPY policies/ ./policies/
COPY --from=ui /ui/dist ./frontend/dist
ENV PYTHONPATH=/app/backend VETO_ROOT=/app VETO_DEMO=1
EXPOSE 8000
CMD ["uvicorn", "veto.gateway.app:app", "--host", "0.0.0.0", "--port", "8000"]
