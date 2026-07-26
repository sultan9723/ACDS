FROM python:3.10-slim

# Avoids Python writing .pyc files
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

WORKDIR /app

# requirements.txt is at project root (build context .)
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# copy backend source from context's backend folder
COPY ./backend /app

# Use uvicorn to run the 'app' instance from the 'main' module
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
