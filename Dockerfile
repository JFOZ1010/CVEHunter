FROM python:3.12-alpine3.20

ENV PYTHONUNBUFFERED=1

# Establezco el directorio de trabajo en /app
WORKDIR /app

# Instalando las dependencias de la aplicación
RUN  apk update \
	&& apk add --no-cache gcc musl-dev postgresql-dev python3-dev libffi-dev \
	&& pip install --upgrade pip

# Copiando los archivos de la aplicación al contenedor
COPY ./requirements.txt ./ 

RUN pip install -r requirements.txt

COPY ./ ./ 

# Ejecuto el servidor de desarrollo de Django
CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]