FROM python:3.12.3

LABEL MAINTAINER="Maxou56800"

WORKDIR /app

RUN pip install poetry

COPY . /app/

RUN poetry lock

RUN poetry install --no-root

RUN poetry run python setup.py install

ENTRYPOINT ["poetry", "run", "btg"]