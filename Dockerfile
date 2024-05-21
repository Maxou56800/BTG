FROM python:3.12.3

LABEL MAINTAINER="Maxou56800"

WORKDIR /app

RUN pip install poetry

COPY . /app/

RUN poetry lock --no-update

RUN poetry install

RUN poetry run python setup.py install

ENTRYPOINT ["poetry", "run", "btg"]