FROM python:3.7-slim

ADD . /app
RUN pip install -r /app/requirements.txt &&\
    pip install -e /app

CMD ["crypt4gh"]