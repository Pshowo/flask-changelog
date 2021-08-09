FROM python:3.8

COPY . .
RUN pip install -r requirements.txt

CMD gunicorn -w 4 -b 0.0.0.0:5000 app:app
