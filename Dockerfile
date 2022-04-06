# Using Python image
FROM python:3.8

# Using Python image
FROM python:3.8

# Creating working directory for connector
WORKDIR /app

# Adding files in the app folder into working directory
ADD app/ .

# Installing Python requirements
RUN pip install -r requirements.txt

# Creating permanent volume for logs
VOLUME /app/log

# Creating permanent volume for db
VOLUME /app/db

# Starting script as an entrypoint
ENTRYPOINT ["python", "connector.py"]