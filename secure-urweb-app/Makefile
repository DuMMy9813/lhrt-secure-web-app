# Makefile for Ur/Web Health Tracker
#
# Prerequisites:
#   - Ur/Web installed (http://www.impredicative.com/ur/)
#   - PostgreSQL running with database 'health_tracker_urweb'
#
# Usage:
#   make          – compile the application
#   make run      – compile and start the HTTP server on port 8080
#   make db       – create/reset the PostgreSQL schema
#   make clean    – remove compiled artefacts

URWEB   = urweb
APP     = app
PORT    = 8080
PSQL    = psql
DB_NAME = health_tracker_urweb
DB_USER = postgres

.PHONY: all run db clean

all: $(APP).exe

$(APP).exe: $(APP).ur $(APP).urp
	$(URWEB) $(APP)

run: $(APP).exe
	./$(APP).exe -p $(PORT)

db:
	$(PSQL) -U $(DB_USER) -c "DROP DATABASE IF EXISTS $(DB_NAME);"
	$(PSQL) -U $(DB_USER) -c "CREATE DATABASE $(DB_NAME);"
	$(PSQL) -U $(DB_USER) -d $(DB_NAME) -f schema.sql

clean:
	rm -f $(APP).exe $(APP).c $(APP).h
