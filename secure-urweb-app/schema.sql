PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;

CREATE TABLE uw_Healthtracker_users(
    uw_id integer NOT NULL,
    uw_username text NOT NULL,
    uw_passhash text NOT NULL,
    uw_email text NOT NULL,
    uw_fullname text NOT NULL,
    CONSTRAINT uw_Healthtracker_users_pkey PRIMARY KEY (uw_id));

CREATE TABLE uw_Healthtracker_healthRecords(
    uw_id integer NOT NULL,
    uw_userid integer NOT NULL,
    uw_recorddate text NOT NULL,
    uw_weightkg real NOT NULL,
    uw_bloodpressure text NOT NULL,
    uw_heartrate integer NOT NULL,
    uw_notes text NOT NULL,
    CONSTRAINT uw_Healthtracker_healthRecords_pkey PRIMARY KEY (uw_id));
