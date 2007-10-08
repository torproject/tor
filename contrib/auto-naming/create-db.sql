
CREATE TABLE router (
	router_id	SERIAL PRIMARY KEY,
	fingerprint	CHAR(40)		NOT NULL,
	UNIQUE(fingerprint)
);
-- already created implicitly due to unique contraint
-- CREATE INDEX router_fingerprint ON router(fingerprint);

CREATE TABLE nickname (
	nickname_id	SERIAL PRIMARY KEY,
	nick		VARCHAR(30)		NOT NULL,
	UNIQUE(nick)
);
-- already created implicitly due to unique contraint
-- CREATE INDEX nickname_nick ON nickname(nick);

CREATE TABLE router_claims_nickname (
	router_id	INTEGER		NOT NULL	REFERENCES router(router_id) ON DELETE CASCADE,
	nickname_id	INTEGER		NOT NULL	REFERENCES nickname(nickname_id) ON DELETE CASCADE,
	first_seen	TIMESTAMP WITH TIME ZONE	NOT NULL	DEFAULT CURRENT_TIMESTAMP,
	last_seen	TIMESTAMP WITH TIME ZONE	NOT NULL	DEFAULT CURRENT_TIMESTAMP,
	named		BOOLEAN				NOT NULL	DEFAULT 'false',
	UNIQUE(router_id, nickname_id)
);
CREATE INDEX router_claims_nickname_router_id ON router_claims_nickname(router_id);
CREATE INDEX router_claims_nickname_nickname_id ON router_claims_nickname(nickname_id);
CREATE INDEX router_claims_nickname_first_seen ON router_claims_nickname(first_seen);
CREATE INDEX router_claims_nickname_last_seen ON router_claims_nickname(last_seen);
