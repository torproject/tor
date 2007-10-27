
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


-- Copyright (c) 2007 Peter Palfrader
--
-- Permission is hereby granted, free of charge, to any person obtaining a copy
-- of this software and associated documentation files (the "Software"), to deal
-- in the Software without restriction, including without limitation the rights
-- to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
-- copies of the Software, and to permit persons to whom the Software is
-- furnished to do so, subject to the following conditions:
--
-- The above copyright notice and this permission notice shall be included in
-- all copies or substantial portions of the Software.
--
-- THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
-- IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
-- FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
-- AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
-- LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
-- OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
-- SOFTWARE.
