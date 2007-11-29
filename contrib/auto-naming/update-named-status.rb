#!/usr/bin/ruby

# update-named-status.rb - update the named status of routers in our database
#
# Copyright (c) 2007 Peter Palfrader
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

require "yaml"

require 'db'
require 'db-config'

def do_update(verbose)
	now = $db.query_row("SELECT max(last_seen) AS max FROM router_claims_nickname")['max']
	unless now
		STDERR.puts "Could not find the latest last_seen timestamp.  Is the database empty still?"
		return
	end
	now = "TIMESTAMP '" + now.to_s + "'"

	denamed = $db.do("
			UPDATE router_claims_nickname
			SET named=false
			WHERE named
			  AND last_seen < #{now} - INTERVAL '6 months'")
	puts "de-named: #{denamed}" if verbose

	named = $db.do("
			UPDATE router_claims_nickname
			SET named=true
			WHERE NOT named
			  AND first_seen < #{now} - INTERVAL '2 weeks'
			  AND last_seen  > #{now} - INTERVAL '2 days'
			  AND NOT EXISTS (SELECT *
			       FROM router_claims_nickname AS innertable
			       WHERE named
			         AND router_claims_nickname.nickname_id=innertable.nickname_id) "+ # if that nickname is already named, we lose.
			" AND NOT EXISTS (SELECT *
			       FROM router_claims_nickname AS innertable
			       WHERE router_claims_nickname.nickname_id=innertable.nickname_id
			         AND router_claims_nickname.router_id <> innertable.router_id
			         AND last_seen > #{now} - INTERVAL '1 month') ") # if nobody else wanted that nickname in the last month we are set
	puts "named: #{named}" if verbose
end

if __FILE__ == $0
	$db = Db.new($CONFIG['database']['dbhost'], $CONFIG['database']['dbname'], $CONFIG['database']['user'], $CONFIG['database']['password'])
	verbose = ARGV.first == "-v"

	$db.transaction_begin
	do_update verbose
	$db.transaction_commit
end
