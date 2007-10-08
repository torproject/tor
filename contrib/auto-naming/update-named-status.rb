#!/usr/bin/ruby

require "yaml"

require 'db'
require 'db-config'

def do_update verbose
	now = "TIMESTAMP '" + $db.query_row("SELECT max(last_seen) AS max FROM router_claims_nickname")['max'].to_s + "'"

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
	$db = Db.new($CONFIG['database']['dbname'], $CONFIG['database']['user'], $CONFIG['database']['password'])
	verbose = ARGV.first == "-v"

	$db.transaction_begin
	do_update verbose
	$db.transaction_commit
end
