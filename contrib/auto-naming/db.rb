#!/usr/bin/ruby

# Copyright (c) 2006, 2007 Peter Palfrader
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

require "dbi"

class WeaselDbQueryHandle
	def initialize(sth)
		@sth = sth
	end

	def next()
		row = @sth.fetch_hash
		if row
			return row
		else
			@sth.finish
			return nil
		end
	end
end

class Db
	def initialize(host, database, user, password)
		@dbh = DBI.connect("dbi:Pg:#{database}:#{host}", user, password);
		@dbh['AutoCommit'] = false
		@transaction = false
		@pre_initial_transaction=true
	end

	def do(query,*args)
		@dbh.do(query,*args)
	end
	def transaction_begin()
		@dbh.do("BEGIN") unless @pre_initial_transaction
		@transaction = true
		@pre_initial_transaction=false
	end
	def transaction_commit()
		@dbh.do("COMMIT")
		@transaction = false
	end
	def transaction_rollback()
		@dbh.do("ROLLBACK")
	end
	def get_primarykey_name(table);
		#return 'ref';
		return table+'_id';
	end

	def update(table, values, keys)
		cols = []
		vals = []
		values.each_pair{ |k,v|
			cols << "#{k}=?"
			vals << v
		}

		wheres = []
		keys.each_pair{ |k,v|
			wheres << "#{k}=?"
			vals << v
		}

		throw "update value set empty" unless cols.size > 0
		throw "where clause empty" unless wheres.size > 0

		query = "UPDATE #{table} SET #{cols.join(',')} WHERE #{wheres.join(' AND ')}"
		transaction_begin unless transaction_before=@transaction
		r = @dbh.do(query, *vals)
		transaction_commit unless transaction_before
		return r
	end

	def update_row(table, values)
		pk_name = get_primarykey_name(table);
		throw "Ref not defined" unless values[pk_name]
		return update(table, values.clone.delete_if{|k,v| k == pk_name}, { pk_name => values[pk_name] });
	end
	def insert(table, values)
		cols = values.keys
		vals = values.values
		qmarks = values.values.collect{ '?' }

		query = "INSERT INTO #{table} (#{cols.join(',')}) VALUES (#{qmarks.join(',')})"
		transaction_begin unless transaction_before=@transaction
		@dbh.do(query, *vals)
		transaction_commit unless transaction_before
	end

	def insert_row(table, values)
		pk_name = get_primarykey_name(table);
		if values[pk_name]
			insert(table, values)
		else
			transaction_begin unless transaction_before=@transaction
			row = query_row("SELECT nextval(pg_get_serial_sequence('#{table}', '#{pk_name}')) AS newref");
			throw "No newref?" unless row['newref']
			values[pk_name] = row['newref']
			insert(table, values);
			transaction_commit unless transaction_before
		end
	end
	def delete_row(table, ref)
		pk_name = get_primarykey_name(table);
		query = "DELETE FROM #{table} WHERE #{pk_name}=?"
		transaction_begin unless transaction_before=@transaction
		@dbh.do(query, ref)
		transaction_commit unless transaction_before
	end
	def query(query, *params)
		sth = @dbh.execute(query, *params)
		while row = sth.fetch_hash
			yield row
		end
		sth.finish
	end
	# nil if no results
	# hash if one match
	# throw otherwise
	def query_row(query, *params)
		sth = @dbh.execute(query, *params)

		row = sth.fetch_hash
		if row == nil
			sth.finish
			return nil
		elsif sth.fetch_hash != nil
			sth.finish
			throw "More than one result when querying for #{query}"
		else
			sth.finish
			return row
		end
	end
	def query_all(query, *params)
		sth = @dbh.execute(query, *params)

		rows = sth.fetch_all
		return nil if rows.size == 0
		return rows
	end
	def query2(query, *params)
		sth = @dbh.execute(query, *params)
		return WeaselDbQueryHandle.new(sth)
	end
end
