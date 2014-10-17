--[[

Parses and transforms the Percona Server slow query logs.
Tested on version 5.5 only!

Config:

- type (string, optional, default nil):
    Sets the message 'Type' header to the specified value.

- truncate_sql (int, optional, default nil)
    Truncates the SQL payload to the specified number of bytes (not UTF-8 aware)
    and appends "...". If the value is nil no truncation is performed. A
    negative value will truncate the specified number of bytes from the end.

- tz (string, optional, defaults to UTC):
    Timezone.

- log_query_start (boolean, optional, default true)
    Substract query_time from logged timestamp to log when query was started (instead of logging when the query was finished).

*Example Heka Configuration*

.. code-block:: ini

    [Sync-1_5-SlowQuery]
    type = "LogstreamerInput"
    log_directory = "/var/log/mysql"
    file_match = 'mysql-slow\.log'
    parser_type = "regexp"
    delimiter = "\n(# Time: )"
    delimiter_location = "start"
    decoder = "PerconaSlowQueryDecoder"

    [PerconaSlowQueryDecoder]
    type = "SandboxDecoder"
    filename = "lua_decoders/ngs.percona_server_slow_query_log.lua"

    [PerconaSlowQueryDecoder.config]
    truncate_sql = 64
    type = "log_mysql_slow"

*Example Heka Message*

:Timestamp: 2014-05-07 15:51:28 -0700 PDT
:Type: log_mysql_slow
:Hostname: 127.0.0.1
:Pid: 0
:UUID: 5324dd93-47df-485b-a88e-429f0fcd57d6
:Logger: Sync-1_5-SlowQuery
:Payload: /* [queryName=FIND_ITEMS] */ SELECT bso.userid, bso.collection, ...
:EnvVersion:
:Severity: 7
:Fields:
    | name:"Rows_examined" value_type:DOUBLE value_double:16458
    | name:"Query_time" value_type:DOUBLE representation:"s" value_double:7.24966
    | name:"Rows_sent" value_type:DOUBLE value_double:5001
    | name:"Lock_time" value_type:DOUBLE representation:"s" value_double:0.047038
--]]

local dt = require "date_time"
local l = require "lpeg"
local s = require "string"
l.locale(l)

local msg_type		= read_config("type")
local truncate_sql	= read_config("truncate_sql")
local log_query_start	= read_config("log_query_start")
if not log_query_start then
	log_query_start = true
end

local msg = {
	Timestamp	= nil,
	Type		= msg_type,
	Payload		= nil,
	Fields		= {}
}

local blank		= l.space^1
local sep		= l.P("\n")
local sql_end		= l.P(";") * sep^-1
local rest_line		= (l.P(1) - sep)^0 * sep
local float		= l.digit^1 * "." * l.digit^1
local int		= l.digit^1
local yes_no		= l.C(l.P("Yes") + l.P("No"))
local hex		= (l.R("AF") + l.digit)^1

local time		= l.P("# Time: ") * l.Cg( l.Ct( l.Cg((l.digit*l.digit)/function (yy) return os.date("%Y"):sub(1,2)..yy end, "year") * dt.date_month * dt.date_mday * l.P(" ")^1 * l.Cg(int, "hour") * ":" * dt.time_minute * ":" * dt.time_second * dt.time_secfrac^-1 ) / dt.time_to_ns, "ts_log" ) * sep

local user_name		= (l.P(1)-"[")^0 * "[" * l.Cg((l.P(1)-"]")^1, "username") * "]"
local host_name		= l.alpha^0 * l.space^0 * "[" * l.Cg((l.P(1)-"]")^0, "hostname") * "]"
local user_line		= l.P("# User@Host: ") * user_name * blank * "@" * blank * host_name * sep

local thread_line	= l.P("# Thread_id: ") * l.Cg(int/tonumber, "thread_id") * blank
			* l.P("Schema: ") * l.Cg((l.P(1)-" ")^1, "db") * blank
			* l.P("Last_errno:") * blank * l.Cg(int/tonumber, "last_errno") * blank
			* l.P("Killed:") * blank * l.Cg(int/tonumber, "killed") * sep

local querystat_line	= l.P("# Query_time: ") * l.Cg(float/tonumber, "query_time") * blank
			* l.P("Lock_time: ") * l.Cg(float/tonumber, "lock_time") * blank
			* l.P("Rows_sent: ") * l.Cg(int/tonumber, "rows_sent") * blank
			* l.P("Rows_examined: ") * l.Cg(int/tonumber, "rows_examined") * blank
			* l.P("Rows_affected: ") * l.Cg(int/tonumber, "rows_affected") * blank
			* l.P("Rows_read: ") * l.Cg(int/tonumber, "rows_read") * sep

local bytes_line	= l.P("# Bytes_sent: ") * l.Cg(int/tonumber, "bytes_sent") * blank
			* l.P("Tmp_tables: ") * l.Cg(int/tonumber, "tmp_tables") * blank
			* l.P("Tmp_disk_tables: ") * l.Cg(int/tonumber, "tmp_disk_tables") * blank
			* l.P("Tmp_table_sizes: ") * l.Cg(int/tonumber, "tmp_table_sizes") * sep

local innodb_trx_id	= l.P("# InnoDB_trx_id: ") * l.Cg(hex, "innodb_trx_id") * sep

local qc_line		= l.P("# QC_Hit: ") * l.Cg(yes_no, "qc_hit") * blank
			* l.P("Full_scan: ") * l.Cg(yes_no, "full_scan") * blank
			* l.P("Full_join: ") * l.Cg(yes_no, "full_join") * blank
			* l.P("Tmp_table: ") * l.Cg(yes_no, "tmp_table") * blank
			* l.P("Tmp_table_on_disk: ") * l.Cg(yes_no, "tmp_table_on_disk") * sep

local filesort_line	= l.P("# Filesort: ") * l.Cg(yes_no, "filesort") * blank
			* l.P("Filesort_on_disk: ") * l.Cg(yes_no, "filesort_on_disk") * blank
			* l.P("Merge_passes: ") * l.Cg(int/tonumber, "merge_passes") * sep

local innodb_stats	= l.P("#   InnoDB_IO_r_ops: ") * l.Cg(int/tonumber, "innodb_io_r_ops") * blank
			* l.P("InnoDB_IO_r_bytes: ") * l.Cg(int/tonumber, "innodb_io_r_bytes") * blank
			* l.P("InnoDB_IO_r_wait: ") * l.Cg(float/tonumber, "innodb_io_r_wait") * sep
			* l.P("#   InnoDB_rec_lock_wait: ") * l.Cg(float/tonumber, "innodb_rec_lock_wait") * blank
			* l.P("InnoDB_queue_wait: ") * l.Cg(float/tonumber, "innodb_queue_wait") * sep
			* l.P("#   InnoDB_pages_distinct: ") * l.Cg(int/tonumber, "innodb_pages_distinct") * sep

local use_db		= l.P("use ") * rest_line

local set_line		= l.P("SET ") * (l.P("last_insert_id=") * int * ",")^-1 * (l.P("insert_id=") * int * ",")^-1 * l.P("timestamp=") * l.Cg(int/tonumber, "ts_master") * ";" * sep

local admin_line	= l.P("# administrator command: ") * rest_line

local sql_query		= l.Cg((l.P(1) - sql_end)^0 * sql_end, "sql_query")

local slow_query_grammar = l.Ct( l.Cg (l.Ct( time * user_line * thread_line * querystat_line * bytes_line * innodb_trx_id * qc_line * filesort_line * innodb_stats * use_db * set_line * admin_line^-1 * sql_query ), "Fields") )

function process_message ()
	local log = read_message("Payload")
	local tmp = slow_query_grammar:match(log)
	if not tmp then return -1 end

	msg.Fields = tmp.Fields

	-- playing with time
	msg.Timestamp = msg.Fields.ts_log
	if log_query_start == true  then
		msg.Timestamp = msg.Timestamp - msg.Fields.query_time
	end
	msg.Fields.slave_lag = msg.Fields.ts_log - msg.Fields.ts_master
	msg.Fields.ts_log = nil
	msg.Fields.ts_master = nil

	-- sql query
	if truncate_sql and #msg.Fields.sql_query > truncate_sql then
		msg.Payload = s.format("%s...", msg.Fields.sql_query:sub(1, truncate_sql))
	else
		msg.Payload = msg.Fields.sql_query
	end
	msg.Fields.sql_query = nil

	inject_message(msg)
	return 0
end
