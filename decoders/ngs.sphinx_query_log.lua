--[[
Parses Sphinx search query log (up to version 2.25).

Config:

- type (string, optional, default nil):
    Sets the message 'Type' header to the specified value.

- tz (string, optional, defaults to UTC):
    Timezone.

*Example Heka Configuration*

.. code-block:: ini

    [SphinxQuery]
    type = "LogstreamerInput"
    log_directory = "/var/log/sphinx"
    file_match = 'query\.log'
    decoder = "SphinxQueryDecoder"

    [SphinxQueryDecoder]
    type = "SandboxDecoder"
    filename = "lua_decoders/ngs.sphinx_query_log.lua"

    [SphinxQueryDecoder.config]
    type = "sphinx_query_logs"
    tz = "Asia/Novosibirsk"

*Example Heka Message 1*

:Timestamp: 2014-09-24 17:19:56 +0700 NOVT
:Type: sphinx_query_logs
:Hostname: search1
:Pid: 23678
:UUID: a1ee8eb0-e60b-4b81-a143-5dfe9a64b75b
:Logger: SphinxQuery
:Payload: 
:EnvVersion:
:Severity: 7
:Fields:
    | name:"total-matches" value_type:DOUBLE value_double:10
    | name:"query_type" value_string:"SphinxQL"
    | name:"wall-time" value_type:DOUBLE value_double:0.006
    | name:"real-time" value_type:DOUBLE value_double:0.006
    | name:"query_sql" value_string:"SELECT  FROM market_city68_goods GROUP BY cat_id WITHIN GROUP ORDER BY mode-0 LIMIT 0, 5000 OPTION max_matches=5000, ranker=proximity"
    | name:"query_error" value_string:"unknown local index 'market_city68_goods' in search request"
    | name:"io_stats" value_string:"ios=20 kb=24.0 ioms=0.200 cpums=10.2 agents=(0.003, 1.123)"
    | name:"connection_id" value_type:DOUBLE value_double:1176853648

*Example Heka Message 2*

:Timestamp: 2014-09-24 17:19:56 +0700 NOVT
:Type: sphinx_query_logs
:Hostname: search1
:Pid: 23678
:UUID: a1ee8eb0-e60b-4b81-a143-5dfe9a64b75b
:Logger: SphinxQuery
:Payload: 
:EnvVersion:
:Severity: 7
:Fields:
    | name:"total-matches" value_type:DOUBLE value_double:7352
    | name:"query_type" value_string:"plain"
    | name:"wall-time" value_type:DOUBLE value_double:0.011
    | name:"real-time" value_type:DOUBLE value_double:0.011
    | name:"offset" value_type:DOUBLE value_double:0
    | name:"limit" value_type:DOUBLE value_double:100
    | name:"match-mode" value_string:"ext"
    | name:"sort-mode" value_string:"ext"
    | name:"filters-count" value_type:DOUBLE value_double:9
    | name:"index-names" value_string:"realty_arenda realty_arenda_delta"
    | name:"query_plain" value_string:"query text"
    | name:"groupby-attr" value_string:"_id_city_district"
    | name:"io_stats" value_string:"ios=20 kb=24.0 ioms=0.200 cpums=10.2 agents=(0.003, 1.123)"
--]]

local dt	= require "date_time"
local l		= require 'lpeg'
l.locale(l)

local msg_type	= read_config("type")

local msg = {
	Timestamp	= nil,
	Type		= msg_type,
	Pid		= nil,
	Payload		= nil,
	Fields		= {}
}

local number = l.digit^1
local float = number * l.P(".") * number

local ts_weekday = l.P"Mon" + "Tue" + "Wed" + "Thu" + "Fri" + "Sat" + "Sun"
local timestamp = l.Cg( l.Ct( ts_weekday * l.P(" ") * dt.date_mabbr * l.P(" ") * dt.date_mday_sp * l.P(" ") * dt.rfc3339_partial_time * l.P(" ") * dt.date_fullyear ) / dt.time_to_ns, "timestamp" )

local plain_match_mode = l.P("all") + l.P("any") + l.P("phr") + l.P("bool") + l.P("ext")*l.P("2")^-1 + l.P("scan")
local plain_sort_mode = l.P("rel") + l.P("attr-") + l.P("attr+") + l.P("tsegs") + l.P("ext")
local plain_query_header_times = l.Cg(float/tonumber, "real-time" ) * l.P(" sec ") * ( l.Cg(float/tonumber, "wall-time" ) * l.P(" sec ") )^-1 * ( l.P("x") * l.Cg(number/tonumber, "query_multiplier") * l.P(" ") )^-1 
local plain_query_header_stats = l.P("[") * l.Cg(plain_match_mode, "match-mode") * l.P("/") * l.Cg(number/tonumber, "filters-count") * l.P("/") * l.Cg(plain_sort_mode, "sort-mode") * l.P(" ") * l.Cg(number/tonumber, "total-matches") * l.P(" (") * l.Cg(number/tonumber, "offset") * l.P(",") * l.Cg(number/tonumber, "limit") * l.P(")") * ( l.P(" @") * l.Cg((l.alpha+l.space+l.digit+l.S("-_,"))^1, "groupby-attr") )^-1 * l.P("]")
local plain_query_header_indexes =  l.P(" [") * l.Cg((l.alpha+l.space+l.digit+l.S("-_,"))^1, "index-names") * l.P("]")
local plain_query_header_io = ( l.P(" [") * l.Cg( (l.P(1)-(l.P("]")))^0 , "io_stats") * l.P("]") )^-1
local plain_query_grammar = l.Ct( l.P("[") * timestamp * l.P("] ") * plain_query_header_times * plain_query_header_stats * plain_query_header_indexes * plain_query_header_io * l.P(" ")^-1 * l.Cg( (l.P(1)-l.P("\n"))^0, "query_plain" ) )

local sql_query_header = l.P(" conn ") * l.Cg( number/tonumber, "connection_id") * (l.P(" real ") * l.Cg( float/tonumber, "real-time"))^-1 * l.P(" wall ") * l.Cg( float/tonumber, "wall-time") * l.P(" found ") * l.Cg( number/tonumber, "total-matches") * l.P(" ")
local sql_query_footer_error = (l.P(" ") * (l.P("/*")+l.P("#")) * l.P(" error=") * l.Cg((l.P(1)-(l.P("\n")+l.P(" #")+l.P(" */")))^0, "query_error") * l.P(" */")^-1 )^-1
local sql_query_footer_io = ( l.P(" ") * (l.P("/* ")+l.P("# ")) * l.Cg((l.P(1)-(l.P("\n")+l.P(" */")))^0, "io_stats") * l.P(" */")^-1 )^-1 * l.Cg( (l.P(1)-l.P("\n"))^0, "rest" )
local sql_query_grammar = l.Ct( l.P("/* ") * timestamp * sql_query_header * l.P("*/ ") * l.Cg( (l.P(1)-l.P(";"))^0, "query_sql" ) * l.P(";") * sql_query_footer_error * sql_query_footer_io )

function process_message ()
	local log = read_message("Payload")

	local tmp
	-- common fields
	msg.Fields['query_type'] = nil
	msg.Fields['real-time'] = nil
	msg.Fields['wall-time'] = nil
	msg.Fields['total-matches'] = nil
	msg.Fields['io_stats'] = nil
	-- only for plain format
	msg.Fields['match-mode'] = nil
	msg.Fields['filters-count'] = nil
	msg.Fields['sort-mode'] = nil
	msg.Fields['offset'] = nil
	msg.Fields['limit'] = nil
	msg.Fields['groupby-attr'] = nil
	msg.Fields['index-names'] = nil
	msg.Fields['query_plain'] = nil
	-- only for SphinxQL format
	msg.Fields['connection_id'] = nil
	msg.Fields['query_sql'] = nil
	msg.Fields['query_error'] = nil

	-- save original UUID
	msg.Fields["oiriginal_UUID"] = read_message("Uuid")

	tmp = plain_query_grammar:match(log)
	if tmp then
		msg.Timestamp = tmp.timestamp
		msg.Payload = nil
		msg.Fields['query_type'] = 'plain'
		msg.Fields['real-time'] = tmp['real-time']
		msg.Fields['wall-time'] = tmp['wall-time']
		msg.Fields['query_multiplier'] = tmp['query_multiplier']
		msg.Fields['match-mode'] = tmp['match-mode']
		msg.Fields['filters-count'] = tmp['filters-count']
		msg.Fields['sort-mode'] = tmp['sort-mode']
		msg.Fields['total-matches'] = tmp['total-matches']
		msg.Fields['offset'] = tmp['offset']
		msg.Fields['limit'] = tmp['limit']
		msg.Fields['groupby-attr'] = tmp['groupby-attr']
		msg.Fields['index-names'] = tmp['index-names']
		msg.Fields['io_stats'] = tmp['io_stats']
		msg.Fields['query_plain'] = tmp['query_plain']
		inject_message(msg)
		return 0
	else
		tmp = sql_query_grammar:match(log)
		if tmp then
			msg.Timestamp = tmp.timestamp
			msg.Payload = nil
			msg.Fields['query_type'] = 'SphinxQL'
			msg.Fields['real-time'] = tmp['real-time']
			msg.Fields['wall-time'] = tmp['wall-time']
			msg.Fields['total-matches'] = tmp['total-matches']
			msg.Fields['connection_id'] = tmp['connection_id']
			msg.Fields['query_sql'] = tmp['query_sql']
			msg.Fields['query_error'] = tmp['query_error']
			msg.Fields['io_stats'] = tmp['io_stats']
			inject_message(msg)
			return 0
		else
			return -1
		end
	end
end
