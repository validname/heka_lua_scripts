--[[
Parses the Nginx error logs based on the Nginx hard coded internal format.

Config:

- type (string, optional, default nil):
    Sets the message 'Type' header to the specified value.

- tz (string, optional, defaults to UTC):
    The conversion actually happens on the Go side since there isn't good TZ support here.

*Example Heka Configuration 1*

.. code-block:: ini

    [TestWebserverError]
    type = "LogstreamerInput"
    log_directory = "/var/log/nginx"
    file_match = 'error\.log'
    decoder = "NGSNginxErrorDecoder"

    [NGSNginxErrorDecoder]
    type = "SandboxDecoder"
    filename = "lua_decoders/ngs.nginx_error_log.lua"

    [NGSNginxErrorDecoder.config]
    type = "nginx_error_logs"
    tz = "Asia/Novosibirsk"

Nginx pass through non-printable characters to error log. For example: let URL is 'http://host/uri?var=%0Avalue' and it's rewrited and proxied to upstream. Nginx will write to error log '..., request: "GET /uri?var=%0Avalue HTTP/1.1", upstream: "/uri?var=
value"'. That is, line will be broken by 'line feed' character. It's proved up to version 1.2.9, but no further version was checked. In this case decoder will generate error message on each such line and will be restarted by sandbox. To eliminate messages and performance overhead, you may use log breaking by start of true line instead of 'line feed':

*Example Heka Configuration 2*

.. code-block:: ini

    [TestWebserverError]
    type = "LogstreamerInput"
    log_directory = "/var/log/nginx"
    file_match = 'error\.log'
    decoder = "NGSNginxErrorDecoder"
    parser_type = "regexp"
    delimiter = "\n([0-9]{4}/[0-9]{2}/[0-9]{2} )"
    delimiter_location = "start"

    [NGSNginxErrorDecoder]
    type = "SandboxDecoder"
    filename = "lua_decoders/ngs.nginx_error_log.lua"

    [NGSNginxErrorDecoder.config]
    type = "nginx_error_logs"
    tz = "Asia/Novosibirsk"

*Example Heka Message*

:Timestamp: 2014-09-24 17:19:56 +0700 NOVT
:Type: nginx_error_logs
:Hostname: frontend6
:Pid: 16842
:UUID: a1ee8eb0-e60b-4b81-a143-5dfe9a64b75b
:Logger: TestWebserverError
:Payload: delaying request, excess: 0.015, by zone \u0022common_ip_nonRU\u0022
:EnvVersion:
:Severity: 5
:Fields:
    | name:"thread_id" value_type:DOUBLE value_double:0
    | name:"connection" value_type:DOUBLE value_double:386031267
    | name:"client" value_string:"148.251.112.123"
    | name:"server" value_string:"ngs.ru"
    | name:"request" value_string:"GET /path/index.php?query=string HTTP/1.1
    | name:"subrequest" value_string:"/ssi.php"
    | name:"upstream" value_string:"fastcgi://127.0.0.1:4006"
    | name:"host" value_string:"ngs.ru"
    | name:"referrer" value_string:"http://ngs.ru/"
--]]

local dt	= require "date_time"
local l		= require 'lpeg'
l.locale(l)

local msg_type	= read_config("type")

local msg_fields = {}
-- common fields
msg_fields['query_type'] = nil
msg_fields['real-time'] = nil
msg_fields['wall-time'] = nil
msg_fields['total-matches'] = nil
-- only for plain format
msg_fields['match-mode'] = nil
msg_fields['filters-count'] = nil
msg_fields['sort-mode'] = nil
msg_fields['offset'] = nil
msg_fields['limit'] = nil
msg_fields['groupby-attr'] = nil
msg_fields['index-names'] = nil
msg_fields['query_plain'] = nil
-- only for SphinxQL format
msg_fields['connection_id'] = nil
msg_fields['query_sql'] = nil

local msg = {
	Timestamp	= nil,
	Type		= msg_type,
	Pid		= nil,
	Payload		= nil,
	Fields		= msg_fields
}

local number = l.digit^1
local seconds_float = number * l.P(".") * number

local timestamp = l.Cg( dt.build_strftime_grammar("%a %b %e %f %Y") / dt.time_to_ns, "timestamp" )
local plain_match_mode = l.P("all") + l.P("any") + l.P("phr") + l.P("bool") + l.P("ext")*l.P("2")^-1 + l.P("scan")
local plain_sort_mode = l.P("rel") + l.P("attr-") + l.P("attr+") + l.P("tsegs") + l.P("ext")
local plain_query_header = l.Cg(seconds_float, "real-time" ) * l.P(" sec ") * ( l.Cg(seconds_float, "wall-time" ) * l.P(" sec ") )^-1 * l.P("[") * l.Cg(plain_match_mode, "match-mode") * l.P("/") * l.Cg(number, "filters-count") * l.P("/") * l.Cg(plain_sort_mode, "sort-mode") * l.P(" ") * l.Cg(number, "total-matches") * l.P(" (") * l.Cg(number, "offset") * l.P(",") * l.Cg(number, "limit") * l.P(")") * ( l.P(" @") * l.Cg((l.alpha+l.digit)^1, "groupby-attr") )^-1 * l.P("] [") * l.Cg((l.alpha+l.space+l.digit+l.S("-_,"))^1, "index-names") * l.P("]") * l.P(" ")^-1
local plain_query_grammar = l.Ct( l.P("[") * timestamp * l.P("] ") * plain_query_header * l.Cg( (l.P(1)-l.P("\n"))^0, "query_plain" ) )
local sql_query_header = l.P(".")
local sql_query_grammar = l.Ct( l.P("/* ") * timestamp * sql_query_header * l.P("*/ ") * l.Cg( (l.P(1)-l.P("\n"))^0, "query_sql" ) )

function process_message ()
	local log = read_message("Payload")

	local tmp

	tmp = plain_query_grammar:match(log)
	if tmp then
		msg.Timestamp = tmp.timestamp
		msg.Payload = nil
		msg.Fields['query_type'] = 'plain'
		msg.Fields['real-time'] = tonumber(tmp['real-time'])
		msg.Fields['wall-time'] = tonumber(tmp['wall-time'])
		msg.Fields['match-mode'] = tmp['match-mode']
		msg.Fields['filters-count'] = tonumber(tmp['filters-count'])
		msg.Fields['sort-mode'] = tmp['sort-mode']
		msg.Fields['total-matches'] = tonumber(tmp['total-matches'])
		msg.Fields['offset'] = tonumber(tmp['offset'])
		msg.Fields['limit'] = tonumber(tmp['limit'])
		msg.Fields['groupby-attr'] = tmp['groupby-attr']
		msg.Fields['index-names'] = tmp['index-names']
		msg.Fields['query_plain'] = tmp['query_plain']
		inject_message(msg)
		return 0
	else
		tmp = sql_query_grammar:match(log)
		if tmp then
			msg.Timestamp = tmp.timestamp
			msg.Payload = nil
			msg.Fields['query_type'] = 'SphinxQL'
			msg.Fields['real-time'] = tonumber(tmp['real-time'])
			msg.Fields['wall-time'] = tonumber(tmp['wall-time'])
			msg.Fields['total-matches'] = tonumber(tmp['total-matches'])
			msg.Fields['connection_id'] = tonumber(tmp['connection_id'])
			msg.Fields['query_sql'] = tmp['query_sql']
			inject_message(msg)
			return 0
		else
			return -1
		end
	end
end
