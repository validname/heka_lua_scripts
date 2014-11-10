--[[
Parses the Nginx error logs based on the Nginx hard coded internal format.

Config:

- type (string, optional, default nil):
    Sets the message 'Type' header to the specified value.

- tz (string, optional, defaults to UTC):
    Timezone.

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

local msg = {
	Timestamp	= nil,
	Type		= msg_type,
	Severity	= nil,
	Pid		= nil,
	Hostname	= nil,
	Payload		= nil,
	Fields		= {}
}

local unquoted_string	= l.P("\"") * l.C( (l.P(1)-l.S("\"\n"))^0)

local timestamp		= l.Cg( dt.build_strftime_grammar("%Y/%m/%d %H:%M:%S") / dt.time_to_ns, "timestamp" )
local ts_grammar	= l.Ct( timestamp * l.Cg( l.P(1)^0, "rest" ) )

local error_levels = l.Cg((
	l.P("debug")	/ "7"
	+ l.P("info")	/ "6"
	+ l.P("notice")	/ "5"
	+ l.P("warn")	/ "4"
	+ l.P("error")	/ "3"
	+ l.P("crit")	/ "2"
	+ l.P("alert")	/ "1"
	+ l.P("emerg")	/ "0")
	/ tonumber, "level")

local header_grammar	= l.Ct( l.P(" [") * error_levels * l.P("] ") * l.Cg(l.digit^1, "pid") * l.P("#") * l.Cg(l.digit^1, "tid") * l.P(": *") * l.Cg(l.digit^1, "cid") * l.P(" ") * l.Cg( l.P(1)^0, "rest" ) )

local client_prefix	= l.P(", client: ")
local before_client	= l.Cg( (l.P(1)-client_prefix)^0, "begin" )
local client		= client_prefix * l.Cg( l.P(1)^0, "client")
local client_grammar	= l.Ct( before_client * client )

local server_prefix	= l.P(", server: ")
local before_server	= l.Cg( (l.P(1)-server_prefix)^0, "begin" )
local server		= server_prefix * l.Cg( l.P(1)^0, "server")
local server_grammar	= l.Ct( before_server * server )

local request_prefix	= l.P(", request: ")
local before_request	= l.Cg( (l.P(1)-request_prefix)^0, "begin" )
local request		= request_prefix * l.Cg( l.P(1)^0, "request")
local request_grammar	= l.Ct( before_request * request )

local subrequest_prefix		= l.P(", surequest: ")
local before_subrequest		= l.Cg( (l.P(1)-subrequest_prefix)^0, "begin" )
local subrequest		= subrequest_prefix * l.Cg( l.P(1)^0, "subrequest")
local subrequest_grammar	= l.Ct( before_subrequest * subrequest )

local upstream_prefix	= l.P(", upstream: ")
local before_upstream	= l.Cg( (l.P(1)-upstream_prefix)^0, "begin" )
local upstream		= upstream_prefix * l.Cg( l.P(1)^0, "upstream")
local upstream_grammar	= l.Ct( before_upstream * upstream )

local host_prefix	= l.P(", host: ")
local before_host	= l.Cg( (l.P(1)-host_prefix)^0, "begin" )
local host		= host_prefix * l.Cg( l.P(1)^0, "host")
local host_grammar	= l.Ct( before_host * host )

local referrer_prefix	= l.P(", referrer: ")
local before_referrer	= l.Cg( (l.P(1)-referrer_prefix)^0, "begin" )
local referrer		= referrer_prefix * l.Cg( l.P(1)^0, "referrer")
local referrer_grammar	= l.Ct( before_referrer * referrer )

function parse_end ( string, var_name, grammar )
	local var, string_begin, tmp, tmp2

	tmp = grammar:match( string )
	if tmp then
		if tmp[var_name] then
			tmp2 = unquoted_string:match( tmp[var_name] )
			if tmp2 then
				var = tmp2
			else
				var = tmp[var_name]
			end
		end
		string_begin = tmp.begin
	else
		string_begin = string
	end
	return var, string_begin
end

function process_message ()
	local log = read_message("Payload")

	local tmp

	-- mandatory fields: only timestamp
	tmp = ts_grammar:match(log)
	if tmp then
		msg.Timestamp = tmp.timestamp
		log = tmp.rest
	else
		return -1
	end

	-- msg level, process id, thread id and connection id is mandatory fields for nginx but it's not a big problem if we don't parse them
	tmp = header_grammar:match(log)
	if tmp then
		msg.Severity = tmp.level
		msg.Pid = tmp.pid
		msg.Fields.thread_id = tmp.tid
		msg.Fields.connection = tmp.cid
		log = tmp.rest
	end

	-- msg.Hostname is missed, there is no info for it

	-- optional referrer from the end of line
	msg.Fields.referrer, log = parse_end ( log, "referrer", referrer_grammar )
	-- optional host from the end of line
	msg.Fields.host, log = parse_end ( log, "host", host_grammar )
	-- optional upstream from the end of line
	msg.Fields.upstream, log = parse_end ( log, "upstream", upstream_grammar )
	-- optional request from the end of line
	msg.Fields.request, log = parse_end ( log, "request", request_grammar )
	-- optional subrequest from the end of line
	msg.Fields.subrequest, log = parse_end ( log, "subrequest", subrequest_grammar )
	-- optional server from the end of line
	msg.Fields.server, log = parse_end ( log, "server", server_grammar )
	-- optional client from the end of line
	msg.Fields.client, log = parse_end ( log, "client", client_grammar )

	-- other information is not parseable and used as payload
	msg.Payload = log
	-- save original UUID
	msg.Fields["original_UUID"] = read_message("Uuid")

	inject_message(msg)
	return 0
end
