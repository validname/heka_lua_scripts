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
    log_directory = "/var/log/php/"
    file_match = 'fpm\.log'
    decoder = "NGSPhpFPMErrorDecoder"

    [NGSPhpFPMErrorDecoder]
    type = "SandboxDecoder"
    filename = "lua_decoders/ngs.php_fpm_log.lua"

    [NGSPhpFPMErrorDecoder.config]
    type = "php_fpm_log"
    tz = "Asia/Novosibirsk"

*Example Heka Message 1*

:Timestamp: 2014-09-24 17:19:56 +0700 NOVT
:Type: php_fpm_logs
:Hostname: phpnode6
:Pid: 0
:UUID: a1ee8eb0-e60b-4b81-a143-5dfe9a64b75b
:Logger: TestWebserverError
:Payload: failed to acquire scoreboard
:EnvVersion:
:Severity: 4
:Fields:

*Example Heka Message 2*

:Timestamp: 2014-09-24 17:19:56 +0700 NOVT
:Type: php_fpm_logs
:Hostname: phpnode6
:Pid: 3456
:UUID: a1ee8eb0-e60b-4b81-a143-5dfe9a64b75b
:Logger: TestWebserverError
:Payload: exited with code 0 after 629.227064 seconds from start
:EnvVersion:
:Severity: 4
:Fields:
    | name:"pool" value_string:"main"

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

local php_fpm_error_levels = l.Cg((
	l.P("DEBUG")		/ "7"
	+ l.P("NOTICE") 	/ "5"
	+ l.P("WARNING")	/ "4"
	+ l.P("ERROR")		/ "3"
	+ l.P("ALERT")		/ "1")
	/ tonumber, "level")
local timestamp	= l.P("[") * l.Cg( dt.build_strftime_grammar("%d-%b-%Y %H:%M:%S") / dt.time_to_ns, "timestamp" ) * l.P("] ")
local level	= php_fpm_error_levels * l.P(": ")
local pool	= l.P("[pool ") * l.Cg((l.R("az") + l.R("AZ") + l.R("09") + l.S("-_ "))^1, "pool") * l.P("] ")
local child	= l.P("child ") * l.Cg(l.R("09")^1, "child" ) * l.P(" ")

local header_grammar	= l.Ct( timestamp * level * l.Cg( (l.P(1)-l.S("\n"))^0, "rest" ) )
local child_header_grammar = l.Ct( pool * child * l.Cg( l.P(1)^0, "rest" ) )

function process_message ()
	local log = read_message("Payload")

	local tmp

	-- mandatory fields in header
	tmp = header_grammar:match(log)
	if tmp then
		msg.Timestamp = tmp.timestamp
		msg.Severity = tmp.level
		log = tmp.rest
	else
		return -1
	end

	tmp = child_header_grammar:match(log)
	if tmp then
		msg.Pid = tmp.child
		msg.Fields.pool = tmp.pool
		log = tmp.rest
	end

	-- msg.Hostname is missed, there is no info for it

	-- other information is not parseable and used as payload
	msg.Payload = log

	-- save original UUID
	msg.Fields["original_UUID"] = read_message("Uuid")

	inject_message(msg)
	return 0
end
