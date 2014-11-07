--[[
Parses Sphinx search searchd log (up to version 2.25).

Config:

- type (string, optional, default nil):
    Sets the message 'Type' header to the specified value.

- tz (string, optional, defaults to UTC):
    Timezone.

*Example Heka Configuration*

.. code-block:: ini

    [SphinxSearchd]
    type = "LogstreamerInput"
    log_directory = "/var/log/sphinx"
    file_match = 'searchd\.log'
    decoder = "SphinxSearchdDecoder"

    [SphinxSearchdDecoder]
    type = "SandboxDecoder"
    filename = "lua_decoders/ngs.sphinx_searchd_log.lua"

    [SphinxSearchdDecoder.config]
    type = "sphinx_searchd_logs"
    tz = "Asia/Novosibirsk"

*Example Heka Message 1*

:Timestamp: 2014-09-24 17:19:56 +0700 NOVT
:Type: sphinx_searchd_logs
:Hostname: search1
:Pid: 23678
:UUID: a1ee8eb0-e60b-4b81-a143-5dfe9a64b75b
:Logger: SphinxSearchd
:Payload: failed to send server version (client=127.0.0.1:50986(534692118))
:EnvVersion:
:Severity: 4
:Fields:
--]]

local dt	= require "date_time"
local l		= require 'lpeg'
l.locale(l)

local msg_type	= read_config("type")

local msg = {
	Timestamp	= nil,
	Type		= msg_type,
	Severity        = nil,
	Pid		= nil,
	Payload		= nil,
	Fields		= {}
}

local number = l.digit^1
local seconds_float = number * l.P(".") * number

local ts_weekday = l.P"Mon" + "Tue" + "Wed" + "Thu" + "Fri" + "Sat" + "Sun"
local timestamp = l.Cg( l.Ct( ts_weekday * l.P(" ") * dt.date_mabbr * l.P(" ") * dt.date_mday_sp * l.P(" ") * dt.rfc3339_partial_time * l.P(" ") * dt.date_fullyear ) / dt.time_to_ns, "timestamp" )
--local log_level = ( l.Cg(l.P + l.P + l.P("") + l.P), "log_level")
local log_level = l.Cg((
	l.P("DEBUG")		/ "7"
	+ l.P("WARNING")	/ "4"
	+ l.P("FATAL")		/ "0")
	/ tonumber, "log_level") * l.P(": ")

local log_grammar = l.Ct( l.P("[") * timestamp *l.P("] [") * (l.P(" ")^1)^-1 * l.Cg(l.digit^1 / tonumber, "pid") * l.P("] ") * log_level^-1 * l.Cg( (l.P(1)-l.P("\n"))^0, "rest" ) )

function process_message ()
	local log = read_message("Payload")

	local tmp

	tmp = log_grammar:match(log)
	if tmp then
		msg.Timestamp = tmp.timestamp
		msg.Pid = tmp.pid
		msg.Severity = tmp.log_level
		msg.Payload = tmp.rest
		-- save original UUID
		msg.Fields["oiriginal_UUID"] = read_message("Uuid")
		inject_message(msg)
		return 0
	else
		return -1
	end
end
