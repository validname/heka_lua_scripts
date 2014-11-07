--[[
Very simple CSV parser.
Pros:
+ It can parse timestamp from certain field (and then removes that field).
Cons:
- It ignores quotes and hence, it ignores field delimiters and line endings in the fileds. (Actually, it should be used only with 'non-printable' delimiters (e.g.: '\t')).
- It doesn't keep payload. 

Config:

- field_delimiter (string, optional, default ','):
    Field delimiter.

- field_names (string, optional, default nil):
    Field names list, separated by 'field_delimiter' character. If it's missed, fild names will be labeled as 'field_%field_number%'.

- ts_field_number (number, optional, default nil):
    Number of field with timestamp.

- ts_format (string, optional, default nil):
    Format of timestamp, see strftime() description. You must set either both ts_field_number and ts_format parameters or none of them.

- tz (string, optional, defaults to UTC):
    Timezone.

- type (string, optional, default nil):
    Sets the message 'Type' header to the specified value.

*Example Heka Configuration*

.. code-block:: ini

    [NginxAccessLogs]
    type = "LogstreamerInput"
    log_directory = "/var/log/nginx"
    file_match = 'access\.log'
    decoder = "CSVDecoder"

    [CSVDecoder]
    type = "SandboxDecoder"
    filename = "lua_decoders/ngs.csv_decoder.lua"

    [CSVDecoder.config]
    field_delimiter = "\t"
    field_names = "time_local\tmsec\tremote_addr\tproxy_add_x_forwarded_for\thostname\turl\request_length\tstatus\trequest_time\tupstream_response_time\tupstream_addr\tupstream_status\tbody_bytes_sent\tgzip_ratio\tcache_status\trequest_filename\thttp_referer\thttp_user_agent\tgeo_country\tgeo\tuid_got\tuid_set"
    ts_field_number = 1
    ts_format = "[%d/%b/%Y:%H:%M:%S %z]"
    type = "nginx_access_tsv"
    tz = "Asia/Novosibirsk"

*Example Heka Message*

:Timestamp: 2014-09-29 11:55:15 +0700 NOVT
:Type: nginx_access_tsv
:Hostname: frontend
:Pid: 0
:UUID: f34e3443-9e9d-43d5-ac62-d027739a27f4
:Logger: NginxAccessLogs
:Payload:
:EnvVersion:
:Severity: 7
:Fields:
    | name:"msec" value_string:"1411991715.646"
    | name:"remote_addr" value_string:"37.193.151.190"
    | name:"proxy_add_x_forwarded_for" value_string:"37.193.151.190"
    | name:"hostname" value_string:"frontend2"
    | name:"url" value_string:"GET http://news.ngs.ru/static/img/agelimit/age_limit_ngs_sm_18b.png"
    | name:"request_length" value_string:"1149"
    | name:"status" value_string:"304"
    | name:"request_time" value_string:"0.000"
    | name:"upstream_response_time" value_string:"-"
    | name:"upstream_addr" value_string:"-"
    | name:"upstream_status" value_string:"-"
    | name:"body_bytes_sent" value_string:"0"
    | name:"gzip_ratio" value_string:"-"
    | name:"cache_status" value_string:""
    | name:"request_filename" value_string:"/data/projects/news.ngs.ru/www/static/img/agelimit/age_limit_ngs_sm_18b.png"
    | name:"http_referer" value_string:"http://news.ngs.ru/more/1940001/"
    | name:"http_user_agent" value_string:"Mozilla/5.0 iPad; CPU OS 7_1_2 like Mac OS X AppleWebKit/537.51.2 KHTML, like Gecko YaBrowser/14.8.1985.9542.11 Mobile/11D257 Safari/9537.53"
    | name:"geo_country" value_string:"RU"
    | name:"geo" value_string:"54
    | name:"uid_got" value_string:"ngs_uid=664C10ACF1AE0E548118358402FF9203"
    | name:"uid_set" value_string:"-"
--]]

local string	= require "string"
local dt	= require "date_time"
local l		= require 'lpeg'
l.locale(l)

local field_delimiter	= read_config("field_delimiter")
if not field_delimiter then field_delimiter = ',' end
local field_names	= read_config("field_names")
local msg_type		= read_config("type")
local ts_field_number	= read_config("ts_field_number")
local ts_format		= read_config("ts_format")
local ts_grammar = nil
if not ts_format or not ts_field_number then			-- must be both defined! all or nothing, he-he
	ts_format = nil
	ts_field_number = nil
elseif ts_format and ts_field_number then
-- build timestamp grammar
	ts_grammar = l.Ct( l.Cg( dt.build_strftime_grammar(ts_format) / dt.time_to_ns, "timestamp" ) )
end

-- based on http://lua-users.org/wiki/LuaCsv but simplified to almost nothing.
-- TODO: rewrite parser to use LPeg, see http://www.inf.puc-rio.br/~roberto/lpeg/#CSV

-- set array with field names
local field_names_array = {}
local pos = 1
local i = 1
while field_names do
	local c = string.sub(field_names, pos, pos)
	if (c == "") then break end
	local startp,endp = string.find(field_names, field_delimiter, pos)
	if (startp) then
		field_names_array[i] = string.sub(field_names, pos, startp-1)
		pos = endp + 1
	else
		-- no delimiter found -> use rest of string and terminate
		field_names_array[i] = string.sub(field_names, pos)
		break
	end 
	i = i + 1
end

local msg = {
	Timestamp	= nil,
	Type		= msg_type,
	Payload		= nil,
	Fields		= {}
}

function process_message ()
	local payload = read_message("Payload")
	local pos = 1
	local i = 1	-- field number
	local field_name, field_value
	local loop = true
	msg.Payload = nil
	msg.Fields = {}
	while loop do
		local c = string.sub(payload, pos, pos)
		if (c == "") then
			msg.Payload = payload
			break
		end
		local startp, endp = string.find(payload, field_delimiter, pos)
		if ( field_names_array[i] ) then
			field_name = field_names_array[i]
		else
			field_name = string.format("field_%d", i)
		end
		if startp then
			field_value = string.sub(payload, pos, startp-1)
			pos = endp + 1
		else
			-- no delimiter found -> use rest of string and terminate
			-- find optional string end
			local startp = string.find(payload, "\n", pos)
			if (startp) then -- there is \n on the end
				field_value = string.sub(payload, pos, startp-1)
			else
				field_value = string.sub(payload, pos)
			end
			loop = false
		end

		if ts_field_number and i==ts_field_number then
			local tmp = ts_grammar:match( field_value )
			if tmp and tmp.timestamp then
				msg.Timestamp = tmp.timestamp
			else
				msg.Timestamp = nil
				msg.Fields[field_name] = field_value
			end
		else
			msg.Fields[field_name] = field_value
		end
		i = i + 1
	end
	-- save original UUID
	msg.Fields["oiriginal_UUID"] = read_message("Uuid")
	inject_message(msg)
	return 0
end
