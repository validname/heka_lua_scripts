--[[
Config:

- field_delimiter (string)

- field_names (string)

*Example Heka Configuration*

.. code-block:: ini

*Example Heka Message*

:Timestamp: 2014-01-10 07:04:56 -0800 PST
:Type: combined
:Hostname: test.example.com
:Pid: 0
:UUID: 8e414f01-9d7f-4a48-a5e1-ae92e5954df5
:Logger: TestWebserver
:Payload:
:EnvVersion:
:Severity: 7
:Fields:
    | name:"remote_user" value_string:"-"
--]]

local string	= require "string"
local dt	= require "date_time"
local l		= require 'lpeg'

local field_delimiter	= read_config("field_delimiter")
if not field_delimiter then field_delimiter = ',' end		-- default: ','
local field_names	= read_config("field_names")		-- defailt: nil, field names will be 'field_%field_number%'. List must be delimited by the 'field_delimiter' character!
local output_msg_type	= read_config("output_msg_type")	-- default: nil, which means type from original message (will be copied by Sanbox runner)
local ts_field_number	= read_config("ts_field_number")	-- default: nil
local ts_format		= read_config("ts_format")		-- default: nil
local ts_grammar = nil
if not ts_format or not ts_field_number then			-- must be both defined! all or nothing, he-he
	ts_format = nil
	ts_field_number = nil
elseif ts_format and ts_field_number then
-- build timestamp grammar
	ts_grammar = l.Ct( l.Cg( dt.build_strftime_grammar(ts_format) / dt.time_to_ns, "timestamp" ) )
end

-- based on http://lua-users.org/wiki/LuaCsv but simplified to almost nothing. Ignores: quotes (and hence), field delimiters and line endings in the fileds. Actually, it should be used only with non-ASCII delimiters.
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
	Type		= output_msg_type,
	Payload		= nil,
	Fields		= {}
}

function process_message ()
	local payload = read_message("Payload")
	local pos = 1
	local i = 1
	local field_name, field_value
	local loop = true
	msg.Payload = nil
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
--			msg.Fields['ts_type'] = type(tmp)
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
	inject_message(msg)
	return 0
end
