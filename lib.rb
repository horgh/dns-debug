#
# Functions common to the DNS programs.
#

# Take DNS message and parse it into its parts.
def parse_message(msg)
	parsed = {}


	# Header section.

	# Header is a constant size. 12 bytes.
	if msg.bytesize < 12
		puts "message is too short to contain a valid header"
		return nil
	end

	hdr = msg[0..11].unpack('nCCnnnn')

	# Bytes 0 and 1
	parsed[:id]     = hdr[0]

	# Byte 2
	parsed[:qr]     = (hdr[1] >> 7) & 0x01
	parsed[:opcode] = (hdr[1] >> 3) & 0x0f
	parsed[:aa]     = (hdr[1] >> 2) & 0x01
	parsed[:tc]     = (hdr[1] >> 1) & 0x01
	parsed[:rd]     = hdr[1] & 0x01

	# Byte 3
	parsed[:ra]     = (hdr[2] >> 7) & 0x01
	parsed[:z]      = (hdr[2] >> 4) & 0x07
	parsed[:rcode]  = hdr[2] & 0x0f

	# Bytes 4 & 5
	parsed[:qdcount] = hdr[3]

	# Bytes 6 & 7
	parsed[:ancount] = hdr[4]

	# Bytes 8 & 9
	parsed[:nscount] = hdr[5]

	# Bytes 10 & 11
	parsed[:arcount] = hdr[6]


	# Current byte offset in the message after we finish with the header.
	offset = 12


	# Question section

	questions, new_offset = parse_questions(msg, offset, parsed[:qdcount])
	if questions.nil?
		puts "unable to parse questions"
		return nil
	end

	parsed[:questions] = questions
	offset = new_offset


	# Answer section.

	answers, new_offset = parse_rrs(msg, offset, parsed[:ancount])
	if answers.nil?
		puts "unable to parse answers"
		return nil
	end

	parsed[:answers] = answers
	offset = new_offset


	# Authority section.

	authorities, new_offset = parse_rrs(msg, offset, parsed[:nscount])
	if authorities.nil?
		puts "unable to parse authorities/ns"
		return nil
	end

	parsed[:authorities] = authorities
	offset = new_offset


	# Additional section.

	additionals, new_offset = parse_rrs(msg, offset, parsed[:arcount])
	if additionals.nil?
		puts "unable to parse additionals"
		return nil
	end

	parsed[:additionals] = additionals
	offset = new_offset

	return parsed
end

# Parse question section
#
# Returns nil if error, or [questions (array of hashes), new offset] on success
def parse_questions(msg, offset, qdcount)
	questions = []

	for i in 0..qdcount-1
		name, new_offset = labels_to_name(msg, offset)
		if name.nil?
			puts "unable to parse question #{i} at offset #{offset}"
			return nil
		end

		offset = new_offset

		if offset+4-1 > msg.bytesize-1
			puts "malformed message. qtype/qclass not found"
			return nil
		end

		# Take 4 bytes. They contain qtype and qclass.
		q = msg.byteslice(offset...offset+4).unpack('nn')

		questions << {
			name:   name,
			qtype:  q[0],
			qclass: q[1],
		}

		offset += 4
	end

	return questions, offset
end

# Parse name at given offset.
#
# Returns nil if error.
# Returns [name, new offset] if parsed.
def labels_to_name(msg, offset)
	name = ""
	while true
		if offset > msg.bytesize-1
			puts "label length is outside of message"
			return nil
		end

		length = msg.bytes[offset]
		offset += 1

		# Length octet either starts with 00 indicating it is a label, or with 11
		# indicating it is a pointer (message compression, see RFC 1035 section 4.1.4)

		# 0xc0 is 0b1100 0000. Check the value of the first two bits.

		if ~length & 0xc0 == 0xc0
			# We end at zero length label.
			if length == 0
				return name, offset
			end

			if offset+length-1 > msg.bytesize-1
				puts "message is too short to contain the label"
				return nil
			end

			name += msg.byteslice(offset...offset+length) + "."
			offset += length

			next
		end

		if length & 0xc0 == 0xc0
			# Pointer is 2 octets.

			if offset > msg.bytesize-1
				puts "message is too short to contain pointer"
				return nil
			end

			# Drop the 11 on the first.
			pointer = ((length & 0x3f) << 4) | msg.bytes[offset]
			offset += 1

			name_piece, new_offset = labels_to_name(msg, pointer)
			name += name_piece

			# Keep current offset. new_offset is if we were parsing where the pointer
			# pointed.
			return name, offset
		end

		puts "invalid label prefix"
		return nil
	end
end

# Parse resource records. These are what make up
# answers/authoritities/additionals sections.
#
# Return nil on error
# Return [array of hashes, new offset] on success.
def parse_rrs(msg, offset, count)
	rrs = []

	for i in 0..count-1
		name, new_offset = labels_to_name(msg, offset)
		if name.nil?
			puts "unable to parse rr #{i} at offset #{offset}"
			return nil
		end

		offset = new_offset

		# Type (2 bytes), class (2 bytes), TTL (4 bytes), rdlength (2 bytes)

		if offset+10-1 > msg.bytesize-1
			puts "malformed message. type/class/ttl/rdlength not found"
			return nil
		end

		fields = msg.byteslice(offset...offset+10).unpack('nnNn')

		rr = {
			name:     name,
			type:     fields[0],
			class:    fields[1],
			ttl:      fields[2],
			rdlength: fields[3],
		}

		offset += 10

		# Rdata is variable length. Its form depends on the type and class.

		# Type A and class IN means 4 octet RDATA.
		if rr[:type] == 1 && rr[:class] == 1
			if rr[:rdlength] != 4
				puts "unexpected rdlength for IN A"
				return nil
			end

			if offset+4-1 > msg.bytesize-1
				puts "message too short to contain rdata"
				return nil
			end

			rr[:rdata] = sprintf("%d.%d.%d.%d", msg.bytes[offset],
													 msg.bytes[offset+1], msg.bytes[offset+2],
													 msg.bytes[offset+3])
			offset += 4
			rrs << rr
			next
		end

		# Rdata with domain names. NS (2), CNAME (5).
		if (rr[:type] == 2 || rr[:type] == 5) && rr[:class] == 1
			name, new_offset = labels_to_name(msg, offset)
			if name.nil?
				puts "unable to parse domain name. type: #{rr[:type]} offset: #{offset}"
				return nil
			end

			offset = new_offset

			rr[:rdata] = name
			rrs << rr
			next
		end

		# Not yet implemented.
		puts "rdata type not yet supported. type: #{rr[:type]} class: #{rr[:class]}"

		if offset+rr[:rdlength]-1 > msg.bytesize-1
			puts "message too short to contain rdata"
			return nil
		end

		rr[:rdata] = nil

		rrs << rr

		offset += rr[:rdlength]
	end

	return rrs, offset
end

# Print out a parsed message.
#
# msg is a hash.
def print_message(msg)
	puts "ID: #{msg[:id]}"

	if msg[:qr] == 0
		puts "QR: #{msg[:qr]} (query)"
	else
		puts "QR: #{msg[:qr]} (response)"
	end

	if msg[:opcode] == 0
		puts "OPCODE: #{msg[:opcode]} (standard query)"
	elsif msg[:opcode] == 1
		puts "OPCODE: #{msg[:opcode]} (inverse query)"
	elsif msg[:opcode] == 2
		puts "OPCODE: #{msg[:opcode]} (server status)"
	else
		puts "OPCODE: #{msg[:opcode]} (reserved)"
	end

	if msg[:aa] == 0
		puts "AA: #{msg[:aa]} (not authoritative)"
	else
		puts "AA: #{msg[:opcode]} (authoritative)"
	end

	if msg[:tc] == 0
		puts "TC: #{msg[:tc]} (not truncated)"
	else
		puts "TC: #{msg[:tc]} (truncated)"
	end

	if msg[:rd] == 0
		puts "RD: #{msg[:rd]} (recursion not desired)"
	else
		puts "RD: #{msg[:rd]} (recursion desired)"
	end

	if msg[:ra] == 0
		puts "RA: #{msg[:ra]} (recursion not available)"
	else
		puts "RA: #{msg[:ra]} (recursion available)"
	end

	puts "Z: #{msg[:z]} (meaningless)"

	if msg[:rcode] == 0
		puts "RCODE: #{msg[:rcode]} (no error)"
	elsif msg[:rcode] == 1
		puts "RCODE: #{msg[:rcode]} (format error)"
	elsif msg[:rcode] == 2
		puts "RCODE: #{msg[:rcode]} (SERVFAIL)"
	elsif msg[:rcode] == 3
		puts "RCODE: #{msg[:rcode]} (NXDOMAIN)"
	elsif msg[:rcode] == 4
		puts "RCODE: #{msg[:rcode]} (server has not implemented support)"
	elsif msg[:rcode] == 5
		puts "RCODE: #{msg[:rcode]} (refused)"
	else
		puts "RCODE: #{msg[:rcode]} (reserved)"
	end

	puts "QDCOUNT: #{msg[:qdcount]}"

	for i in 0..msg[:qdcount]-1
		puts "Question #{i}:"

		puts "  QNAME: #{msg[:questions][i][:name]}"

		type_str = qtype_to_string(msg[:questions][i][:qtype])
		puts "  QTYPE: #{msg[:questions][i][:qtype]} (#{type_str})"

		class_str = qclass_to_string(msg[:questions][i][:qclass])
		puts "  QCLASS: #{msg[:questions][i][:qclass]} (#{class_str})"
	end

	puts "ANCOUNT: #{msg[:ancount]}"
	print_rrs(msg[:answers])

	puts "NSCOUNT: #{msg[:nscount]}"
	print_rrs(msg[:authorities])

	puts "ARCOUNT: #{msg[:arcount]}"
	print_rrs(msg[:additionals])
end

# Print out RR information.
#
# Provide this function with the hashes from parse_rrs().
def print_rrs(rrs)
	rrs.each do |rr|
		puts "RR:"

		puts "  NAME: #{rr[:name]}"

		type_str = type_to_string(rr[:type])
		puts "  TYPE: #{rr[:type]} (#{type_str})"

		class_str = class_to_string(rr[:class])
		puts "  CLASS: #{rr[:class]} (#{class_str})"

		puts "  TTL: #{rr[:ttl]}"

		puts "  RDLENGTH: #{rr[:rdlength]}"

		puts "  RDATA: #{rr[:rdata]}"
	end
end

# QTYPE to string
def qtype_to_string(t)
	case t
	when 252
		return "AXFR"
	when 253
		return "MAILB"
	when 254
		return "MAILA"
	when 255
		return "*"
	else
		return type_to_string(t)
	end
end

# DNS TYPE to string.
def type_to_string(t)
	case t
	when 1
		return "A"
	when 2
		return "NS"
	when 3
		return "MD"
	when 4
		return "MF"
	when 5
		return "CNAME"
	when 6
		return "SOA"
	when 7
		return "MB"
	when 8
		return "MG"
	when 9
		return "MR"
	when 10
		return "NULL"
	when 11
		return "WKS"
	when 12
		return "PTR"
	when 13
		return "HINFO"
	when 14
		return "MINFO"
	when 15
		return "MX"
	when 16
		return "TXT"
	else
		return "unknown"
	end
end

# QCLASS to string
def qclass_to_string(c)
	case c
	when 255
		return "*"
	else
		return class_to_string(c)
	end
end

# DNS CLASS to string.
def class_to_string(c)
	case c
	when 1
		return "IN"
	when 2
		return "CS"
	when 3
		return "CH"
	when 4
		return "HS"
	else
		return "unknown"
	end
end
