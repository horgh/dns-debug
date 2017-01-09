require 'optparse'
require 'socket'

def main
	args = get_args
	if args.nil?
		return false
	end
	p args

	sock = UDPSocket.new
	sock.connect args[:ip], 53


	# Construct question message. See RFC 1035 section 4 for format.


	# Header section

	# ID: 16 bits
	id = 0


	# QR: 1 bit. 0 for query.
	qr = 0

	# Opcode: 4 bits. 0 for standard query.
	opcode = 0

	# AA (authoritative answer). 1 bit. Leave 0 for query.
	aa = 0

	# TC (truncation). 1 bit. Leave 0 for query.
	tc = 0

	# RD (recursion desired). 1 bit. Specify to query recursively (1)
	rd = 1


	# RA (recursion available). 1 bit. Set in response to indicate whether
	# recursion is available. Leave 0 for query.
	ra = 0

	# Z. 3 bits. Reserved for future use.
	z = 0

	# Rcode. 4 bits. Set in response.
	rcode = 0


	# Qdcount. 16 bits. How many questions.
	qdcount = 1

	# Ancount. 16 bits. How many answers.
	ancount = 0

	# Nscount. 16 bits. How many ns records.
	nscount = 0

	# Arcount. 16 bits. How many additional records.
	arcount = 0


	# Question section.

	# Qname
	domain_name = "icanhazip.com"
	#qname = name_to_label(domain_name)

	# Qtype. 16 bits. Type of RR. 1 is A
	qtype = 1

	# Qclass. 16 bits. Query class. 1 is internet.
	qclass = 1


	fields = [
		# 16 bits
		id,
		# 8 bits
		qr << 7 | opcode << 3 | aa << 2 | tc << 1 | rd,
		# 8 bits
		ra << 7 | z << 4 | rcode,

		# 16 bits
		qdcount,
		# 16 bits
		ancount,
		# 16 bits
		nscount,
		# 16 bits
		arcount,

		# qname
		9,
		"icanhazip",
		3,
		"com",
		0,

		# 16 bits
		qtype,
		# 16 bits
		qclass
	]

	msg = fields.pack('nCCnnnnCA9CA3Cnn')


	puts "Sending message:"
	s = ""
	msg.bytes.map { |b| s += sprintf("0x%02x", b) + " " }
	puts s

	m = parse_message(msg)
	print_message(m)


	n = sock.send msg, 0
	puts "Sent #{n} bytes"


	puts ""

	resp = sock.recv(1024)
	puts "Received #{resp.length} bytes"
	puts "Received message:"
	s = ""
	resp.bytes.map { |b| s += sprintf("0x%02x", b) + " " }
	puts s

	m = parse_message(resp)
	print_message(m)
end

def get_args
	args = {}

	opt = OptionParser.new do |opts|
		opts.banner = "Usage: " + $0 + " [options]"

		opts.on("-h", "--help", "Print this help") do
			puts opts
			return nil
		end

		opts.on("-iIP", "--ip=IP", "IP of DNS server to query.") do |i|
			args[:ip] = i
		end

		opts.on("-nHOSTNAME", "--name=HOSTNAME", "Hostname to look up (A).") do |n|
			args[:hostname] = n
		end
	end

	opt.parse!

	if !args.has_key?(:ip) || !args.has_key?(:hostname)
		puts opt
		return nil
	end

	return args
end

# Take DNS message and parse it into its parts.
def parse_message(msg)
	parsed = {}

	# Header is a constant size. 12 bytes.
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


	# Current byte offset in the message.
	offset = 12


	# Question section

	parsed[:questions] = []

	for i in 0..parsed[:qdcount]-1
		name, new_offset = labels_to_name(msg, offset)
		if name.nil?
			puts "unable to parse question #{i} at offset #{offset}"
			return nil
		end

		offset = new_offset

		# Take 4 bytes. They contain qtype and qclass.
		q = msg[offset..offset+4-1].unpack('nn')

		parsed[:questions] << {
			name:   name,
			qtype:  q[0],
			qclass: q[1],
		}

		offset += 4
	end


	# Answer section.

	parsed[:answers] = []

	for i in 0..parsed[:ancount]-1
		name, new_offset = labels_to_name(msg, offset)
		if name.nil?
			puts "unable to parse answer #{i} at offset #{offset}"
			return nil
		end

		offset = new_offset

		# Type (2 bytes), class (2 bytes), TTL (4 bytes), rdlength (2 bytes)
		fields = msg[offset..offset+10-1].unpack('nnNn')

		answer = {
			name:     name,
			type:     fields[0],
			class:    fields[1],
			ttl:      fields[2],
			rdlength: fields[3],
		}

		offset += 10

		# Rdata is variable length. Its form depends on the type and class.

		# Type A and class IN means 4 octet RDATA.
		if answer[:type] == 1 && answer[:class] == 1
			answer[:rdata] = sprintf("%d.%d.%d.%d", msg.bytes[offset],
															 msg.bytes[offset+1], msg.bytes[offset+2],
															 msg.bytes[offset+3])
			offset += 4
			parsed[:answers] << answer
			next
		end

		# NS
		if answer[:type] == 2 && answer[:class] == 1
			name, new_offset = labels_to_name(msg, offset)
			if name.nil?
				puts "unable to parse ns offset #{offset}"
				return nil
			end

			offset = new_offset

			answer[:rdata] = name
			parsed[:answers] << answer
			next
		end

		puts "rdata type not yet supported"
		answer[:rdata] = nil

		parsed[:answers] << answer

		offset += answer[:rdlength]
	end


	# TODO(horgh): authority/additional

	return parsed
end

# Parse name at given offset.
#
# Returns nil if error.
# Returns [name, new offset] if parsed.
def labels_to_name(msg, offset)
	name = ""
	while true
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

			name += msg[offset..offset+length-1] + "."
			offset += length

			next
		end

		if length & 0xc0 == 0xc0
			# Pointer is 2 octets. Drop the 11 on the first.
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

# Print out a parsed message.
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

		# TODO(horgh): qtype is a superset of type
		type_str = type_to_string(msg[:questions][i][:qtype])
		puts "  QTYPE: #{msg[:questions][i][:qtype]} (#{type_str})"

		# TODO(horgh): qclass is a superset of class
		class_str = class_to_string(msg[:questions][i][:qclass])
		puts "  QCLASS: #{msg[:questions][i][:qclass]} (#{class_str})"
	end

	puts "ANCOUNT: #{msg[:ancount]}"

	for i in 0..msg[:ancount]-1
		puts "Answer #{i}"

		puts "  NAME: #{msg[:answers][i][:name]}"

		type_str = type_to_string(msg[:answers][i][:type])
		puts "  TYPE: #{msg[:answers][i][:type]} (#{type_str})"

		class_str = class_to_string(msg[:answers][i][:class])
		puts "  CLASS: #{msg[:answers][i][:class]} (#{class_str})"

		puts "  TTL: #{msg[:answers][i][:ttl]}"

		puts "  RDLENGTH: #{msg[:answers][i][:rdlength]}"

		puts "  RDATA: #{msg[:answers][i][:rdata]}"
	end

	puts "NSCOUNT: #{msg[:nscount]}"
	puts "ARCOUNT: #{msg[:arcount]}"
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

exit(main ? 0 : 1)
