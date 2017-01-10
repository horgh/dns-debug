#
# This program is for debugging DNS server responses.
#
# It constructs a DNS question message manually and then send it via UDP to a
# given DNS server. It then reads and parses the response and dumps out
# everything about it.
#
# My use case is to determine what is going on with a device's DNS server where
# I have little insight into what the device is doing. I see periodic errors
# that I cannot explain, and I want to try to rule out bugs in DNS libraries,
# or at least get very low level to try to better understand what is happening.
#
# I write it in Ruby for practice in the language rather than anything else.
#
# My basis/specification is RFC 1035.
#

require 'optparse'
require 'socket'

def main
	args = get_args
	if args.nil?
		return false
	end

	id = 0
	question = create_question(args[:hostname], id)
	if question.nil?
		puts "unable to create question"
		return false
	end


	puts "Sending question message:"

	print_bytes(question)

	q = parse_message(question)
	if q.nil?
		puts "unable to parse message"
		return false
	end

	print_message(q)


	# I am choosing to use TCP mainly because it appears in the problem case I am
	# investigating TCP is in use.

	puts "Connecting..."

	local_host = nil
	local_port = nil
	sock = Socket.tcp(args[:ip], 53, local_host, local_port,
										{ connect_timeout: args[:timeout] })


	puts "Sending..."

	# When using TCP we must prefix our message with 2 bytes indicating the length.
	question_length = [question.bytesize].pack('n')
	question_msg = question_length+question

	n = send_with_timeout(sock, question_msg, args[:timeout])
	if n != question_msg.bytesize
		puts "failed to write entire question message"
		return false
	end

	puts "Sent #{n} bytes"
	puts ""


	puts "Receiving..."

	resp = read_dns_message_with_timeout(sock, args[:timeout])
	if resp.nil?
		puts "unable to read DNS message"
		return false
	end

	puts "Received #{resp.bytesize} bytes"


	puts "Received message:"

	print_bytes(resp)

	r = parse_message(resp)
	if r.nil?
		puts "unable to parse message"
		return false
	end

	print_message(r)

	return true
end

# Retrieve command line arguments.
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

		opts.on("-t[TIMEOUT]", "--timeout[=TIMEOUT]", "Timeout for network related actions, in seconds. If not provided we use 5 seconds as the default.") do |t|
			args[:timeout] = t.to_i
		end
	end

	opt.parse!

	if !args.has_key?(:ip) || !args.has_key?(:hostname)
		puts opt
		return nil
	end

	if !args.has_key?(:timeout)
		args[:timeout] = 5
	end

	return args
end

# Construct question message. See RFC 1035 section 4 for format.
#
# This always creates an IN A question currently.
#
# Return a byte string on success, or nil on failure.
def create_question(name, id)
	if id >= 2**16
		puts "id is too large"
		return nil
	end

	# Header section

	# ID: 16 bits

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


	header_fields = [
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
	]

	msg = header_fields.pack('nCCnnnn')


	# Question section.

	# Qname
	qname = name_to_labels(name)
	if qname.nil?
		puts "unable to convert given hostname to labels (#{name})"
		return nil
	end

	msg += qname

	# Qtype. 16 bits. Type of RR. 1 is A
	qtype = 1

	# Qclass. 16 bits. Query class. 1 is internet.
	qclass = 1


	question_fields = [
		# 16 bits
		qtype,
		# 16 bits
		qclass
	]

	msg += question_fields.pack('nn')

	return msg
end

# Convert a domain name (hostname) into a sequence of labels.
#
# A label is a single octet specifying the length followed by that many octets.
#
# A sequence ends with a null label, one where the length is zero.
#
# The first two bits of the length octet must be zero. This means 6 bits to
# work with for the length which means each label must be [0, 63] in length.
#
# The entire sequence must be 255 octets or less.
#
# See RFC 1035 section 3.1.
#
# Returns the sequence as a binary string, or nil if error.
def name_to_labels(name)
	sequence = ""

	name.split(".").each do |piece|
		if piece.bytesize > 63
			puts "domain name piece is too long (#{piece.bytesize} bytes)"
			return nil
		end

		sequence += [piece.bytesize, piece].pack("CA*")
	end

	# Null label.
	sequence += [0].pack("C")

	if sequence.bytesize > 255
		puts "domain name is too long (#{sequence.length} bytes)"
		return nil
	end

	return sequence
end

# Print out string's bytes as hex octets.
def print_bytes(s)
	out = ""
	s.bytes.map { |b| out += sprintf("0x%02x", b) + " " }
	puts out
end

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

# Try to send the entirety of the buffer. Use up to timeout seconds.
#
# Returns how many bytes we send.
def send_with_timeout(sock, buf, timeout)
	if timeout == 0
		return 0
	end

	# Wait up to 1 second for socket to be writable.
	rdy = IO.select([], [sock], [], 1)

	# Socket isn't ready within 1 second. Try again. Decrease how long we are now
	# willing to wait by 1 second.
	if rdy == nil
		return send_with_timeout(sock, buf, timeout-1)
	end

	# Try to write. May have a partial write.
	begin
		n = sock.write_nonblock buf
	rescue
	end

	# Wrote it all? Then we're done.
	if n == buf.bytesize
		return n
	end

	# Try again to write whatever is left. Decrease how long we will wait by 1
	# second.
	newbuf = buf.byteslice(n...buf.bytesize)

	return n+send_with_timeout(sock, newbuf, timeout-1)
end

# Try to read a full DNS message. Wait up to timeout seconds.
#
# Return the message's byte buffer if we successfully read a full message.
# Return nil if failure.
def read_dns_message_with_timeout(sock, timeout)
	# When using TCP, the server prefixes messages with two bytes telling the
	# length of the message. Once we know how many bytes there are, ensure we
	# read the entire message.

	buf = ""
	# Start out trying to read 1024 bytes at a time. Once we know how large the
	# message is, read only what we need.
	needed_size = 1024
	msg_size = -1

	# Repeatedly try to read until we hit our timeout.
	while true
		if timeout == 0
			puts "exceeded timeout reading message"
			return nil
		end

		# Wait 1 second for readability.
		rdy = IO.select([sock], nil, nil, 1)
		if rdy == nil
			timeout -= 1
			next
		end

		# Something is there to read. Regardless, wait 1 less second next time.
		timeout -= 1

		# Read.
		buf2 = ""
		begin
			sock.read_nonblock(needed_size, buf2)
		rescue
		end

		if !buf2.nil?
			buf += buf2
		end

		# Get message size from the first two bytes.
		if msg_size == -1 && buf.bytesize >= 2
			pieces = buf.unpack('n')
			msg_size = pieces[0]
		end

		# Figure how how many more bytes we need to read. -2 because the two bytes
		# indicating message size are not included.
		have_msg_size = buf.bytesize-2
		needed_size = msg_size-have_msg_size

		if needed_size == 0
			# Return without the length prefix.
			return buf.byteslice(2...buf.bytesize)
		end
	end
end

exit(main ? 0 : 1)
