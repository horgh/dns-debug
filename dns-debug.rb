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

require_relative 'lib.rb'
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
