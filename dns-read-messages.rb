#
# Read DNS messages from a file.
#
# dns-debug can write the raw messages out to a file. This program can read them
# in and decode them.
#
# The purpose is to be able to examine a set of captured messages.

require_relative 'lib.rb'
require 'optparse'

def main
	args = get_args
	if args.nil?
		return false
	end

	mode = "rb"
	fh = File.open(args[:file], mode)

	msgs = read_and_parse_messages(fh)

	fh.close

	i = 0
	msgs.each do |msg|
		puts "Message #{i}:"
		print_message(msg)
		i += 1
	end

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

		opts.on("-f FILE", "--file FILE", "File containing messages.") do |o|
			args[:file] = o
		end
	end

	opt.parse!

	if !args.has_key?(:file)
		puts opt
		return nil
	end

	return args
end

# Read messages from the file. Parse each one.
#
# For the format of each message and the file itself, refer to dns-debug's
# write_message_to_file function.
#
# Returns an array of parsed messages (hashes), or nil if there is a failure.
def read_and_parse_messages(fh)
	msgs = []

	while true
		header_raw = fh.read(6)

		# EOF
		if header_raw.nil?
			break
		end

		if header_raw.bytesize != 6
			puts "unable to read message header, short read"
			return nil
		end

		pieces = header_raw.unpack('nN')

		msg_length = pieces[0]
		msg_unixtime = pieces[1]
		msg_time = Time.at(msg_unixtime)

		puts "Message @ #{msg_time} is #{msg_length} bytes"

		msg_raw = fh.read(msg_length)
		if msg_raw.nil?
			puts "unexpected EOF reading message"
			return nil
		end

		if msg_raw.bytesize != msg_length
			puts "short read on message"
			return nil
		end

		r = parse_message(msg_raw)
		if r.nil?
			puts "unable to parse message"
			return nil
		end

		msgs << r
	end

	return msgs
end

exit(main ? 0 : 1)
