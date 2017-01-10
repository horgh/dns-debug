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

	msgs.each do |msg|
		print_message(msg)
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

		opts.on("-fFILE", "--file=FILE", "File containing messages.") do |o|
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
end

exit(main ? 0 : 1)
