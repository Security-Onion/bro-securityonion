##! This script is to support the bpf.conf file like other network monitoring tools use.
##! Please don't try to learn from this script right now, there are a large number of
##! hacks in it to work around bugs discovered in Bro.

@load base/frameworks/notice
@load ./interface
@load ./sensorname

module BPFConf;

export {
	## The file that is watched on disk for BPF filter changes.
	## A templated variable is available: "sensorname".
	## It can be used by surrounding the term by doubled curly braces.
	const filename = "/etc/nsm/{{sensorname}}/bpf-bro.conf" &redef;

	redef enum Notice::Type += { 
		## Invalid filter notice.
		InvalidFilter
	};
}

global filter_parts: vector of string = vector();

global current_filter_filename = "";

type FilterLine: record {
	s: string;
};

global last_line = current_time();
global ignore_lines_until = last_line;

redef enum PcapFilterID += {
	BPFConfPcapFilter,
};


event is_filter_done()
	{
	if ( |filter_parts| > 0 && current_time() - last_line > 5msec )
		{
		local filter = join_string_vec(filter_parts, " ");
		capture_filters["bpf.conf"] = filter;
		
		if ( precompile_pcap_filter(BPFConfPcapFilter, filter) )
			{
			PacketFilter::install();
			}
		else
			{
			NOTICE([$note=InvalidFilter,
			        $msg=fmt("Compiling packet filter from %s failed", filename),
			        $sub=filter]);
			}

		filter_parts=vector();
		}
	}

event BPFConf::line(description: Input::EventDescription, tpe: Input::Event, s: string)
	{
	last_line = current_time();
	if ( last_line < ignore_lines_until )
		return;

	local part = sub(s, /[[:blank:]]*#.*$/, "");

	# There is a bug in the input framework where it's reading the file twice the first time.
	# If there is a duplicate line, this avoids rereading it.
	if ( |filter_parts| > 0 && filter_parts[0] == part )
		{
		ignore_lines_until = last_line + 2secs;
		return;
		}
	
	# We don't want any blank parts.
	if ( part != "" )
		filter_parts[|filter_parts|] = part;

	schedule 2secs { is_filter_done() };
	}


function add_filter_file()
	{
	local real_filter_filename = BPFConf::filename;

	# Support the sensorname template value.
	if ( SecurityOnion::interface in SecurityOnion::sensornames)
		{
		if ( SecurityOnion::sensornames[SecurityOnion::interface]$sensorname != "" )
			real_filter_filename = gsub(real_filter_filename, /\{\{sensorname\}\}/, SecurityOnion::sensornames[SecurityOnion::interface]$sensorname);
		}

	if ( /\{\{/ in real_filter_filename )
		{
		Reporter::warning(fmt("Template value remaining in BPFConf filename: %s", real_filter_filename));
		return;
		}
	else
		Reporter::info(fmt("BPFConf filename set: %s", real_filter_filename));

	if ( real_filter_filename != current_filter_filename )
		{
		current_filter_filename = real_filter_filename;
		Input::add_event([$source=real_filter_filename,
		                  $name="bpfconf",
		                  $reader=Input::READER_RAW,
		                  $mode=Input::REREAD,
		                  $want_record=F,
		                  $fields=FilterLine,
		                  $ev=BPFConf::line]);
		}
	}

event Input::end_of_data(name: string, source: string) 
	{
	add_filter_file();
	}
