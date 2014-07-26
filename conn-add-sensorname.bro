@load ./interface
@load ./sensorname

redef record Conn::Info += {
        sensorname: string &log &optional;
};

event connection_state_remove(c: connection)
        {
		if ( SecurityOnion::interface in SecurityOnion::sensornames)
			{
	                c$conn$sensorname = SecurityOnion::sensornames[SecurityOnion::interface]$sensorname;
			}
        }

