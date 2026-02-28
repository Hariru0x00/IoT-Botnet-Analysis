rule Linux_Gafgyt_Variant_Victim02 {
    meta:
        description = "Detects Gafgyt/Mirai variant based on victim_02.elf sample"
        author = "Analyst & hina"
        date = "2026-02-14"
        hash = "b9d418f63a5846eaab052335b740d5d384a312b03fe9e440fa289b6488438b73"
        threat_level = "High"

    strings:
        // 1. Identified IP addresses and Domains (IOCs)
        $c2_ip1 = { 0a 00 00 19 } // 10.0.0.25 in Little Endian
        $c2_ip2 = "38.60.250.111"
        $c2_domain = "duckdns.org"

        // 2. User-Agent strings used for HTTP Flood attacks (from 4.txt)
        $ua1 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.10; rv:40.0) Gecko/20100101 Firefox/40.0"
        $ua2 = "Mozilla/5.0 (iPad; CPU OS 7_1_2 like Mac OS X)"
        $ua3 = "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0)"

        // 3. System commands used for hiding and removing traces
        $cmd1 = "systemctl kill -s HUP rsyslog.service"
        $cmd2 = "rm -rf /var/log/syslog"
        $cmd3 = "/usr/lib/rsyslog/rsyslog-rotate"
        
        // 4. Gafgyt family characteristics
        $gaf1 = "BUILD LNX"
        $gaf2 = "PONG"
        $gaf3 = "HTTPFLOOD"

    condition:
        // Condition: Is ELF file and matches at least 1 IP or Domain accompanied by behavioral indicators
        uint32(0) == 0x464c457f and 
        (
            ($c2_domain or any of ($c2_ip*)) and 
            (2 of ($ua*)) and 
            (any of ($cmd*)) or
            (all of ($gaf*))
        )
}
