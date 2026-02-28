rule Linux_Gafgyt_Ciobaba_Final {
    meta:
        description = "Detects Gafgyt variant from ciobabaservices infrastructure"
        author = "Security Researcher"
        date = "2026-02-15"

    strings:
        $c2_domain = "ciobabaservices.duckdns.org" ascii wide
        $p1 = "/etc/systemd/system/%s.service" ascii
        $p2 = "WantedBy=multi-user.target" ascii
        $p4 = "/proc/self/exe" ascii
        $t1 = "lighttpd" ascii
        $t2 = "uhttpd" ascii
        $a1 = "UDP" ascii wide
        $a4 = "FLOOD" ascii wide

    condition:
        uint32(0) == 0x464c457f and
        ($c2_domain or (2 of ($p*) and 1 of ($t*) and 1 of ($a*)))
}
