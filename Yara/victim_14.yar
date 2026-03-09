rule Malware_SPARC_Victim14_Botnet {
    meta:
        description = "Detects Botnet variants (Mirai/Gafgyt) on SPARC architecture"
        author = "hina"
        reference = "Analysis of victim_14.elf sample"
        date = "2026-03-09"

    strings:
        /* Infrastructure indicators (C2) in Plaintext */
        $c2_domain = "intranet.milnetstresser.ru" ascii wide
        $c2_ip = "141.98.10.50" ascii wide

        /* Important shell command strings (XORed with 0x54) */
        // Decoded: "/bin/busybox"
        $enc_busybox = "{6=:{6!'-6;,t" ascii
        // Decoded: "/bin/sh -c"
        $enc_sh = "{01\"{9='7{#5 7<0;3T" ascii
        // Decoded: "Mozilla/5.0 (Windows NT" (User-Agent for HTTP DDoS)
        $enc_useragent = "nt5$$81 t:; t2;!:0T" ascii
        // Decoded: "Listening on port %d..."
        $enc_listen = "=: &5:1 z9=8:1 ' &1''1&z&!T" ascii

        /* Characteristic Opcode on SPARC (XNOR instruction for bitwise data manipulation) */
        // Opcode: xnor o2, g0, o2 (94 3a 80 00)
        $op_xnor_logic = { 94 3a 80 00 }

    condition:
        /* Check for ELF32 format, Big Endian, SPARC architecture */
        uint32(0) == 0x464c457f and 
        uint8(4) == 1 and 
        uint8(5) == 2 and 
        uint16(18) == 0x0002 and
        
        /* Matching conditions: C2 indicators OR encoded strings OR machine code characteristics */
        ($c2_domain or $c2_ip) or 
        (2 of ($enc_*)) or 
        ($op_xnor_logic and any of ($enc_*))
}
