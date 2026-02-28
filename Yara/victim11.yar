rule DetectGafgytVictim11
{
    meta:
        description = "Detect Gafgyt variant from victim_11"

    strings:
        // C2 Infrastructure
        $c2a = "intranet.milnetstresser.ru" ascii
        $c2b = "141.98.10.50" ascii

        // Obfuscated / XORed patterns
        $obf1 = "{6=:{6!'-6;,t" ascii
        $obf2 = "nt5$$81 t:; t2;!:0T" ascii
        $obf3 = "{$&;7{:1 { 7$" ascii

        // Recon paths
        $sys1 = "/sys/devices/system/cpu" ascii
        $sys2 = "/proc/stat" ascii

    condition:
        uint32(0) == 0x464c457f and
        (
            any of ($c2*) or 
            (2 of ($obf*) and all of ($sys*))
        )
}
