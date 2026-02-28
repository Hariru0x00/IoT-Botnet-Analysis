rule Hakai_Botnet_PPC_Final_v2 {
    meta:
        description = "Detects Hakai Botnet on PPC"
        threat_level = "Critical"

    strings:
        /* Cac chuoi he thong sau khi giai ma */
        $s1 = "hakaiboatnet.pw" ascii
        $s2 = "/proc/net/tcp" ascii
        $s3 = "/dev/watchdog" ascii
        
        /* Dau van tay tac gia */
        $auth = "hacked by hoa long" ascii

        /* Chuoi ma hoa hex thuc te trong binary */
        $hex1 = { 2d 24 2b 24 2c 27 2a 24 31 2b 20 31 6b 35 32 } 
        $hex2 = { 6a 35 37 2a 26 6a 2b 20 31 6a 31 26 35 }

        /* Ten cac ham dac trung */
        $f1 = "table_init"
        $f2 = "tcpFl00d"
        $f3 = "tcpcsum"

    condition:
        uint32(0) == 0x464c457f and
        (
            $s1 or $s2 or $s3 or $auth or ($hex1 and $hex2) or (2 of ($f1, $f2, $f3))
        )
}
