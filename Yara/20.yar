import "elf"

rule Mirai_Gafgyt_SuperRule_Combined {
    meta:
        description = "Combined rule for detecting Mirai/Gafgyt Botnet campaigns from 22 sample files - Fixed Version"
        author = "github"
        version = "2.1"
        severity = "Critical"

    strings:
        /* --- GROUP 1: C2 INFRASTRUCTURE & DOMAINS (IOCs) --- */
        $c2_1 = "ciobabaservices.duckdns.org" ascii wide
        $c2_2 = "slursbeback.ru" ascii wide
        $c2_3 = "blueblackside.com" ascii
        $c2_4 = "connectivity.accesscam.org" ascii
        $c2_5 = "hakaiboatnet.pw" ascii
        $c2_6 = "intranet.milnetstresser.ru" ascii
        $c2_7 = "130.12.180.151" ascii
        $c2_8 = "141.98.10.50" ascii
        $c2_ip_hex = { 32 B7 31 58 } // 50.183.49.88 (encoded)

        /* --- GROUP 2: CPU ARCHITECTURE CHARACTERISTICS (OPCODES) --- */
        $op_sh4_socket = { 02 E5 [0-6] 0B 4? }
        $op_mips_connect = { 24 02 10 4a 00 00 00 0c }
        $op_arm_svc = { 80 ef ?? ?? } 
        $hacker_mark = "KHserverHACKER"

        /* --- GROUP 3: SYSTEM BEHAVIOR & ANTI-ANALYSIS --- */
        $sys_1 = "/proc/self/exe" ascii
        $sys_2 = "/dev/watchdog" ascii
        $sys_3 = "/proc/net/tcp" ascii
        $sys_4 = "OOM_SCORE_ADJ" ascii
        $anti_virt = "HYPERVISOR" ascii // Variable that previously caused errors
        
        /* --- GROUP 4: ATTACK MODULES & KILLER --- */
        $killer_1 = "kdevtmpfsi" ascii wide
        $killer_2 = "xmrig" ascii wide
        $killer_3 = "kinsing" ascii wide
        $attack_1 = "HTTPFLOOD" ascii
        $attack_2 = "sh4_flood" ascii
        $attack_3 = "{ id name email }" // GraphQL variant

        /* --- GROUP 5: CODE TABLES & CHARACTERISTIC TOKENS --- */
        $token = "GDQDPROJH" ascii wide nocase
        $custom_b32 = "w5q6he3dbrsgmclkiu4to18npavj702f" ascii
        $go_magic = "Go build ID:"

    condition:
        // 1. Check ELF format
        uint32(0) == 0x464c457f and
        (
            // 2. Priority match for C2 infrastructure or identification tokens
            any of ($c2_*) or $token or $custom_b32 or $hacker_mark or
            
            // 3. Or match anti-virtualization mechanism + system behavior
            ($anti_virt and any of ($sys_*)) or
            
            // 4. Or combination of CPU Architecture + Behavior + Attack
            (
                any of ($op_*) and 
                2 of ($sys_*) and 
                (any of ($attack_*) or any of ($killer_*))
            ) or
            
            // 5. Go source code characteristics
            ($go_magic and any of ($attack_*))
        )
}
