/*
 * YARA Rules for Mirai/Gafgyt IoT Botnet Detection
 * Author: Security Analysis Assistant
 * Version: 3.1 (Fixed & Optimized)
 * Date: 2026-02-28
 */

import "elf"

/* ============================
   ELF VALIDATOR
   ============================ */

rule ELF_Validator {
    meta:
        description = "Kiểm tra file ELF hợp lệ"
    condition:
        uint32(0) == 0x464c457f
}

/* ============================
   INFRASTRUCTURE IOCs (C2)
   ============================ */

rule IOCs_C2_Domains {
    meta:
        description = "Phát hiện C2 domains đặc trưng của Mirai/Gafgyt"
        severity = "Critical"
    
    strings:
        $c2_domain_1 = "ciobabaservices.duckdns.org" ascii wide nocase
        $c2_domain_2 = "slursbeback.ru" ascii wide nocase
        $c2_domain_3 = "blueblackside.com" ascii wide nocase
        $c2_domain_4 = "connectivity.accesscam.org" ascii wide nocase
        $c2_domain_5 = "hakaiboatnet.pw" ascii wide nocase
        $c2_domain_6 = "intranet.milnetstresser.ru" ascii wide nocase
        $c2_domain_7 = "duckdns.org" ascii wide nocase
        $c2_domain_8 = "t.me/flylegit" ascii wide nocase
    
    condition:
        ELF_Validator and any of ($c2_domain_*)
}

rule IOCs_C2_IPs {
    meta:
        description = "Phát hiện C2 IP addresses"
        severity = "Critical"
    
    strings:
        $c2_ip_1 = "130.12.180.151" ascii
        $c2_ip_2 = "141.98.10.50" ascii
        $c2_ip_3 = "38.60.250.111" ascii
        $c2_ip_4 = "176.65.139.18" ascii
        $c2_ip_5 = "185.207.225.218" ascii
        $c2_ip_6 = "180.196.247.222" ascii
        $c2_ip_hex_1 = { 32 B7 31 58 }  // 50.183.49.88
        $c2_ip_hex_2 = { 0a 00 00 19 }  // 10.0.0.25
        $c2_ip_hex_3 = { 21 27 bd ff }  // Encoded
    
    condition:
        ELF_Validator and (any of ($c2_ip_*) or any of ($c2_ip_hex_*))
}

/* ============================
   SYSTEM PATHS & BEHAVIOR
   ============================ */

rule System_Recon_Indicators {
    meta:
        description = "Phát hiện hành vi trinh sát hệ thống"
        severity = "High"
    
    strings:
        $proc_1 = "/proc/self/exe" ascii
        $proc_2 = "/proc/net/tcp" ascii
        $proc_3 = "/proc/stat" ascii
        $proc_4 = "/proc/cmdline" ascii
        $proc_5 = "/proc/%s/comm" ascii
        $sys_1 = "/dev/watchdog" ascii
        $sys_2 = "/dev/null" ascii
        $sys_3 = "/etc/watchdog" ascii
        $sys_4 = "/sys/devices/system/cpu" ascii
        $oom = "OOM_SCORE_ADJ" ascii
        $path_dvr = "/root/dvr_app" ascii
    
    condition:
        ELF_Validator and (
            3 of ($proc_*) or
            2 of ($sys_*) or
            ($oom and 1 of ($proc_*)) or
            $path_dvr
        )
}

/* ============================
   ANTI-ANALYSIS
   ============================ */

rule Anti_Analysis_Techniques {
    meta:
        description = "Phát hiện cơ chế chống phân tích"
        severity = "High"
    
    strings:
        $anti_virt_1 = "HYPERVISOR" ascii
        $anti_virt_2 = "VIRTIO" ascii
        $anti_virt_3 = "VIRTBLK" ascii
        $anti_virt_4 = "VFIO" ascii
        $cmd_clean_1 = "systemctl kill -s HUP rsyslog.service" ascii
        $cmd_clean_2 = "rm -rf /var/log/syslog" ascii
        $cmd_clean_3 = "/usr/lib/rsyslog/rsyslog-rotate" ascii
    
    condition:
        ELF_Validator and (
            2 of ($anti_virt_*) or
            any of ($cmd_clean_*)
        )
}

/* ============================
   ATTACK COMMANDS
   ============================ */

rule DDoS_Attack_Commands {
    meta:
        description = "Phát hiện các lệnh tấn công DDoS"
        severity = "Critical"
    
    strings:
        $attack_1 = "HTTPFLOOD" ascii wide nocase
        $attack_2 = "UDP" ascii wide nocase
        $attack_3 = "TCP" ascii wide nocase
        $attack_4 = "FLOOD" ascii wide nocase
        $attack_5 = "udpplain" ascii fullword
        $attack_6 = "syn" ascii fullword
        $attack_7 = "ping" ascii fullword
        $attack_8 = "pong" ascii fullword
        $attack_9 = "BOTKILL" ascii
        $gql_1 = "{ id name email }" ascii
        $gql_2 = "{ id title content }" ascii
        $gql_3 = "{ id name price }" ascii
        $sh4_flood = "sh4_flood" ascii
    
    condition:
        ELF_Validator and (
            3 of ($attack_*) or
            all of ($gql_*) or
            $sh4_flood
        )
}

/* ============================
   USER AGENTS
   ============================ */

rule HTTP_Flood_UserAgents {
    meta:
        description = "User-Agents giả mạo"
        severity = "Medium"
    
    strings:
        $ua_1 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.10; rv:40.0) Gecko/20100101 Firefox/40.0" ascii
        $ua_2 = "Mozilla/5.0 (iPad; CPU OS 7_1_2 like Mac OS X)" ascii
        $ua_3 = "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0)" ascii
        $ua_4 = "Gecko/20100101 Firefox/147.0" ascii
        $ua_5 = "Mozilla/5.0 Slackware/13.37" ascii
        $ua_6 = "Camino/1.5.4" ascii
    
    condition:
        ELF_Validator and 2 of ($ua_*)
}

/* ============================
   PROCESS KILLER
   ============================ */

rule Process_Killer_Module {
    meta:
        description = "Module diệt tiến trình đối thủ"
        severity = "Critical"
    
    strings:
        $killer_1 = "kdevtmpfsi" ascii wide
        $killer_2 = "xmrig" ascii wide
        $killer_3 = "kinsing" ascii wide
        $killer_4 = "cpuminer" ascii wide
        $killer_5 = ".uhavenobotsxd" ascii wide
        $killer_func = "process_killer_loop" ascii
    
    condition:
        ELF_Validator and (
            3 of ($killer_*) or
            $killer_func
        )
}

/* ============================
   ARCHITECTURE OPCODES
   ============================ */

rule ARM_Opcode_Indicators {
    meta:
        description = "Đặc trưng mã máy ARM"
        architecture = "ARM"
    
    strings:
        $arm_svc = { 80 ef ?? ?? }
        $arm_raw = { 22 30 a0 e3 }
    
    condition:
        any of ($arm_*)
}

rule MIPS_Opcode_Indicators {
    meta:
        description = "Đặc trưng mã máy MIPS"
        architecture = "MIPS"
    
    strings:
        $mips_connect = { 24 02 10 4a 00 00 00 0c }
        $mips_raw = { 24 04 00 02 24 05 00 03 24 06 00 12 }
        $mips_prng = { 3c 05 08 42 34 a5 10 85 00 45 00 19 }
        $mips_xor = { 38 ?? 00 21 }
    
    condition:
        any of ($mips_*)
}

rule SH4_Opcode_Indicators {
    meta:
        description = "Đặc trưng mã máy SH4"
        architecture = "SH4"
    
    strings:
        $sh4_udp = { 02 E5 [0-6] 0B 4? }
        $sh4_tcp = { 01 E5 [0-6] 0B 4? }
        $sh4_c2 = { D? ?? [0-2] 04 63 41 00 }
        $sh4_socket = { 02 E5 [0-4] 0B 4? }
    
    condition:
        any of ($sh4_*)
}

/* ============================
   ENCRYPTION KEYS
   ============================ */

rule Custom_Encryption_Keys {
    meta:
        description = "Phát hiện khóa mã hóa đặc trưng"
        severity = "High"
    
    strings:
        $xor_key_1 = { DE DE FF BA }
        $xor_key_2 = { 2e 67 6a 3d }
        $xor_key_3 = { 27 60 71 3d }
        $tea_delta = { B9 79 37 9E }
        $fnv1_const = { 93 01 00 01 }
        $custom_b32 = "w5q6he3dbrsgmclkiu4to18npavj702f" ascii
        $custom_b64 = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ" ascii
    
    condition:
        any of ($xor_key_*) or
        $tea_delta or
        $fnv1_const or
        $custom_b32 or
        $custom_b64
}

/* ============================
   HACKER MARKS
   ============================ */

rule Hacker_Identification_Marks {
    meta:
        description = "Dấu vết nhận diện tác giả"
    
    strings:
        $mark_1 = "KHserverHACKER" ascii
        $mark_2 = "GDQDPROJH" ascii wide nocase
        $mark_3 = "YakuzaBotnet" ascii
        $mark_4 = "Scarface1337" ascii
        $mark_5 = "Self Rep Fucking NeTiS" ascii
        $mark_6 = "PozHlpiND4xPDPuGE6tq" ascii
        $mark_7 = "hacked by hoa long" ascii
        $mark_8 = "someoffdeeznuts" ascii
        $handshake_1 = "TS3INIT1" ascii
        $handshake_2 = "BOT\x01TAKE" ascii
        $handshake_3 = "[CONNECTED] [HITTA]" ascii
    
    condition:
        any of ($mark_*) or
        any of ($handshake_*)
}

/* ============================
   INFECTION VECTORS
   ============================ */

rule ADB_Infection_Module {
    meta:
        description = "Module lây nhiễm qua ADB"
        severity = "Critical"
    
    strings:
        $adb_cmd = "shell:cd /data/local/tmp/; busybox wget" ascii wide
        $adb_script = "adb-shell.sh" ascii wide
        $dropper_1 = "deltahaxsyeaok.sh" ascii
        $dropper_2 = "ukloltftp1.sh" ascii
        $dropper_3 = "ukloltftp2.sh" ascii
        $dlr = "GET/dlr." ascii
    
    condition:
        any of ($adb_*) or
        any of ($dropper_*) or
        $dlr
}

/* ============================
   DEBUG STRINGS
   ============================ */

rule Debug_Telemetry_Strings {
    meta:
        description = "Chuỗi debug trong botnet"
    
    strings:
        $debug_1 = "[DEBUG_MODE_ATTACK] attack_parse:" ascii wide
        $debug_2 = "starting attack vector=%u duration=%u targets=%u" ascii wide
        $debug_3 = "received %d bytes" ascii wide
        $debug_4 = "BUILD LNX" ascii
        $debug_5 = "REPORT %s:%s" ascii
        $debug_6 = "invalid password" ascii nocase
    
    condition:
        2 of ($debug_*)
}

/* ============================
   GOLANG INDICATORS
   ============================ */

rule Golang_Malware_Indicators {
    meta:
        description = "Phát hiện malware viết bằng Go"
        language = "Golang"
    
    strings:
        $go_magic = "Go build ID:" ascii
        $go_pclntab = { FB FF FF FF }
    
    condition:
        $go_magic or $go_pclntab
}

/* ============================
   ARCHITECTURE DETECTION
   ============================ */

rule Architecture_ARM {
    meta:
        description = "File ELF kiến trúc ARM"
    condition:
        ELF_Validator and elf.machine == 0x28
}

rule Architecture_MIPS {
    meta:
        description = "File ELF kiến trúc MIPS"
    condition:
        ELF_Validator and (elf.machine == 8 or elf.machine == 10)
}

rule Architecture_SH4 {
    meta:
        description = "File ELF kiến trúc SH4"
    condition:
        ELF_Validator and elf.machine == 42
}

/* ============================
   COMBINED SUPER RULES (FIXED)
   ============================ */

rule SuperRule_Mirai_Gafgyt_Combined {
    meta:
        description = "Phát hiện tất cả biến thể Mirai/Gafgyt"
        severity = "Critical"
    
    condition:
        ELF_Validator and (
            IOCs_C2_Domains or
            IOCs_C2_IPs or
            (System_Recon_Indicators and DDoS_Attack_Commands) or
            (Process_Killer_Module and Custom_Encryption_Keys) or
            (Hacker_Identification_Marks and System_Recon_Indicators) or
            (ADB_Infection_Module and Debug_Telemetry_Strings)
        )
}

/* ============================
   ARCHITECTURE-SPECIFIC DETECTION (FIXED)
   ============================ */

rule Mirai_ARM_Detect {
    meta:
        description = "Phát hiện Mirai/Gafgyt trên ARM"
        architecture = "ARM"
    
    condition:
        Architecture_ARM and
        ARM_Opcode_Indicators and
        (IOCs_C2_Domains or System_Recon_Indicators or DDoS_Attack_Commands)
}

rule Mirai_MIPS_Detect {
    meta:
        description = "Phát hiện Mirai/Gafgyt trên MIPS"
        architecture = "MIPS"
    
    condition:
        Architecture_MIPS and
        MIPS_Opcode_Indicators and
        (IOCs_C2_IPs or Process_Killer_Module or Custom_Encryption_Keys)
}

rule Mirai_SH4_Detect {
    meta:
        description = "Phát hiện Mirai/Gafgyt trên SH4"
        architecture = "SH4"
    
    condition:
        Architecture_SH4 and
        SH4_Opcode_Indicators and
        (System_Recon_Indicators or DDoS_Attack_Commands)
}

/* ============================
   CAMPAIGN-SPECIFIC RULES
   ============================ */

rule Campaign_Hitta_Variant {
    meta:
        description = "Phát hiện biến thể Hitta"
        campaign = "Hitta"
    
    strings:
        $hitta_moniker = "[CONNECTED] [HITTA]" ascii
        $hitta_delta = { B9 79 37 9E }
        $ciobaba = "ciobabaservices.duckdns.org" ascii
    
    condition:
        ELF_Validator and ($hitta_moniker or $hitta_delta or $ciobaba)
}

rule Campaign_DDoSia_NoName057 {
    meta:
        description = "Phát hiện DDoSia (NoName057)"
        campaign = "DDoSia"
    
    condition:
        ELF_Validator and
        Golang_Malware_Indicators and
        DDoS_Attack_Commands and
        (Custom_Encryption_Keys or Hacker_Identification_Marks)
}

rule Campaign_Yakuza_Scarface {
    meta:
        description = "Phát hiện Yakuza Botnet"
        campaign = "Yakuza"
    
    strings:
        $yakuza_auth = "PozHlpiND4xPDPuGE6tq" ascii
        $yakuza_brand = "YakuzaBotnet" ascii
        $scarface = "Scarface1337" ascii
        $udp_magic = { 38 46 4a 93 49 44 9a }
    
    condition:
        ELF_Validator and (
            $yakuza_auth or
            $yakuza_brand or
            $scarface or
            $udp_magic
        )
}

rule Campaign_Hakai_Botnet {
    meta:
        description = "Phát hiện Hakai Botnet"
        campaign = "Hakai"
    
    strings:
        $hakai_domain = "hakaiboatnet.pw" ascii
        $hakai_auth = "hacked by hoa long" ascii
        $hakai_hex1 = { 2d 24 2b 24 2c 27 2a 24 31 2b 20 31 6b 35 32 }
        $hakai_hex2 = { 6a 35 37 2a 26 6a 2b 20 31 6a 31 26 35 }
        
    condition:
        ELF_Validator and (
            $hakai_domain or
            $hakai_auth or
            ($hakai_hex1 and $hakai_hex2)
        )
}

/* ============================
   LEGACY RULES (FIXED)
   ============================ */

rule Linux_Gafgyt_Bashlite_Ciobaba : Campaign_Hitta_Variant {
    condition:
        Campaign_Hitta_Variant
}

rule Malware_Lnx_DDoSia_NoName057 : Campaign_DDoSia_NoName057 {
    condition:
        Campaign_DDoSia_NoName057
}

rule Malware_Yakuza_Scarface_MIPS : Campaign_Yakuza_Scarface {
    condition:
        Campaign_Yakuza_Scarface and Architecture_MIPS
}

rule Hakai_Botnet_PPC_Final : Campaign_Hakai_Botnet {
    condition:
        Campaign_Hakai_Botnet
}