# Simple Malware Lab
A simple, self-built lab environment to safely learn and practice **malware analysis**.

**Repo name**: Simple-Malware-Lab
**Author**: [48696e61746172613731](https://github.com/48696e61746172613731) (likely decodes from hex to "hanataro71" 😉)

## Purpose
This repo provides a lightweight, easy-to-deploy lab for:
- Practicing **static analysis**
- Practicing **dynamic analysis**
- Observing the behavior of malware samples (or self-created ones)
- Learning how to set up a safe environment (VM isolation, snapshots, network control…)

Suitable for beginners learning malware analysis, reverse engineering, or blue team / DFIR work.

**Serious Warning**
This repo may contain or guide the use of **actual malware** (or simulated samples).
**Do not run any files on your host machine!** Use only in a completely isolated virtual environment.

## Key Features
- Simple configuration, minimal dependencies
- Quick setup guides for VirtualBox / VMware Workstation
- Simulated network patterns (INetSim, FakeDNS…) or INet isolation usage
- Helper scripts (optional): sample renaming, hash calculation, process monitoring…
- Easy snapshot & rollback

## System Requirements
- Computer with RAM ≥ 16GB (≥ 32GB recommended)
- CPU with virtualization support (Intel VT-x / AMD-V enabled in BIOS)
- Free hard disk space ~80–150GB
- Virtualization software: VirtualBox (free) or VMware Workstation/Player

## Main Lab Components (Suggestion)

| Component | Purpose | Suggested Tools / OS |
|--------------------|----------------------------------------|----------------------------------|
| Windows Victim | Run malware | Windows 10 / Windows 7 (Flare-VM) |
| Analysis Machine | Static analysis + network monitoring | REMnux or Kali Linux |
| Windows Analysis | Dynamic analysis, debugging | Windows 10 with FLARE-VM |
| Gateway / Firewall | Block or simulate C2 connections | pfSense / NAT + INetSim |
| Host Machine | Control everything, snapshots | Any OS with virtualization support |

## Quick Start Guide

1. **Create a Windows Victim Virtual Machine**
   - Install Windows 10 (or Windows 7 for a lighter option)
   - Disable Windows Defender and Windows Update
   - Create a "Clean" snapshot

2. **Install FLARE-VM (optional, for full toolset)**
   ```powershell
   # On the Windows Victim or Analysis machine
   # Run PowerShell as Administrator
   (New-Object net.webclient).DownloadFile('https://raw.githubusercontent.com/mandiant/flare-vm/main/install.ps1','.\install.ps1')
   .\install.ps1 -password <your_password> -noGui
