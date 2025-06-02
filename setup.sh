#!/bin/bash
[ "$EUID" -ne 0 ] && echo "Please run as root" && exit 1
mkdir -p /var/log/usbfstab /etc/usbfstab
[ "$(uname)" == "Darwin" ] && brew install python3 && pip3 install -r requirements.txt || (apt-get update && apt-get install -y python3 python3-pip usbutils && pip3 install -r requirements.txt)
echo '{"check_interval":1.0,"backup_interval":3600,"max_backups":24,"alert_threshold":3,"do_backup":true,"do_monitor":true,"do_cleanup":true}' > /etc/usbfstab/config.json
echo '/var/log/usbfstab/*.log {daily rotate 7 compress delaycompress missingok notifempty create 644 root root}' > /etc/logrotate.d/usbfstab
chmod +x usbfstab.py cellebrite.py jiggler_block.py
[ "$(uname)" != "Darwin" ] && (echo '[Unit]\nDescription=USB Forensic Security Tools\nAfter=network.target\n\n[Service]\nType=simple\nUser=root\nExecStart=/usr/bin/python3 '"$(pwd)"'/usbfstab.py\nRestart=always\nRestartSec=3\n\n[Install]\nWantedBy=multi-user.target' > /etc/systemd/system/usbfstab.service && systemctl daemon-reload && systemctl enable usbfstab && systemctl start usbfstab)
[ "$(uname)" == "Darwin" ] && (echo '<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n<plist version="1.0">\n<dict>\n<key>Label</key>\n<string>com.usbfstab</string>\n<key>ProgramArguments</key>\n<array>\n<string>/usr/bin/python3</string>\n<string>'"$(pwd)"'/usbfstab.py</string>\n</array>\n<key>RunAtLoad</key>\n<true/>\n<key>KeepAlive</key>\n<true/>\n<key>StandardErrorPath</key>\n<string>/var/log/usbfstab/error.log</string>\n<key>StandardOutPath</key>\n<string>/var/log/usbfstab/output.log</string>\n</dict>\n</plist>' > ~/Library/LaunchAgents/com.usbfstab.plist && launchctl load ~/Library/LaunchAgents/com.usbfstab.plist)
read -p "Run tools now? (y/n) " -n 1 -r && echo && [[ $REPLY =~ ^[Yy]$ ]] && (python3 usbfstab.py & python3 cellebrite.py & python3 jiggler_block.py &) 
