ipconfig /release
ipconfig /flushdns
ipconfig /renew
netsh int ip reset
netsh winsock reset
route /f
sc config FDResPub start=auto
sc config fdPHost start=auto
shutdown -r -t 10
