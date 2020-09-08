## Eventlog QuickWins
### This tool parses eventlogs to identify QuickWins during incident response scenarios.
### Only includes relevant fields
### Outputs to C:\CS\

HOSTNAME_EventlogRDP.txt
  * Security 4624
    * Logon Type 10 and 7
  * Microsoft-Windows-TerminalServices-LocalSessionManager/Operational
    * EventID 21, 23, 24

HOSTNAME_EventlogPowershell.txt
  * Microsoft-Windows-PowerShell/Operational 
    * EventID 4104
  * Microsoft-Windows-PowerShell
    * All events that contain a non-empty, non-default HostApplication, ScriptName, or CommandLine
