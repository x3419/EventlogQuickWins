## Eventlog QuickWins
### This tool parses eventlogs to identify quick wins during incident response scenarios.
### Outputs to C:\CS\

HOSTNAME_EventlogRDP.txt
  * Security 4624
    * Logon Type 10 and 7
    * Only outputs the fields "Logon Type", "Workstation Name", "Source Network Address", "Network Account Name", "Account Name", "Account Domain" 
      * Omitted when they are empty
  * Microsoft-Windows-TerminalServices-LocalSessionManager/Operational
    * EventID 21, 23, 24


HOSTNAME_EventlogPowershell.txt
  * Microsoft-Windows-PowerShell/Operational 
    * EventID 4104
  * Microsoft-Windows-PowerShell
    * All events that contain a non-empty, non-default HostApplication, ScriptName, or CommandLine

### TODO:

  * Output as CSV
  * Sort by timeGenerated